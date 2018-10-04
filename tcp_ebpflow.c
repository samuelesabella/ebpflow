// creato da: Brendan Gregg
// modificato da: Alessandro Di Giorgio
//                Samuele Sabelle           
// mail: a.digiorgio1@studenti.unipi.it

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <bcc/proto.h>
#include <linux/pid_namespace.h>


// Creating hash table with <key: pid, value: struct sock*>
BPF_HASH(currsock, u32, struct sock *);


// ----- ----- USER-KERNEL DATA ----- ----- //
/*
 * proto flag: 
 *    - 601  for tcp client
 *    - 602  for tcp server
 *    - 1701 for upd receive
 *    - 1702 for udp send  
 */
struct ipv4_data_t {
    u32 pid;
    u32 uid;
    u32 gid;
    u16 proto;
    u16 loc_port;
    u16 dst_port;
    u16 ip;
    u32 saddr;
    u32 daddr;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    u32 uid;
    u32 gid;
    u16 proto;
    u16 loc_port;
    u16 dst_port;
    u16 ip;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);


/* ******************************************* */
/* ******************************************* */


/*
 * Initializes hash entries, needs to be atached
 * to 'tcp_vx_connect' (x = 4 or 6) function on entry (BPF_PROBE_ENTRY flag)
 * ARGS: 
 *      ctx - ebpf context
 *      sk  - socket passed to the 'tcp_vx_connect'
 */
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid();
    currsock.update(&pid, &sk);
    return 0;
};

/*
 * Handles the termination of connect events. If connect
 * succed data is collected, passed to user level and
 * the entry (created in trace_connect_entry) removed from the table
 */
static int trace_connect_return(struct pt_regs *ctx, short ipver) {
    // tcp_vx_connect return value
    int ret = PT_REGS_RC(ctx);
    // Getting pid for lookup
    u32 pid = bpf_get_current_pid_tgid();

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&pid); // removing enrty from hash table
        return 0;
    }

    // Looking up for entry
    struct sock **skpp;
    skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0; // Return if missed entry
    }
    struct sock *skp = *skpp;

    // User and group id
    u64 guid = bpf_get_current_uid_gid();
    u32 uid = guid & 0xFFFFFFFF;
    u32 gid = (guid >> 32) & 0xFFFFFFFF;

    // Ports
    u16 dst_port = skp->__sk_common.skc_dport;
    dst_port = ntohs(dst_port);
    u16 loc_port = skp->__sk_common.skc_num;
    loc_port = ntohs(loc_port);

    if (ipver == 4) {
        struct ipv4_data_t data4 = {
            .pid = pid, 
            .uid = uid,
            .gid = gid,
            .proto = 601,
            .dst_port = dst_port,
            .loc_port = loc_port,
            .ip = ipver,
            .saddr = skp->__sk_common.skc_rcv_saddr,
            .daddr = skp->__sk_common.skc_daddr,
        };
        // Storing command that originated event
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        // Submitting event to buffer
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } 
    else {
        struct ipv6_data_t data6 = {
            .pid = pid, 
            .uid = uid,
            .gid = gid,
            .proto = 601,
            .dst_port = dst_port,
            .loc_port = loc_port,
            .ip = ipver,
        };
        // Reading addresses
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        // Storing command that originated event
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        // Submitting event to buffer
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    // Event submitted, we can safely elimanate the entry
    currsock.delete(&pid);
    return 0;
}

/*
 * Discriminate ip version for 'tcp_vx_connect' returns event. Ipv4 and Ipv6 
 * can be discriminated by attaching this functions respectively to tcp_v4_connect
 * and tcp_v6_connect (BPF_PROBE_RETURN flag)
 */
int trace_connect_v4_return(struct pt_regs *ctx) {
    return trace_connect_return(ctx, 4);
}
int trace_connect_v6_return(struct pt_regs *ctx) {
    return trace_connect_return(ctx, 6);
}

/*
 * Handles the termination of accept events. If the accept call
 * succed, data is collected, passed to user level. No entry
 * was created so the hash remain unused in this situation
 */
int trace_tcp_accept(struct pt_regs *ctx) {
    // tcp_v6_accept return value
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (newsk == NULL) {
        return 0;
    }
    // Getting pid for lookup
    u32 pid = bpf_get_current_pid_tgid();

    // Getting user and group id
    u64 guid = bpf_get_current_uid_gid();
    u32 uid = guid & 0xFFFFFFFF;
    u32 gid = (guid >> 32) & 0xFFFFFFFF;

    // Getting ports
    u16 loc_port = 0;
    bpf_probe_read(&loc_port, sizeof(loc_port), &newsk->__sk_common.skc_num);
    u16 dst_port = 0;
    bpf_probe_read(&dst_port, sizeof(dst_port), &newsk->__sk_common.skc_dport);

    // Discriminating ipv4/ipv6 based on family flag
    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &newsk->__sk_common.skc_family);

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {
            .pid = pid, 
            .uid = uid,
            .gid = gid,
            .proto = 602,
            .dst_port = dst_port,
            .loc_port = loc_port,
            .ip = 4,
        };
        // Reading addresses
        bpf_probe_read(&data4.saddr, sizeof(u32),
            &newsk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(u32),
            &newsk->__sk_common.skc_daddr);
        // Storing command that originated event
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        // Submitting event to buffer
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } 
    else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {
            .pid = pid, 
            .uid = uid,
            .gid = gid,
            .proto = 602,
            .dst_port = dst_port,
            .loc_port = loc_port,
            .ip = 6,
        };
        // Reading addresses
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        // Storing command that originated event
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        // Submitting event to buffer
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    return 0;
}