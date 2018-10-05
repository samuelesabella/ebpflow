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
 * ARGS:
 *      accept: 1 if accept event, 0 for connect events
 */
static int trace_return(struct pt_regs *ctx, short ipver, short t_connect) {
    u32 pid;
    u64 guid;
    u32 gid;
    u32 uid;
    u16 proto;
    u16 loc_port;
    u16 dst_port;
    u16 family;
    struct sock **skpp;
    struct sock *skp;

    // tcp_vx_connect return value
    pid = bpf_get_current_pid_tgid();
    
    if (t_connect) {
        // Checking if connect has succed, if not delete entry from table (SYNC packet fail)
        if (PT_REGS_RC(ctx) != 0) {
            currsock.delete(&pid);
            return 0;
        }
        // Grabbing socket from table entry
        if ((skpp = currsock.lookup(&pid)) == 0) {
            return 0;
        }
        skp = *skpp;
    }
    else {
        skp = (struct sock *)PT_REGS_RC(ctx);
        if (skp == NULL) {
            return 0;
        }
        bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);
        ipver = (family == AF_INET) ? 4 : 6;
    }

    // User and group id
    guid = bpf_get_current_uid_gid();
    uid = guid & 0xFFFFFFFF;
    gid = (guid >> 32) & 0xFFFFFFFF;

    // Ports
    bpf_probe_read(&dst_port, sizeof(dst_port), &skp->__sk_common.skc_dport);
    dst_port = ntohs(dst_port);
    bpf_probe_read(&loc_port, sizeof(loc_port), &skp->__sk_common.skc_num);
    loc_port = ntohs(loc_port);

    // Event type
    proto = t_connect ? 602 : 601;

    if (ipver == 4) {
        struct ipv4_data_t data4 = {
            .pid = pid, 
            .uid = uid,
            .gid = gid,
            .proto = proto,
            .dst_port = dst_port,
            .loc_port = loc_port,
            .ip = ipver, 
        };
        // Reading addresses
        bpf_probe_read(&data4.saddr, sizeof(data4.saddr),
            &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(data4.saddr),
            &skp->__sk_common.skc_daddr);
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
            .proto = proto,
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
 * Discriminate ip version for returns event. Ipv4 and Ipv6 
 * can be discriminated by attaching this functions respectively to tcp_v4_connect
 * and tcp_v6_connect (BPF_PROBE_RETURN flag)
 */
int trace_connect_v4_return(struct pt_regs *ctx) {
    return trace_return(ctx, 4, 1);
}
int trace_connect_v6_return(struct pt_regs *ctx) {
    return trace_return(ctx, 6, 1);
}

int trace_accept_return(struct pt_regs *ctx) {
    return trace_return(ctx, -1, 0);
}
