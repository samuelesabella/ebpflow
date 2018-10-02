// creato da: Brendan Gregg
// modificato da: Alessandro Di Giorgio
// mail: a.digiorgio1@studenti.unipi.it

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <bcc/proto.h>
#include <linux/pid_namespace.h>


//crea hash map currsock, dove la chiave e' un u32 e il  valore e' un struct sock*
BPF_HASH(currsock, u32, struct sock *);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u32 pid;
    u32 uid;
    u32 gid;
    u32 saddr;
    u32 daddr;
    u16 ip;
    u16 loc_port;
    u16 dst_port;
    u16 is_client;
    char task[TASK_COMM_LEN];
};

//crea una tabella BPF per inviare informazioni allo spazio utente attraverso un buffer circolare.
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    u32 uid;
    u32 gid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u32 ip;
    u16 loc_port;
    u16 dst_port;
    u16 is_client;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);


//ctx: Registers and BPF context... gli altri sono argomenti della sys-call da monitorare
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();

    // stash the sock ptr for lookup on returns
    currsock.update(&pid, &sk); //inserisco (&pid,&sk)

    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx); //valore di ritorno della chiamata alla tcp_connect
    u32 pid = bpf_get_current_pid_tgid();

    u64 guid = bpf_get_current_uid_gid();
    u32 uid = guid & 0xFFFFFFFF;
    u32 gid = (guid >> 32) & 0xFFFFFFFF;

    struct sock **skpp;
    skpp = currsock.lookup(&pid); //ricerca per pid
    if (skpp == 0) {
        return 0;   // missed entry
    }


    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&pid); //elimino entry dalla tabella hash
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 dst_port = skp->__sk_common.skc_dport;
    dst_port = ntohs(dst_port);
    u16 loc_port = skp->__sk_common.skc_num;
    loc_port = ntohs(loc_port);

    if (ipver == 4) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
        data4.is_client = 1;
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.dst_port = dst_port;
        data4.loc_port = loc_port;
        /*
            prelevo l'id dell'utente chiamante
            prendendo gli ultimi 32 bit
        */
        data4.uid = uid;
        data4.gid = gid;

        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* 6 */ {
        struct ipv6_data_t data6 = {.pid = pid, .ip = ipver};
        data6.is_client = 1;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.dst_port = dst_port;
        data6.loc_port = loc_port;
        data6.uid = uid;
        data6.gid = gid;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    currsock.delete(&pid); //elimino entry con pid *pid

    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx) //IPV4
{
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx) //IPV6
{
    return trace_connect_return(ctx, 6);
}


int trace_tcp_accept(struct pt_regs *ctx)
{
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    u64 guid = bpf_get_current_uid_gid();
    u32 uid = guid & 0xFFFFFFFF;
    u32 gid = (guid >> 32) & 0xFFFFFFFF;

    if (newsk == NULL)
        return 0;

    // pull in details
    u16 loc_port = 0;
    bpf_probe_read(&loc_port, sizeof(loc_port), &newsk->__sk_common.skc_num);
    u16 dst_port = 0;
    bpf_probe_read(&dst_port, sizeof(dst_port), &newsk->__sk_common.skc_dport);

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &newsk->__sk_common.skc_family);

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = 4};
        data4.is_client = 0;
        bpf_probe_read(&data4.saddr, sizeof(u32),
            &newsk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(u32),
            &newsk->__sk_common.skc_daddr);
        data4.loc_port = loc_port;
        data4.dst_port = dst_port;
        // uid and group
        data4.uid = uid;
        data4.gid = gid;
        // Pushing
        bpf_get_current_comm(&data4.task, sizeof(data4.task));

        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {.pid = pid, .ip = 6};
        data6.is_client = 0;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.loc_port = loc_port;
        data6.dst_port = dst_port;
        data6.uid = uid;
        data6.gid = gid;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    return 0;
}