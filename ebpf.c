#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <bcc/proto.h>
#include <linux/fs_struct.h>

#include <linux/mount.h>
#include <linux/dcache.h>

#include <linux/unistd.h>
#include <linux/utsname.h>
#include "ebpf_string.c"

#define INJECTION_ALLOW 0
#define SIZEOF_POLICY 14


typedef enum {
  flag_task_gid   = 1,
  flag_task_uid   = 2,
  flag_task_pid   = 3,
  flag_task       = 4,

  flag_ptask_gid   = 21,
  flag_ptask_uid   = 22,
  flag_ptask_pid   = 23,
  flag_ptask       = 24,

  flag_loc_port = 41,
  flag_dst_port = 42,

  flag_etype = 61
} policy_match_flag;

typedef enum {
  TCP_ACPT = 601, // The event has been triggered by 'tcp_v4_connect' call 
  TCP_CONN = 602, // 'inet_csk_accept' call
} event_type;


/* ****************************************** */
// ===== ===== KERNEL->USER EVENT ===== ===== //
/* ****************************************** */
struct task_info {
  u32 pid;
  u32 uid;
  u32 gid;
  u64 cgroup; // cgroup id
  struct net *n; // Pointer to network namespace
  char task[TASK_COMM_LEN]; // Task name
};

struct net_info4 {
  u16 loc_port; // local port
  u16 dst_port; // remote port
  u32 saddr; // source address
  u32 daddr; // destination address
};

struct KernelData {
  u64 absolute_time; // need to measure the time to sget the event
  u64 ktime; // usec since first event
  struct task_info task; // Task that triggered the ebpf event
  struct task_info ptask; // Parent task
  int policy_flag; // usr | task | addr. | port | future use ...
  event_type etype;
  struct net_info4 net4;
};
BPF_PERF_OUTPUT(user_buffer);


/* ************************************************** */
// ===== ===== LOCAL-LOGIC DATA STRUCTURE ===== ===== //
/* ************************************************** */
/*
 * From the 'tcp_v4_connect' return we can't get the socket used, therefore
 * we extract it from invocations arguments and keep it an hash table.
 * If the connection is successful we get the socket by looking at the tid
 * and extract from it port and addresses. 
 */
BPF_HASH(currsock, u32, struct sock*, 1024);


/* ****************************************** */
// ===== ===== INFORMATION GATHER ===== ===== //
/* ****************************************** */
static void fill_task (struct task_info *t_dst, struct task_struct *t_task) {
  // Reading credentials to extract user and group id
  struct cred *credential;
  bpf_probe_read(&credential, sizeof(struct cred *), &t_task->real_cred);
  // PID, UID, GID,  task name
  bpf_probe_read(&(t_dst->pid), sizeof(u32), &t_task->pid);
  bpf_probe_read(&(t_dst->uid), sizeof(u32), &credential->uid);
  bpf_probe_read(&(t_dst->gid), sizeof(u32), &credential->gid);
  bpf_probe_read(&(t_dst->task), TASK_COMM_LEN, t_task->comm);
}

static void fill_tcp_net (struct KernelData *t_event_data, struct sock *sk, event_type t_etype) {
  t_event_data->etype = t_etype;

  // Ports ----- //
  bpf_probe_read(&t_event_data->net4.dst_port, sizeof(u16), &sk->__sk_common.skc_dport);
  bpf_probe_read(&t_event_data->net4.loc_port, sizeof(u16), &sk->__sk_common.skc_num);
  if (t_etype == TCP_CONN) {
    t_event_data->net4.dst_port = ntohs(t_event_data->net4.dst_port);
    t_event_data->net4.loc_port = ntohs(t_event_data->net4.loc_port);
  }
  // Addresses ----- //
  bpf_probe_read(&t_event_data->net4.saddr, sizeof(u32), &sk->__sk_common.skc_rcv_saddr);
  bpf_probe_read(&t_event_data->net4.daddr, sizeof(u32), &sk->__sk_common.skc_daddr);
}


/* *************************************** */
// ===== ===== SECURITY KEEPER ===== ===== //
/* *************************************** */
BPF_ARRAY(df, int, 1); // 1 for default allow else deny 
BPF_ARRAY(policy_holder, struct KernelData, SIZEOF_POLICY);

static int match_task (struct task_info *t_edata,  struct task_info *t_policy) {
  if (t_policy->gid != -1 && t_policy->gid==t_edata->gid) {
    return flag_task_gid;
  }

  if (t_policy->uid != -1 && t_policy->uid==t_edata->uid) {
    return flag_task_uid;
  }

  if (t_policy->pid != -1 && t_policy->pid==t_edata->pid) {
    return flag_task_pid;
  }

  if (!ebpf_strcmp(t_policy->task, "*") && ebpf_strcmp(t_policy->task, t_edata->task)) {
    return flag_task;
  }

  return 0;
}

static int match_policy (struct KernelData *t_edata, struct KernelData *t_policy, int* t_cause) {
  int ret;

  if (t_policy->etype && (t_policy->etype==t_edata->etype)) {
    *t_cause = flag_etype;
    return 1;
  }
  
  if ((*t_cause = match_task(&t_edata->task, &t_policy->task)) != 0) {
    return 1;
  }

  if ((*t_cause = match_task(&t_edata->ptask, &t_policy->ptask)) != 0) {
    *t_cause += 20; // task flag to parent flag
    return 1;
  }
  
  if (t_policy->net4.loc_port != 0 && (t_policy->net4.loc_port!=t_edata->net4.loc_port)) {
    *t_cause = flag_loc_port;
    return 1;
  }

  if (t_policy->net4.dst_port != 0 && (t_policy->net4.dst_port!=t_edata->net4.dst_port)) {
    *t_cause = flag_dst_port;
    return 1;
  }

  return 0;
}

static int gatekeeper (struct pt_regs *ctx, struct KernelData *t_event_data, int *cause) {
  int zero = 0;
  int *aus = (int *) df.lookup(&zero); // 1 default deny 2 for default allow
  if (aus==NULL || *aus==0) return 0; // Policy may not be initialize (default==0)
  int def = *aus - 1;

  int match;
  struct KernelData *p;
  zero = -1;
  #pragma unroll (SIZEOF_POLICY)
  for (int i = 0; i < SIZEOF_POLICY; i++) {
    zero++;
    // Grabbing policy
    p = policy_holder.lookup(&zero);
    if (p==NULL) return 0;
    else if(p->policy_flag==-1) continue;

    // Matching policy with event
    match = match_policy(t_event_data, p, cause);
    // Injecting based on default deny/allow
    if (match == def) return -1;
  }

  return 0;
}


/* *********************************** */
// ===== ===== USER OUTPUT ===== ===== //
/* *********************************** */
// Stores the time since the first event was send to output
BPF_ARRAY(g_init_time, u64, 1);

/*
 * DESCRIPTION: fill a structure KernelData with all interesting information that
 *              can be gathered.
 * ARGS:
 *    ctx - ebpf context, given for each event_typ
 *    t_sk  - the socket from which to extract information
 *    t_event_data - the structure to fill
 *    t_etype - the cause that generated the event
 * RETURN: 0 if no error occurred, -1 otherwise
 */
static int fill_event(struct pt_regs *ctx, struct sock *sk, struct KernelData *t_event_data, event_type t_etype) {
  struct task_struct *curr_task, *parent_task;
  
  // Time since first event ----- //
  int key = 0;
  u64 *leaf = g_init_time.lookup(&key);
  u64 ktime = bpf_ktime_get_ns();
  if (leaf) { 
    if (*leaf == 0) {
      (*leaf) = ktime;
      t_event_data->ktime = 0;
    } // first time we visit the hash table, storing actual time
    else {
      t_event_data->ktime = (ktime - (*leaf)) / 1000;
    } // Calculate time wrt the fs event time
  }

  t_event_data->absolute_time = bpf_ktime_get_ns();

  // Current task ----- //
  curr_task = (struct task_struct *) bpf_get_current_task();
  fill_task(&t_event_data->task, curr_task);

  // cgroup ----- //
  u64 cgroup = CGROUP_ID
  t_event_data->task.cgroup = cgroup;

  // net namespace ----- //
  struct net *n = curr_task->nsproxy->net_ns;
  t_event_data->task.n = n;

  // Parent task ----- //
  bpf_probe_read(&parent_task, sizeof(struct task_struct *), &curr_task->real_parent);
  fill_task(&t_event_data->ptask, parent_task);

  // Net info ----- //
  fill_tcp_net(t_event_data, sk, t_etype);

  return 0;
}


/* ******************************* */
// ===== ===== CONNECT ===== ===== //
/* ******************************* */
int trace_connect_entry (struct pt_regs *ctx, struct sock *sk) {
  u32 tid = (bpf_get_current_pid_tgid() >> 32) & 0xFFFFFFFF;
  currsock.update(&tid, &sk);
  return 0;
};

/*
 * DESCRIPTION: Checks if a connect was successful executed and
 *              get the socket associated with it
 * ARGS:
 *    ctx - ebpf context, given for each event_typ
 *    t_sk - where to store the socket pointer
 * RETURN: 0 if no error occurred, -1 otherwise
 */
static int connect_check (struct pt_regs *ctx, struct sock **t_sk) {
  struct hash_entry *e;
  u64 diff;
  u32 tid = (bpf_get_current_pid_tgid() >> 32) & 0xFFFFFFFF;  

  // Uncomment to discard error events discarded
  // Checking if connect has succed, if not delete entry from table (SYNC packet fail)
  /*
  if (PT_REGS_RC(ctx) != 0) {
    currsock.delete(&tid);
    return -1;
  }
  */

  // Grabbing socket from table entry
  struct sock **aus = NULL;
  aus = currsock.lookup(&tid);
  if (aus == NULL || *aus == NULL) {
    return -1;
  }
  *t_sk = *aus;

  // We took the socket, we don't need the enry anymore
  currsock.delete(&tid);
  return 0;
}

int trace_connect_v4_return (struct pt_regs *ctx) {
  struct KernelData event_data = {};
  struct sock *sk;

  // Filling event ----- //
  if(connect_check(ctx, &sk) != 0) return -1; 
  fill_event(ctx, sk, &event_data, TCP_CONN);

  // Security filter ----- //
  #if INJECTION_ALLOW
  int cause;
  if(gatekeeper(ctx, &event_data, &cause) != 0) {
    event_data.policy_flag = cause;
    bpf_override_return(ctx, -1);
  }
  #endif

  // Submitting event
  FLTR_TASK
  user_buffer.perf_submit(ctx, &event_data, sizeof(struct KernelData));

  return 0;
}


/* ****************************** */
// ===== ===== ACCEPT ===== ===== //
/* ****************************** */
int trace_accept_return (struct pt_regs *ctx) {
  u16 family;
  struct KernelData event_data = {};
  
  // 'tcp_accept' return the socket we're looking for
  struct sock *sk = (struct sock *) PT_REGS_RC(ctx);
  if (sk == NULL) {
    return 0;
  }

  // Checking if IPv4 ----- //
  bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
  if (family != AF_INET) {
    return -1;
  }
  fill_event(ctx, sk, &event_data, TCP_ACPT);

  // Security filter ----- //
  #if INJECTION_ALLOW
  int cause;
  if(gatekeeper(ctx, &event_data, &cause) != 0) {
    event_data.policy_flag = cause;
    bpf_override_return(ctx, -1);
  }
  #endif
  
  // Submitting event
  FLTR_TASK
  user_buffer.perf_submit(ctx, &event_data, sizeof(struct KernelData));

  return 0;
}
