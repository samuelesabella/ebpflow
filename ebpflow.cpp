#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <climits>
#include <bcc/BPF.h>

using namespace std;

#define TASK_COMM_LEN 16
#define NEW_EBF 1

u_int8_t running = 1;


// ----- ----- STRUCTS AND CLASSES ----- ----- //
struct ipv4KernelData {
  __u64 pid;
  __u64 uid;
  __u64 saddr;
  __u64 daddr;
  __u64 ip;
  __u16 loc_port;
  __u16 dst_port;
  char task[TASK_COMM_LEN];
};

struct ipv6KernelData {
  __u64 pid;
  __u64 uid;
  unsigned __int128 saddr;
  unsigned __int128 daddr;
  __u64 ip;
  __u16 loc_port;
  __u16 dst_port;
  char task[TASK_COMM_LEN];
};


/* ----- ----- MISCELLANEOUS ----- ----- */
char* intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    // Taking last byte
    u_int byte = addr & 0xff;

    // Printing first cipher
    *--cp = byte % 10 + '0';
    byte /= 10;
    // Checking if there are more ciphers
    if(byte > 0) {
      // Writing second cipher
      *--cp = byte % 10 + '0';
      byte /= 10;
      // Writing third cipher
      if(byte > 0)
        *--cp = byte + '0';
    }
    // Adding '.' character between decimals
    *--cp = '.';
    // Shifting address of one byte (next step we'll take last byte)
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

string StrReplace(string t_target, string t_old, string t_new, int ntimes=INT_MAX) {
  int i = 0;
  int oldsize = t_old.length();
  while (i<ntimes) {
    int pos = t_target.find(t_old);
    if (pos != string::npos) {
      t_target.replace(pos, oldsize, t_new);
    }
    else break;
  }
  return t_target;
}

string LoadEBPF(string t_filepath) {
  // loading string ----- //
  ifstream fileinput;
  fileinput.open(t_filepath);

  stringstream str_stream;
  str_stream << fileinput.rdbuf();
  string s = str_stream.str();

  // filtr parsing ----- //
  s = StrReplace(s, "FILTER_PORT_A", "");
  s = StrReplace(s, "FILTER_RPORT_A", "");
  s = StrReplace(s, "FILTER_PORT", "");
  s = StrReplace(s, "FILTER_RPORT", "");
  s = StrReplace(s, "FILTER_PID", "");
  s = StrReplace(s, "FILTER", "");

  return s;
}


// -------------- CALLBACKS ------------------- //
static void IPV4Handler(void* t_bpfctx, void* t_data, int t_datasize) {
  auto event = static_cast<ipv4KernelData*>(t_data);
  char buf1[32], buf2[32];
  
  if(strcmp("nc", event->task)!=0) return;

  printf("[IPv%lu][pid: %lu][uid: %lu][addr: %s:%d <-> %s:%d][%s]\n",
	 (long unsigned int)event->ip,
	 (long unsigned int)event->pid,
	 (long unsigned int)event->uid,
	 intoaV4(htonl(event->saddr), buf1, sizeof(buf1)),
	 event->loc_port,
   intoaV4(htonl(event->daddr), buf2, sizeof(buf2)),
   event->dst_port,
	 event->task);
}

static void IPV6Handler(void* t_bpfctx, void* t_data, int t_datasize) {
  auto event = static_cast<ipv6KernelData*>(t_data);
  
  printf("[IPv%lu][pid: %lu][uid: %lu][port:%d <-> %d][%s]\n",
   (long unsigned int)event->ip,
   (long unsigned int)event->pid,
   (long unsigned int)event->uid,
   event->loc_port,
   event->dst_port,
   event->task);
}

static void SignalHandler(int t_s) {
  std::cerr << "\nTerminating..." << std::endl;
  running = 0;
}

int AttachWrapper(ebpf::BPF* bpf, string t_kernel_fun, string t_ebpf_fun, bpf_probe_attach_type attach_type) {
  auto attach_res = bpf->attach_kprobe(t_kernel_fun, t_ebpf_fun, 
    #if NEW_EBF
    0,
    #endif
    attach_type);
  if(attach_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 0;
  }

  return 1;
}


/* ******************************************* */
/* ******************************************* */


int main() {
  // Initializing udp probe ----- //
  ebpf::BPF tcp_probe;
  auto init_res =tcp_probe.init(LoadEBPF("tcp_ebpflow.c"));
  if(init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  // attaching tcp probe ----- //
  if(
    !AttachWrapper(&tcp_probe, "tcp_v4_connect", "trace_connect_entry", BPF_PROBE_ENTRY) ||
    !AttachWrapper(&tcp_probe, "tcp_v6_connect", "trace_connect_entry", BPF_PROBE_ENTRY) ||
    !AttachWrapper(&tcp_probe, "tcp_v4_connect", "trace_connect_v4_return", BPF_PROBE_RETURN) || 
    !AttachWrapper(&tcp_probe, "tcp_v6_connect", "trace_connect_v6_return", BPF_PROBE_RETURN) ||
    !AttachWrapper(&tcp_probe, "inet_csk_accept", "trace_tcp_accept",       BPF_PROBE_RETURN)
  ){
    return 1;
  };

  // opening tcp output buffers ----- //
  auto open_res = tcp_probe.open_perf_buffer("ipv4_events", &IPV4Handler);
  if(open_res.code() != 0) { 
    std::cerr << open_res.msg() << std::endl; 
    return 1; 
  } 
  open_res = tcp_probe.open_perf_buffer("ipv6_events", &IPV6Handler);
  if(open_res.code() != 0) { 
    std::cerr << open_res.msg() << std::endl; 
    return 1; 
  }
  
  // initializing udp probe ----- //
  // ebpf::BPF udp_probe;
  // init_res = udp_probe.init(LoadEBPF("udp_ebpflow.c"));
  // if(init_res.code() != 0) {
  //   std::cerr << init_res.msg() << std::endl;
  //   return 1;
  // }

  // // attaching udp probe ----- //
  // if(
  //   !AttachWrapper(&udp_probe, "udp_sendmsg", "trace_send_entry", BPF_PROBE_ENTRY) ||
  //   !AttachWrapper(&udp_probe, "udp_sendmsg", "trace_send_v4_return", BPF_PROBE_RETURN) || 
  //   !AttachWrapper(&udp_probe, "udpv6_sendmsg", "trace_send_v6_return", BPF_PROBE_RETURN) ||
  //   !AttachWrapper(&udp_probe, "udp_recvmsg", "trace_receive_v4",       BPF_PROBE_RETURN) ||
  //   !AttachWrapper(&udp_probe, "udpv6_recvmsg", "trace_receive_v6",       BPF_PROBE_RETURN)
  // ){
  //   return 1;
  // };
  // // opening udp output buffers ----- //
  // open_res = udp_probe.open_perf_buffer("ipv4_events", &IPV4Handler);
  // if(open_res.code() != 0) { 
  //   std::cerr << open_res.msg() << std::endl; 
  //   return 1; 
  // }
  // open_res = udp_probe.open_perf_buffer("ipv6_events", &IPV6Handler);
  //   if(open_res.code() != 0) { 
  //     std::cerr << open_res.msg() << std::endl; 
  //     return 1; 
  // }  

  // polling and capturing sigint ----- //
  std::cout << "Started tracing, hit Ctrl-C to terminate." << std::endl;
  signal(SIGINT, SignalHandler);
  while(running) {
   tcp_probe.poll_perf_buffer("ipv4_events", 50);
   tcp_probe.poll_perf_buffer("ipv6_events",  50);

   // udp_probe.poll_perf_buffer("ipv4_events",    50);
   // udp_probe.poll_perf_buffer("ipv6_events",    50);
  }

  return 0;
}
