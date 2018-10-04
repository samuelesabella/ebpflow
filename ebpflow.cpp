#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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
/*
 * proto flag: 
 *    - 601  for tcp client
 *    - 602  for tcp server
 *    - 1701 for upd receive
 *    - 1702 for udp send  
 */
struct ipv4KernelData {
  __u32 pid;
  __u32 uid;
  __u32 gid;
  __u16 proto;
  __u16 loc_port;
  __u16 dst_port;
  __u16 ip;
  __u32 saddr;
  __u32 daddr;
  char task[TASK_COMM_LEN];
};

struct ipv6KernelData {
  __u32 pid;
  __u32 uid;
  __u32 gid;
  __u16 proto;
  __u16 loc_port;
  __u16 dst_port;
  __u16 ip;
  unsigned __int128 saddr;
  unsigned __int128 daddr;
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

char* intoaV6(unsigned __int128 addr, char* buf, u_short bufLen) {
  char *ret = (char*)inet_ntop(AF_INET6, &addr, buf, bufLen);

  if(ret == NULL) {
    buf[0] = '\0';
  }

  return(buf);
}

string LoadEBPF(string t_filepath) {
  // loading string ----- //
  ifstream fileinput;
  fileinput.open(t_filepath);

  stringstream str_stream;
  str_stream << fileinput.rdbuf();
  string s = str_stream.str();

  return s;
}


// -------------- CALLBACKS ------------------- //
int event_type (int t_proto, char* t_buffer, int t_size) {
  switch (t_proto) {
    case 601:
      strncpy(t_buffer, "TCP/s",  t_size);
      break;
    case 602:
      strncpy(t_buffer, "TCP/c",  t_size);
      break;
    case 1701:
      strncpy(t_buffer, "UDP/l", t_size);
      break;
    case 1702:
      strncpy(t_buffer, "UDP/s", t_size);
      break;
    default:
      strncpy(t_buffer, " - ",  t_size);
      break;
  }
  return 1;
}

static void IPV4Handler(void* t_bpfctx, void* t_data, int t_datasize) {
  auto event = static_cast<ipv4KernelData*>(t_data);
  char buf1[32], buf2[32];

  char e_type[16];
  event_type(event->proto, e_type, sizeof(e_type));

  printf("[%s][IPv%d][pid: %lu][uid: %lu][gid: %lu][addr: %s:%d <-> %s:%d][%s]\n",
    e_type,
	  event->ip,
	  (long unsigned int)event->pid,
	  (long unsigned int)event->uid,
    (long unsigned int)event->gid,
	  intoaV4(htonl(event->saddr), buf1, sizeof(buf1)),
	  event->loc_port,
    intoaV4(htonl(event->daddr), buf2, sizeof(buf2)),
    event->dst_port,
	  event->task
  );
}

static void IPV6Handler(void* t_bpfctx, void* t_data, int t_datasize) {
  auto event = static_cast<ipv6KernelData*>(t_data);
  char buf1[128], buf2[128];

  char e_type[16];
  event_type(event->proto, e_type, sizeof(e_type));
  
  printf("[%s][IPv%d][pid: %lu][uid: %lu][gid: %lu][%s:%d <-> %s:%d][%s]\n",
    e_type,
    event->ip,
    (long unsigned int)event->pid,
    (long unsigned int)event->uid,
    (long unsigned int)event->gid,
    intoaV6(htonl(event->saddr), buf1, sizeof(buf1)),
    event->loc_port,
    intoaV6(htonl(event->saddr), buf2, sizeof(buf2)),
    event->dst_port,
    event->task
  );
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
  ebpf::BPF udp_probe;
  init_res = udp_probe.init(LoadEBPF("udp_ebpflow.c"));
  if(init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  // // attaching udp probe ----- //
  if(
    !AttachWrapper(&udp_probe, "udp_sendmsg", "trace_send_entry", BPF_PROBE_ENTRY) ||
    !AttachWrapper(&udp_probe, "udp_sendmsg", "trace_send_v4_return", BPF_PROBE_RETURN) || 
    !AttachWrapper(&udp_probe, "udpv6_sendmsg", "trace_send_v6_return", BPF_PROBE_RETURN) ||
    !AttachWrapper(&udp_probe, "udp_recvmsg", "trace_receive_v4",       BPF_PROBE_RETURN) ||
    !AttachWrapper(&udp_probe, "udpv6_recvmsg", "trace_receive_v6",       BPF_PROBE_RETURN)
  ){
    return 1;
  };
  // opening udp output buffers ----- //
  open_res = udp_probe.open_perf_buffer("ipv4_events", &IPV4Handler);
  if(open_res.code() != 0) { 
    std::cerr << open_res.msg() << std::endl; 
    return 1; 
  }
  open_res = udp_probe.open_perf_buffer("ipv6_events", &IPV6Handler);
    if(open_res.code() != 0) { 
      std::cerr << open_res.msg() << std::endl; 
      return 1; 
  }  

  // polling and capturing sigint ----- //
  std::cout << "Started tracing, hit Ctrl-C to terminate." << std::endl;
  signal(SIGINT, SignalHandler);
  while(running) {
    tcp_probe.poll_perf_buffer("ipv4_events", 50);
    tcp_probe.poll_perf_buffer("ipv6_events",  50);

    udp_probe.poll_perf_buffer("ipv4_events",    50);
    udp_probe.poll_perf_buffer("ipv6_events",    50);
  }

  return 0;
}
