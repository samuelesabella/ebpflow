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
  __u64 port;
  char task[TASK_COMM_LEN];
};

struct ipv6KernelData {
  __u64 pid;
  __u64 uid;
  unsigned __int128 saddr;
  unsigned __int128 daddr;
  __u64 ip;
  __u64 port;
  char task[TASK_COMM_LEN];
};


/* ----- ----- MISCELLANEOUS ----- ----- */
/*
 * Converts an addr into a string
 */
char* intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    u_int byte = addr & 0xff;

    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
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

  printf("[IPv%lu][pid: %lu][uid: %lu][addr: %s <-> %s][port: %lu][%s]\n",
	 (long unsigned int)event->ip,
	 (long unsigned int)event->pid,
	 (long unsigned int)event->uid,
	 intoaV4(htonl(event->saddr), buf1, sizeof(buf1)),
	 intoaV4(htonl(event->daddr), buf2, sizeof(buf2)),
	 (long unsigned int)event->port,
	 event->task);
}

static void IPV6Handler(void* t_bpfctx, void* t_data, int t_datasize) {
  auto event = static_cast<ipv6KernelData*>(t_data);
  // char buf1[128], buf2[128];

  printf("[IPv%lu][pid: %lu][uid: %lu][port: %lu][%s]\n",
   (long unsigned int)event->ip,
   (long unsigned int)event->pid,
   (long unsigned int)event->uid,
   (long unsigned int)event->port,
   event->task);
}

static void SignalHandler(int t_s) {
  std::cerr << "\nTerminating..." << std::endl;
  running = 0;
}

int AttachProbe(ebpf::BPF* bpf, string t_kernel_fun, string t_ebpf_fun, bpf_probe_attach_type attach_type) {
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

int main() {
  ebpf::BPF bpf;
  auto init_res = bpf.init(LoadEBPF("ebpflow.ebpf"));
  if(init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  // attaching tcp probes ----- //
  if(
    !AttachProbe(&bpf, "tcp_v4_connect", "trace_connect_entry", BPF_PROBE_ENTRY) ||
    !AttachProbe(&bpf, "tcp_v4_connect", "trace_connect_v4_return", BPF_PROBE_RETURN) || 
    !AttachProbe(&bpf, "tcp_v6_connect", "trace_connect_v6_return", BPF_PROBE_RETURN) ||
    !AttachProbe(&bpf, "inet_csk_accept", "trace_tcp_accept",       BPF_PROBE_RETURN)
  ){
    return 1;
  };

  // opening output buffers ----- //
  auto open_res = bpf.open_perf_buffer("ipv4_connect_events", &IPV4Handler);
  if(open_res.code() != 0) { 
    std::cerr << open_res.msg() << std::endl; 
    return 1; 
  }
  auto open_res = bpf.open_perf_buffer("ipv4_accept_events", &IPV4Handler);
    if(open_res.code() != 0) { 
      std::cerr << open_res.msg() << std::endl; 
      return 1; 
  }  
  open_res = bpf.open_perf_buffer("ipv6_connect_events", &IPV6Handler);
  if(open_res.code() != 0) { 
    std::cerr << open_res.msg() << std::endl; 
    return 1; 
  }
  open_res = bpf.open_perf_buffer("ipv6_accept_events", &IPV6Handler);
    if(open_res.code() != 0) { 
      std::cerr << open_res.msg() << std::endl; 
      return 1; 
  }  


  // polling and capturing sigint ----- //
  signal(SIGINT, SignalHandler);
  std::cout << "Started tracing, hit Ctrl-C to terminate." << std::endl;
  while(running) {
    // Polling every buffer with a timeout of 500 ms ()
    bpf.poll_perf_buffer("ipv4_connect_events", 500);
    bpf.poll_perf_buffer("ipv4_accept_events",  500);
    bpf.poll_perf_buffer("ipv6_accept_events",  500);
    bpf.poll_perf_buffer("ipv6_connect_events", 500);
  }

  cout << "Goodbye" << endl;
  return 0;
}
