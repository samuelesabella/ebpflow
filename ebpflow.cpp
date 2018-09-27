#include <unistd.h>
#include <algorithm>
#include <iostream>
#include <signal.h>
#include <fstream>
#include <sstream>
#include <climits>

#include <bcc/BPF.h>

// Credits to: Joel Sjögren
// https://stackoverflow.com/a/17469726
#include "colors.h" 

using namespace std;


// ----- ----- MACROS ----- ----- //
#define ERR(x) { 							\
    std::cerr << red << x << def << endl; 	\
}


// ----- ----- GLOBALS ----- ----- //
int running = 1; // stopping condition
const int TASK_COMM_LEN = 16;
ebpf::BPF* bpf;

// colors ----- //
Color::Modifier red(Color::FG_RED);
Color::Modifier def(Color::FG_DEFAULT);


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


// ----- ----- FUNCTION DEFINITIONS ----- ----- //
string LoadEBPF(string t_filepath);


// ----- ----- CALLBACKS ----- ----- //
void IPV4Handler(void* t_bpfctx, void* t_data, int t_datasize) {
	auto event = static_cast<ipv4KernelData*>(t_data);
	std::cout << event->port << std::endl;

}

void IPV6Handler(void* t_bpfctx, void* t_data, int t_datasize) {
	auto event = static_cast<ipv6KernelData*>(t_data);
	std::cout << event->port << event->uid;
}


/*
 * NAME: SignalHandler
 * BRIEF: schedule the execution termination
 */
void SignalHandler(int t_s) {
  std::cerr << "\nTerminating..." << std::endl;
  delete bpf;
  running = 0;
}


// ----- ----- MAIN ----- ----- //
int main(int argc, char** argv) {
	const std::string BPF_PROGRAM = LoadEBPF("ebpflow.ebpf");

	bpf = new ebpf::BPF();

	auto init_res = bpf->init(BPF_PROGRAM);
	if (init_res.code() != 0) {
		ERR(init_res.msg());
		return 1;
	} // BPF couldn't be load

	// attaching probes ----- //
	auto attach_res = bpf->attach_kprobe("tcp_v4_connect", "trace_connect_entry");
	if (attach_res.code() != 0) {
		ERR(attach_res.msg());
		return 1;
	} // Error while attaching the probe

	attach_res = bpf->attach_kprobe("tcp_v4_connect", "trace_connect_v4_return", 0, BPF_PROBE_RETURN);
	if (attach_res.code() != 0) {
		ERR(attach_res.msg());
		return 1;
	} // Error while attaching the probe

	attach_res = bpf->attach_kprobe("tcp_v6_connect", "trace_connect_v6_return", 0, BPF_PROBE_RETURN);
	if (attach_res.code() != 0) {
		ERR(attach_res.msg());
		return 1;
	} // Error while attaching the probe
	
	// opening output buffer ----- //
	auto open_res = bpf->open_perf_buffer("ipv4_connect_events", &IPV4Handler);
	if (open_res.code() != 0) {
		ERR(open_res.msg());
		return 1;
	} // Cannot open buffer

	// polling and capturing sigint ----- //
	signal(SIGINT, SignalHandler);
	std::cout << "Started tracing, hit Ctrl-C to terminate." << std::endl;
	while (running) {
		bpf->poll_perf_buffer("ipv4_connect_events");
	}

	return 0;
}


// ----- ----- IMPLEMENTATION ----- ----- //
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

/*
 * NAME: LoadEBPF
 * RETURN: a string containing the ebpf to be load
 */
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