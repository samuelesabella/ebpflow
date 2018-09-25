#include <unistd.h>
#include <algorithm>
#include <iostream>
#include <signal.h>
#include <fstream>
#include <sstream>

#include <bcc/BPF.h>

// Credits to: Joel Sjögren
// https://stackoverflow.com/a/17469726
#include "colors.h" 

using namespace std;


// ----- ----- MACROS ----- ----- //
#define ERR(x) { 							\
    std::cerr << red << x << def << endl; 	\
}


// ----- ----- STRUCTS AND CLASSES ----- ----- //
// User kernel data
struct UserKernelData {
	__u32 pid;
	__u64 ts;
	char comm[16];
};


// ----- ----- GLOBALS ----- ----- //
int running = 1; // stopping condition
ebpf::BPF* bpf;

// colors ----- //
Color::Modifier red(Color::FG_RED);
Color::Modifier def(Color::FG_DEFAULT);


// ----- ----- FUNCTION DEFINITIONS ----- ----- //
string LoadEBPF(string t_filepath);


// ----- ----- CALLBACKS ----- ----- //
/*
 * NAME: HandleOutput
 * RETURN: zero on success; -1 if an error occurres
 */
void OutputHandler(void* t_bpfctx, void* t_data, int t_datasize) {
  auto event = static_cast<UserKernelData*>(t_data);
  std::cout << "PID: " << event->pid << " " << event->comm
            << std::endl;
}

/*
 * NAME: SignalHandler
 * BRIEF: schedule the execution termination
 */
void SignalHandler(int t_s) {
  std::cerr << "\rTerminating..." << std::endl;
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

	// attaching the probe ----- //
	auto attach_res = bpf->attach_kprobe("sys_sync", "trace");
	if (attach_res.code() != 0) {
		ERR(attach_res.msg());
		return 1;
	} // Error while attaching the probe
	
	// opening output buffer ----- //
	auto open_res = bpf->open_perf_buffer("events", &OutputHandler);
	if (open_res.code() != 0) {
		ERR(open_res.msg());
		return 1;
	} // Cannot open buffer

	// polling and capturing sigint ----- //
	signal(SIGINT, SignalHandler);
	std::cout << "Started tracing, hit Ctrl-C to terminate." << std::endl;
	while (running) {
		bpf->poll_perf_buffer("events");
	}

	return 0;
}


// ----- ----- IMPLEMENTATION ----- ----- //
/*
 * NAME: LoadEBPF
 * RETURN: a string containing the ebpf to be load
 */
string LoadEBPF(string t_filepath) {
	ifstream fileinput;
	fileinput.open(t_filepath);

	stringstream str_stream;
	str_stream << fileinput.rdbuf();
	return str_stream.str();
}