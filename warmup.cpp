#include <unistd.h>
#include <algorithm>
#include <iostream>

#include <bcc/BPF.h>

// Credits to: Joel Sjögren
// https://stackoverflow.com/questions/2616906/how-do-i-output-coloured-text-to-a-linux-terminal
#include "colors.h" 

using namespace std;

#define ERR(x) { 							\
    std::cerr << red << x << def << endl; 	\
}


// ----- ----- GLOBALS ----- ----- //
// colors
Color::Modifier red(Color::FG_RED);
Color::Modifier def(Color::FG_DEFAULT);

// bpf program
const std::string BPF_PROGRAM = R"(
#include <linux/sched.h>

// define output data structure in C
struct data_t {
	u32 pid;
	u64 ts;
	char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
	struct data_t data = {};

	data.pid = bpf_get_current_pid_tgid();
	data.ts = bpf_ktime_get_ns();
	bpf_get_current_comm(&data.comm, sizeof(data.comm));

	events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}
)";

// User kernel data
struct data_t {
	__u32 pid;
	__u64 ts;
	char comm[16];
};


int main(int argc, char** argv) {
	// ----- defining bpf ----- //
	ebpf::BPF bpf;
	auto init_res = bpf.init(BPF_PROGRAM);
	if (init_res.code() != 0) {
		ERR(init_res.msg());
		return 1;
	} // BPF couldn't be load

	// ----- attaching the probe ----- //
	auto attach_res = bpf.attach_kprobe("tcp_sendmsg", "hello");
	if (attach_res.code() != 0) {
		ERR(attach_res.msg());
		return 1;
	} // Error while attaching the probe
	
	/*
	int probe_time = 10;
	if (argc == 2) {
	probe_time = atoi(argv[1]);
	}
	std::cout << "Probing for " << probe_time << " seconds" << std::endl;
	sleep(probe_time);

	auto detach_res = bpf.detach_kprobe("tcp_sendmsg");
	if (detach_res.code() != 0) {
	std::cerr << detach_res.msg() << std::endl;
	return 1;
	}

	auto table =
	  bpf.get_hash_table<stack_key_t, uint64_t>("counts").get_table_offline();
	std::sort(
	  table.begin(), table.end(),
	  [](std::pair<stack_key_t, uint64_t> a,
	     std::pair<stack_key_t, uint64_t> b) { return a.second < b.second; });
	auto stacks = bpf.get_stack_table("stack_traces");

	int lost_stacks = 0;
	for (auto it : table) {
	std::cout << "PID: " << it.first.pid << " (" << it.first.name << ") "
	          << "made " << it.second
	          << " TCP sends on following stack: " << std::endl;
	if (it.first.kernel_stack >= 0) {
	  std::cout << "  Kernel Stack:" << std::endl;
	  auto syms = stacks.get_stack_symbol(it.first.kernel_stack, -1);
	  for (auto sym : syms)
	    std::cout << "    " << sym << std::endl;
	} else {
	  // -EFAULT normally means the stack is not availiable and not an error
	  if (it.first.kernel_stack != -EFAULT) {
	    lost_stacks++;
	    std::cout << "    [Lost Kernel Stack" << it.first.kernel_stack << "]"
	              << std::endl;
	  }
	}
	if (it.first.user_stack >= 0) {
	  std::cout << "  User Stack:" << std::endl;
	  auto syms = stacks.get_stack_symbol(it.first.user_stack, it.first.pid);
	  for (auto sym : syms)
	    std::cout << "    " << sym << std::endl;
	} else {
	  // -EFAULT normally means the stack is not availiable and not an error
	  if (it.first.user_stack != -EFAULT) {
	    lost_stacks++;
	    std::cout << "    [Lost User Stack " << it.first.user_stack << "]"
	              << std::endl;
	  }
	}
	}

	if (lost_stacks > 0)
	std::cout << "Total " << lost_stacks << " stack-traces lost due to "
	          << "hash collision or stack table full" << std::endl;
	*/
	return 0;
}