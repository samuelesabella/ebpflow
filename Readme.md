ebpflow
=======
This project aims to offer a packet flow tracer based on eBPF.

### Dependencies
__ebpflow__ needs [BPF Compiler Collection](https://github.com/iovisor/bcc/) (*BCC*) to be installed. More info concerning how to install *BCC* can be found by visiting: [installing bcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

### Running and testing
From the project root, *ebpflow* can be used by running:
```
$ sudo ./ebpflow.py
```
Together with *ebpflow* this repo offers another tool (i.e. *burst_generator.py*) to set-up a testing environment. The tool creates a server application and multiple clients that connects to server, send a small message and then close the connection. To generate a traffic burst composed of 10 clients and one server handling connections, from the project's root directory run:
```
$ ./burst_generator.py -c 100
```
Booth tool supports the flag *-h* to show the options availables

### How is information gathered?
Information regarding each process is read from inside kernel's data structures, starting from [__task_struct__](https://elixir.bootlin.com/linux/v4.18.10/source/include/linux/sched.h#L593) . Containers are distinguished by other processes by looking at the cgroup identifier to which each process belongs to. The docker daemon can then be queried by using the docker id, returned by *ebpflow*, to exctract further information about the container.
