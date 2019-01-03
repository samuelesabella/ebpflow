eBPFlow
=======
eBPF based network monitoring.

### run
eBPFlow can be executed by running
```
sudo ./ebpflow.py
```
### testing
eBPFlow can be tested by monitoring python tasks with command:
```
sudo ./ebpflow.py -t python
```
and generating a traffic burst with:
```
./burst_generator.py -c 1000
```
