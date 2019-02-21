package main

import "C"
import (
  "bytes"
  "encoding/binary"
  "fmt"
  "os"
  "strings"
  "os/signal"
  "io/ioutil"

  "strconv"

  bpf "github.com/iovisor/gobpf/bcc"
)

type Etype uint32
const (
  TCP_ACPT Etype = 601 // The event has been triggered by "tcp_v4_connect" call 
  TCP_CONN Etype = 602 // "inet_csk_accept" callBINARY MessageType = 1
)
const CGROUP_NAME = 64
const TASK_COMM_LEN = 16


/* ****************************************** */
// ===== ===== KERNEL->USER EVENT ===== ===== //
/* ****************************************** */
type Task_info struct {
  Pid uint32
  Uid uint32
  Gid uint32
  Cgroup [CGROUP_NAME]byte // container id
  Task [TASK_COMM_LEN]byte // task name
}

type Net_info4 struct {
  Loc_port uint16 // local port
  Dst_port uint16 // remote port
  Saddr uint32 // source address
  Daddr uint32 // destination address
}

type KernelData struct {
  Absolute_time uint64 // need to measure the time to sget the event
  Ktime uint64 // usec since first event
  Task Task_info // Task that triggered the ebpf event
  Ptask Task_info // Parent task
  Event_type Etype
  Net4 Net_info4
}

func attachProbe (m *bpf.Module, syscall string, bpfprobe string, ret ...int) (int, string) {
  kprobe, err := m.LoadKprobe(bpfprobe)
  if err != nil {
    res := fmt.Sprintf("Failed to load %s: %s\n", bpfprobe, err)
    return -1, res
  }

  if len(ret) == 0 {
    err = m.AttachKprobe(syscall, kprobe)
  } else {
    err = m.AttachKretprobe(syscall, kprobe)
  }

  if err != nil {
   res := fmt.Sprintf("Failed to attach return_value - %s\n", err)
   return -1, res
  }

  return 0, ""
}

func ntoh(ip uint32) string {
  iphost := int64(ip)
  a3 := strconv.FormatInt((iphost>>24)&0xff, 10)
  a2 := strconv.FormatInt((iphost>>16)&0xff, 10)
  a1 := strconv.FormatInt((iphost>>8)&0xff, 10)
  a0 := strconv.FormatInt((iphost & 0xff), 10)
  return a0 + "." + a1 + "." + a2 + "." + a3
}


func main() {
  fmt.Printf("goebpflow - tcp connection monitoring using go\n")

  // Reading ebpflow code ----- //
  ebpflow_rawsrc, err := ioutil.ReadFile("ebpf.c")
  if err != nil {
    fmt.Fprintf(os.Stderr, "Failed to read ebpf codes")
    os.Exit(1)  
  }
  ebpflow_src := string(ebpflow_rawsrc)
  ebpflow_src = strings.Replace(ebpflow_src, "FLTR_TASK", "", -1)
  fmt.Printf("> eBPF code parsed succesfully\n")

  // Initializing probe ----- //
  m := bpf.NewModule(ebpflow_src, []string{})
  defer m.Close()

  // // Attaching probes ----- //
  res, bpferr := attachProbe(m, "tcp_v4_connect", "trace_connect_entry")
  if res != 0 {
    fmt.Println(bpferr)
  }

  res, bpferr = attachProbe(m, "tcp_v4_connect", "trace_connect_v4_return", 1)
  if res != 0 {
    fmt.Println(bpferr)
  }

  res, bpferr = attachProbe(m, "inet_csk_accept", "trace_accept_return", 1)
  if res != 0 {
    fmt.Println(bpferr)
  }
  fmt.Printf("> Probes attached\n")

  // Opening event buffer ----- //
  table := bpf.NewTable(m.TableId("user_buffer"), m)
  channel := make(chan []byte)

  perfMap, err := bpf.InitPerfMap(table, channel)
  if err != nil {
    fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
    os.Exit(1)
  }
  fmt.Printf("> Kernel buffer opened\n")

  sig := make(chan os.Signal, 1)
  signal.Notify(sig, os.Interrupt, os.Kill)

  go func() {
    fmt.Printf("> Start polling\n")
    var event KernelData
    for {
      // Polling event
      data := <- channel
      err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
      if err != nil {
        fmt.Printf("failed to decode received data: %s\n", err)
        continue
      }
      // Parsing C struct
      task := string(event.Task.Task[:bytes.IndexByte(event.Task.Task[:], 0)])
      cgroup := string(event.Task.Cgroup[:bytes.IndexByte(event.Task.Cgroup[:], 0)]) 
      ptask := string(event.Ptask.Task[:bytes.IndexByte(event.Ptask.Task[:], 0)])
      event_type := "TCP/CONN"
      if event.Event_type == TCP_ACPT { event_type = "TCP/ACPT" }
      is_container := (cgroup != "/")
      // Netinfo conversion
      saddr := ntoh(event.Net4.Saddr)
      daddr := ntoh(event.Net4.Daddr)
      // Display info
      fmt.Printf("[%d][gid:%d][uid:%d][pid:%d][%s] \n", event.Ktime, event.Task.Gid, event.Task.Uid, event.Task.Pid, task)
      fmt.Printf("   [gid:%d][uid:%d][pid:%d][%s] (parent) \n", event.Ptask.Gid, event.Ptask.Uid, event.Ptask.Pid, ptask)
      fmt.Printf("   [%s][IPv4][%5s:%d <-> %5s:%d] \n", event_type, saddr, event.Net4.Loc_port, daddr, event.Net4.Dst_port)
      if is_container {
        fmt.Printf("   [cID:%.12s] (docker) \n", cgroup)
      }
    }
  }()

  perfMap.Start()
  <-sig
  perfMap.Stop()
}
