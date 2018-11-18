#!/usr/bin/env python
import signal
import sys
import json
import time
import threading
import argparse

# monotonic time (aka bpf_ktime_get_ns)
import monotonic; mtime = monotonic.time.time

from socket import inet_ntop, ntohs, AF_INET
from struct import pack

import ctypes as ct
from bcc import BPF


# ----- Globals and Termination ----- #
RUNNING = True

def signal_handler(sig, frame):
	global RUNNING
	RUNNING = False
signal.signal(signal.SIGINT, signal_handler)

# ----- Argument parsing ----- #
parser = argparse.ArgumentParser()
parser.add_argument('-t', '--task', default=None,
  help='add a filter based on task\'s name')
args = parser.parse_args()
FILTER_TASK = args.task


# *************************************** #
# ===== ===== DATA STRUCTURES ===== ===== #
# *************************************** #
# ----- User Kernel Data Structures ----- #
TASK_COMM_LEN = 16 
class task_info(ct.Structure):
  _fields_ = [
    ("pid", ct.c_uint32),
    ("uid", ct.c_uint32),
    ("gid", ct.c_uint32),
    ("cgroup", ct.c_uint64),
    ("n", ct.c_void_p),
    ("task", ct.c_char * TASK_COMM_LEN)
	]

class net_info4(ct.Structure):
  _fields_ = [
    ("loc_port", ct.c_uint16),
    ("dst_port", ct.c_uint16),
    ("saddr", ct.c_uint32),
    ("daddr", ct.c_uint32),
	]

class kernel_data(ct.Structure):
  _fields_ = [
    ("absolute_time", ct.c_uint64),
    ("ktime", ct.c_uint64),
    ("task", task_info),
    ("ptask", task_info),
    ("policy_flag", ct.c_int),
    ("etype", ct.c_int),
    ("net4", net_info4)
  ]

  _ltask = '[ktime: %s][gid: %s][uid: %s][pid: %s][%s]'
  _lparent = 'parent: [gid: %s][uid: %s][pid: %s][%s]'
  _lnetinfo = 'netinfo: [%s][IPv4][%s:%s <-> %s:%s]'
  _lcontainer = 'container: [%s][cgroup: %s]'
  _lsecurity = 'flags: [%s]'
  
  _etype_table = {
    601: 'TCP/ACC',
    602: 'TCP/CONN'
  }
  def etype2str (self): 
    return self._etype_table[self.etype]

  def __str__ (self):
    lines = []
    lines.append(self._ltask % (self.ktime, self.task.gid, self.task.uid, self.task.pid, self.task.task))
    lines.append(self._lparent % (self.ptask.gid, self.ptask.uid, self.ptask.pid, self.ptask.task))
    lines.append(self._lnetinfo % (self.etype2str(), 
      inet_ntop(AF_INET, pack("I", self.net4.saddr)), self.net4.loc_port, 
      inet_ntop(AF_INET, pack("I", self.net4.daddr)), self.net4.dst_port))
    lines.append(self._lsecurity % self.policy_flag)
    return '\n|__'.join(lines)

  def dump_json (self):
    return json.dumps(self)

  def from_json (self, json_data):
    print(json_data)

# ----- Events Statistics ----- #
class AtomicInteger():
  def __init__(self, t_value=0):
    self.m_value = t_value
    self.m_lock = threading.Lock()

  def __add__(self, t_v):
    with self.m_lock:
      self.m_value += t_v
      return self

  def get(self):
    with self.m_lock:
      return self.m_value

class Events_Statics():
  def __init__(self):
    self.connect_counter = AtomicInteger(0)
    self.accept_counter = AtomicInteger(0)

  def add(self, e):
    # Event counting
    if e.etype == 601:
      self.accept_counter += 1
    else:
      self.connect_counter += 1

  def __str__(self):
    line = '===== Events count =====\ntot: %s \naccpt: %s \nconn: %s'
    conn = self.accept_counter.get()
    acpt = self.connect_counter.get()
    return (line % (conn + acpt, conn, acpt))

# ************************************* #
# ===== ===== EVENT HANDLER ===== ===== #
# ************************************* 
estats = Events_Statics()
def print_ipv4_event(cpu, data, size):
  global estats
  event = ct.cast(data, ct.POINTER(kernel_data)).contents
  estats.add(event)
  print(str(event))


# ****************************** #
# ===== ===== POLICY ===== ===== #
# ****************************** #
class Policy:
  def __init__(self, t_bpf, src=None):
    self.m_bpf = t_bpf
    self.init_policy()
    self.mdef = 'None'
    self.policy = []

    if src is None:
      self.policy=[]
      self.df = 'allow'
    else:
      self.from_json(src)

  def from_json(src=None):
    with open(src) as f:
      jdata = json.load(f)
      self.policy = jdata.policy
      self.df = jdata.df
      # TODO: Translate from json to kernel data
      print(policy)

  def dump_json(self, dst=None):
    json_policy = [row.dump_json for row in self.polic]
    j = json.dumps({'policy': self.policy, 'df': self.df}, separators=(',',':'))

  def __call__(self, turn='off'):
    if turn not in ['on', 'off']:
      raise ValueError('Value "%s" not valid, only "on" and "off" are accepted' % turn) 
    if turn=='on':
      self.set_default(self.df)
    else:
      self.set_default('None')

  def set_default(self, df='allow'):
    self.df = df
    def_domain = {'allow':2 , 'deny': 1, 'None': 0}
    if df not in def_domain:
      raise ValueError('Value "%s" not valid, only "allow" and "deny" are accepted' % default)
    default = self.m_bpf['df']
    default[ct.c_int(0)] = ct.c_int(def_domain[df])

  def init_policy(self):
    policy_table = self.m_bpf.get_table('policy_holder', leaftype=kernel_data)
    for i in range(0, len(policy_table)):
      policy_table[ct.c_int(i)] = kernel_data(policy_flag=-1)

  def set_policy_row(self, t_bpf, row, t_index=-1, df='allow'):
    # Updating interal policy
    index = t_index if t_index != -1 else len(seld.policy)
    self.policy[index] = row
    # Updating kernel
    self.set_default(df)
    policy_table = self.m_bpf.get_table('policy_holder', leaftype=kernel_data)
    policy_table[ct.c_int(t_index)] = row
 
  def rm_policy_row(self, t_bpf, t_index):
    # Updating internal
    self.policy.pop(t_index)
    # Updating kernel
    policy_table = self.m_bpf.get_table('policy_holder', leaftype=kernel_data)
    policy_table[ct.c_int(t_index)] = kernel_data(policy_flag=-1)


  @staticmethod
  def new_rule(gid=-1, uid=-1, pid=-1, task='*', 
    pgid=-1, puid=-1, ppid=-1, ptask='*',
    etype=0, loc_port=0, dst_port=0):
    k = kernel_data(policy_flag=1)
    # task ----- //
    k.task.task = task
    k.task.gid = gid
    k.task.uid = uid
    k.task.pid = pid
    # ptask ----- //
    k.ptask.task = ptask
    k.ptask.gid = gid
    k.ptask.uid = puid
    k.ptask.pid = ppid
    # net ----- //
    k.etype = etype
    k.net4.loc_port = loc_port
    k.net4.dst_port = dst_port

    return k 


# **************************************** #
# ===== ===== ATTACHING PROBES ===== ===== #
# **************************************** #
def readebpf(src, task=None):
  """
  Load ebpf program in a string and, if specified, apply
  a filter on the task's name
  Argument:
    task - the task name whose events we are interested on
  Return: a string representing the eBPF program  
  """
  with open('ebpf.c', 'r') as ebpfile:
    ebpftxt = ebpfile.read()

  fltr = ''
  if task is not None:
    fltr = 'if(ebpf_strcmp(event_data.task.task, "%s") == 0)' % (task)
  return ebpftxt.replace('FLTR_TASK', fltr) 

# ----- Loading and manipulating ebpf ----- #
print('> Starting up...')
ebpf_str = readebpf('ebpf.c', FILTER_TASK)
bpf = BPF(text=ebpf_str)
print('> eBPF code loaded')

# ----- Attaching probes ----- #
bpf.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")  
bpf.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
bpf.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return") 
print('> eBPF event attached')

# ----- Opening the buffer ----- #
bpf["user_buffer"].open_perf_buffer(print_ipv4_event)
print('> Output buffer opened')

# ----- Polling events ----- #
print('> Start polling events. CTRL+C to stop\n')
while RUNNING is True:
  bpf.perf_buffer_poll(timeout=50)

print('\r  \n' + str(estats))

with open('events.log', 'a') as log:
  log.write(str(estats) + '\n')