#!/usr/bin/env python
import socket
import sys
import threading
import time
import argparse

import signal


# ----- Globals and Termination ----- #
running = True
TEST_MSG = 'Hello, eBPF!'

# ----- Argument parsing ----- #
parser = argparse.ArgumentParser()
parser.add_argument('-c', '--clients', default=1,
  help='specify the number of client to generate')
parser.add_argument('-p', '--port', default=55534,
  help='port to use')
parser.add_argument('-f', '--file', default=None,
  help='message text file')
args = parser.parse_args()

CLIENT_NUM = int(args.clients)
port = args.port
if args.file is not None:
  with open(args.file, 'r') as msgfile:
    TEST_MSG = msgfile.read()
    TEST_MSG = TEST_MSG.replace('\n', ' ')

# ************************************** */
# ===== ===== SIGNAL HANDLER ===== ===== //
# ************************************** */
def handle_signint(sig, frame):
  sys.exit(0)
signal.signal(signal.SIGINT, handle_signint)


# ****************************** */
# ===== ===== SERVER ===== ===== //
# ****************************** */
client_served = 0
class server (threading.Thread):
  def __init__(self, t_port):
    threading.Thread.__init__(self)
    self.port = t_port

  def run(self):
    i = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(.2)
    try:
      server_address = ('localhost', self.port)
      sock.bind(server_address)
      sock.listen(1)
      global running
      while running:
        try:
          cl_socket, client_address = sock.accept()
          cl_socket.send(TEST_MSG.encode())
          global client_served 
          client_served += 1
        except Exception:
          pass
    finally:
      sock.close()
    

# ****************************** */
# ===== ===== CLIENT ===== ===== //
# ****************************** */
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

cnum = AtomicInteger(0)

class client_thread (threading.Thread):
  def __init__(self, t_addr, t_port):
    threading.Thread.__init__(self)
    self.addr = (t_addr, t_port)

  def connect(self):
    s = socket.socket()
    s.settimeout(.5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
      s.connect(self.addr)
      s.recv(len(TEST_MSG) + 1)
      global cnum
      cnum += 1
      return True
    except Exception:
      return False
    finally:
      s.close()

  def run(self):
    while not self.connect():
      pass
      

class atlante_client():
  def __init__(self, t_addr, t_port):
    self.m_tlist = []
    self.port = t_port
    self.addr = t_addr

  def rise_up(self, t_num):
    for i in range(0, t_num):
      c = client_thread(self.addr, self.port)
      self.m_tlist.append(c)
      c.start()

  def join(self):
    for t in self.m_tlist:
      t.join()


# **************************** */
# ===== ===== MAIN ===== ===== //
# **************************** */
s = server(port)
s.start()

ac = atlante_client("localhost", port)
ac.rise_up(CLIENT_NUM)

ac.join()
print('Client terminated, closing server')
running = False
s.join()

print('Served: %s' % (client_served))
print('Connections: %s' % (cnum.get()))