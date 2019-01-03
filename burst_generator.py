#!/usr/bin/env python
import socket
import sys
import threading
import time
import argparse

import signal


# ----- Globals ----- #
TEST_MSG = 'Hello, eBPF!'
TERMINATION_MSG = '<END>'

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
PORT = int(args.port)
if args.file is not None:
  with open(args.file, 'r') as msgfile:
    TEST_MSG = msgfile.read()
    TEST_MSG = TEST_MSG.replace('\n', ' ')
print('Creating {0} clients and a server on port {1}'.format(CLIENT_NUM, PORT))
print('burst_generator -h to show help message')

# ****************************** */
# ===== ===== SERVER ===== ===== //
# ****************************** */
client_served = 0
class server (threading.Thread):
  """
  Creates a server thread that listens on port t_port
  and terminates when TERMINATION_MSG is received
  """
  def __init__(self, t_port):
    threading.Thread.__init__(self)
    self.port = t_port

  def run(self):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
      server_address = ('localhost', self.port)
      sock.bind(server_address)
      sock.listen(1)
      while True:
        try:
          connection, client_address = sock.accept()
          data = connection.recv(16)
        except socket.error, exc:
          continue 
        stringdata = data.decode('utf-8')
        if stringdata==TERMINATION_MSG:
          break
    finally:
      sock.close()
    

# ****************************** */
# ===== ===== CLIENT ===== ===== //
# ****************************** */
class client_thread (threading.Thread):
  """
  Creates a client thread that connects to t_addr:t_port and 
  tries to send t_msg until it succeeds
  """
  def __init__(self, t_addr, t_port, t_msg):
    threading.Thread.__init__(self)
    self.addr = (t_addr, t_port)
    self.msg = t_msg

  def connect(self):
    """
    Tries to connect to self.addr:self.msg and send self.msg
    Return: True if no error occurres otherwise False 
    """
    s = socket.socket()
    s.settimeout(.5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
      s.connect(self.addr)
      s.send(self.msg)
      return True
    except socket.error, exc:
      return False
    finally:
      s.close()

  def run(self):
    while not self.connect():
      pass
      

class atlante_client():
  """
  Manages a pool of clients that connect to t_addr:t_port
  """
  def __init__(self, t_addr, t_port):
    self.m_tlist = []
    self.port = t_port
    self.addr = t_addr
  
  def rise_up(self, t_num):
    """
    Creates t_num clients sending TEST_MSG on t_addr:t_port
    """
    for i in range(0, t_num):
      c = client_thread(self.addr, self.port, TEST_MSG)
      self.m_tlist.append(c)
      c.start()

  def join(self):
    """
    Joins all the threads created
    """
    for t in self.m_tlist:
      t.join()


# **************************** */
# ===== ===== MAIN ===== ===== //
# **************************** */
# Starting server
s = server(PORT)
s.start()
# Running clients
ac = atlante_client("localhost", PORT)
ac.rise_up(CLIENT_NUM)
ac.join()
# Starting last client (i.e. the one that sends TERMINATION_MSG)
term_thread = client_thread("localhost", PORT, TERMINATION_MSG)
term_thread.start()
term_thread.join()
# Joining the server
s.join()

