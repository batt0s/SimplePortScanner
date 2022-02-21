#!/usr/bin/python3

import socket
import threading
import sys
import optparse
from queue import Queue
from datetime import datetime


class colored:
	HEADER = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'




def main():

	parser = optparse.OptionParser(f"Usage : {sys.argv[0]} -H <targetHost> -p <targetPort(s) (all : all ports)> -t <threads (default : 8)>\nExample : \n{sys.argv[0]} -H 192.168.1.1 -p 21,22,80 -t 8")

	parser.add_option('-H', dest="tgtHost", type="string")
	parser.add_option('-p', dest="tgtPorts", type="string")
	parser.add_option('-t', dest="threads", type="string")

	(options, args) = parser.parse_args()

	tgtHost = options.tgtHost
	tgtPorts = options.tgtPorts
	threads = options.threads

	if (tgtHost == None):

		print(parser.usage)

		sys.exit()

	if (tgtPorts == None):
		print(parser.usage)
		sys.exit()
	if (tgtPorts == "all"):
		tgtPorts = range(1, 49152)
	else:
		tgtPorts = tgtPorts.split(",")
	if (tgtPorts[0] == None):
		print(parser.usage)
		sys.exit()




	if (threads == None):
		threads = 8
	else:
		threads = int(threads)

	socket.setdefaulttimeout(2)

	global open_ports
	open_ports = []

	try:
		tgtIP = socket.gethostbyname(tgtHost)

	except:
		print(colored.FAIL + "[!] Unknown host " + tgtHost + colored.ENDC)
		sys.exit()


	queue = Queue()

	for tgtPort in tgtPorts:
		queue.put(tgtPort)


	print(colored.BOLD + colored.WARNING + "[*]" + colored.ENDC + colored.BOLD + colored.HEADER + f"\tScan results for {tgtHost} ({tgtIP}) : " + colored.ENDC)
	print("\n")

	def worker():
		while not queue.empty():
			tgtPort = queue.get()
			Scan(tgtHost, tgtPort)

	thread_list = []

	start = datetime.now()

	for t in range(threads):
		thread = threading.Thread(target=worker)
		thread_list.append(thread)

	for thread in thread_list:
		thread.start()

	for thread in thread_list:
		thread.join()

	stop = datetime.now()

	print(colored.HEADER + "\n\n\tDone" + colored.ENDC + f"  (In {stop-start})\nDiscovered open ports : ")
	for port in open_ports:

		print(colored.WARNING + port + colored.ENDC)








def Scan(tgtHost, tgtPort):


	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((tgtHost, int(tgtPort)))
		try:
			banner = s.recv(1024).decode()
		except:
			banner = colored.FAIL + "[-]" + colored.ENDC + "Can't grab banner."

		open_ports.append(tgtPort)

		print(colored.OKGREEN + "\n[+]" + colored.ENDC + f" {tgtPort}/tcp open.\nBanner : \n----------------------------------------------\n" + banner + "\n----------------------------------------------")


	except:
		print(colored.FAIL + "\n[-]" + colored.ENDC + f" {tgtPort}/tcp is closed.")

	finally:
		s.close()






if __name__ == "__main__":

	main()
