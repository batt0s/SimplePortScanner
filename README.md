# SimplePortScanner
A simple tcp port scanner made in Python3.


# Usage

## scanner.py : 
scanner.py -H <target host> -p <target port(s)>

Examples :
scanner.py -H 192.168.1.1 -p 21
scanner.py -H google.com -p 21,22,80


## scannerthreaded.py : 
scannerthreaded.py -H <targetHost> -p <targetPort(s) (all : all ports)> -t <threads (default : 8)>

Example :
scannerthreaded.py -H 192.168.1.1 -p 21,22,80 -t 8
