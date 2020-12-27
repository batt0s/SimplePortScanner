#!/usr/bin/python3

import socket
import optparse
from threading import *
import sys

class colors:
    HEADER = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



def main():

    parser = optparse.OptionParser("Usage : scanner.py -H <target host> -p <target port(s)>\nExamples : \nscanner.py -H 192.168.1.1 -p 21\nscanner.py -H google.com -p 21,22,80")

    parser.add_option('-H', dest='tgtHost', type='string', help='Target host.')
    parser.add_option('-p', dest='tgtPort', type='string', help='Target port(s).')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')
    if (tgtHost == None) | (tgtPorts[0] == None):
        print(parser.usage)
        sys.exit()
    Scan(tgtHost, tgtPorts)



def Scan(tgtHost,tgtPorts):

    try:
        tgtIP = socket.gethostbyname(tgtHost)

    except:
        print(colors.FAIL + "Unknown host %s " %tgtHost + colors.ENDC)
        exit()


    print(colors.BOLD + colors.WARNING + "[*]" + colors.ENDC + colors.BOLD + " Scan results for "+ tgtHost + " (" + tgtIP + ")" + colors.ENDC)


    
    socket.setdefaulttimeout(1)

    for tgtPort in tgtPorts:

        t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
        t.start()
#        connScan(tgtHost, int(tgtPort))



def connScan(tgtHost, tgtPort):

    try:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((tgtHost, tgtPort))
        try:
            banner = sock.recv(1024).decode()
        except:
            banner = colors.FAIL + "[-] " + colors.ENDC + "Can't grab banner."

        print(colors.OKGREEN + "[+]" + colors.ENDC + f" {tgtPort}/tcp open\nBanner : \n" + banner + "\n")

    except:

        print(colors.FAIL + "[-]" + colors.ENDC + f" {tgtPort}/tcp closed")

    finally:

        sock.close()




if __name__ == "__main__":

    main()
