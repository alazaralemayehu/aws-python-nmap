import string
import nmap
import subprocess
import os
def main(event=None, context=None):
    print(1)
    print(os.getuid())
    print(subprocess.check_output([ "whoami"]))
    # os.system("su sbx_user1051")
    # print(os.getlogin())
    nm = nmap.PortScanner()
    host_to_be_scanned = ""
    # performOSDetection(host_to_be_scanned,  nm)

    print("______-----------------------______ port scan")
    detectSSLVersion(host_to_be_scanned, nm)
    # performComprhensiveScan(host_to_be_scanned, nm)
    # performTCPPortScan(host_to_be_scanned, nm)




    

def performOSDetection(host_to_scan: string, nm: nmap.PortScanner):
    scanned = nm.scan(host_to_scan, arguments="-O -sV")
    hosts = nm.all_hosts()
    print(scanned)
    for host in hosts:
        print(scanned['scan'][host]['osmatch'])
        
def detectSSLVersion(host_to_scan: string, nm: nmap.PortScanner):
    scanned = nm.scan(host_to_scan, arguments="-sV --script ssl-enum-ciphers -p 443") 
    print(scanned)

def performTCPPortScan (host_to_scan: string, nm: nmap.PortScanner):
    nm.scan(host_to_scan, '1-1024','-v -sS -A -oG TCPPort')
    hosts = nm.all_hosts()

    for host in hosts:
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                print(port , " info ", nm[host][proto][port])

def performComprhensiveScan(host_to_scan: string, nm: nmap.PortScanner):
    nm.scan(host_to_scan, '1-1', '-v -sS -sV -sC -A -O -oG test.txt')
    hosts = nm.all_hosts()
    for host in hosts:
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                print(port , " info ", nm[host][proto][port])

main()