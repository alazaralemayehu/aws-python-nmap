import string
import nmap
import subprocess
import os
def main(event=None, context=None):
    print(1)
    print(os.getuid())
    print(subprocess.check_output(["whoami"]))
    print(os.getlogin())
    nm = nmap.PortScanner()
    host_to_be_scanned = "scanme.nmap.org"
    performOSDetection(host_to_be_scanned,  nm)

    print("______-----------------------______ port scan")
    performComprhensiveScan(host_to_be_scanned, nm)
    # performTCPPortScan(host_to_be_scanned, nm)
    # nm.scan(host_to_be_scanned, '22-30', '-v -sS -sU -sV -sC -A -O')

    # nm.command_line()

    # hosts = nm.all_hosts()


    # for host in hosts:
    #     for proto in nm[host].all_protocols():
            
    #         ports = nm[host][proto].keys()

    #         for port in ports:
    #             print(port , " info ", nm[host][proto][port])
    #     # print(nm[host]['tcp'])

def performOSDetection(host_to_scan: string, nm: nmap.PortScanner):
    scanned = nm.scan(host_to_scan, arguments="-O")
    hosts = nm.all_hosts()

    for host in hosts:
        print(scanned['scan'][host]['osmatch'])

def performTCPPortScan (host_to_scan: string, nm: nmap.PortScanner):
    nm.scan(host_to_scan, '1-1024','-v -sS -A')
    hosts = nm.all_hosts()

    for host in hosts:
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                print(port , " info ", nm[host][proto][port])

def performComprhensiveScan(host_to_scan: string, nm: nmap.PortScanner):
    nm.scan(host_to_scan, '1-1024', '-v -sS -sV -sC -A -O')
    hosts = nm.all_hosts()
    for host in hosts:
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                print(port , " info ", nm[host][proto][port])

main()