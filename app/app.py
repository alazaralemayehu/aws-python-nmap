import string
from unittest import result
import nmap
import subprocess
import os
def main(event=None, context=None):
    print(os.getuid())
    print(subprocess.check_output([ "whoami"]))
    # os.system("su sbx_user1051")
    # print(os.getlogin())
    nm = nmap.PortScanner()
    host_to_be_scanned = ""
    
    print(" os scan")
    detectedOS = performOSDetection(host_to_be_scanned,  nm)
    print(detectedOS)
    # 
    print(" port scan")
    ports = performTCPPortScan(host_to_be_scanned, nm)
    print(ports)
    
    print("ssl version")
    sslVersion = detectSSLVersion(host_to_be_scanned, nm)
    print(sslVersion)
    
    print("comprehensive scan")
    scanResult = performComprhensiveScan(host_to_be_scanned, nm)
    print(scanResult)
    

def performOSDetection(host_to_scan: string, nm: nmap.PortScanner):
    scanned = nm.scan(host_to_scan, arguments="-O")
    hosts = nm.all_hosts()
    results = []
    # print(scanned)
    for host in hosts:
        results.append(scanned['scan'][host]['osmatch'])
    return results
def detectSSLVersion(host_to_scan: string, nm: nmap.PortScanner):
    scanned = nm.scan(host_to_scan, arguments="-sV --script ssl-enum-ciphers -p 443") 
    # print(scanned)
    host = nm.all_hosts()[0]
    print("test")
    result:dict = scanned['scan'][host]['tcp'][443]['script']['ssl-enum-ciphers']
    
    return result 

def performTCPPortScan (host_to_scan: string, nm: nmap.PortScanner):
    nm.scan(host_to_scan, '1-1024','-v -sS -sV')
    hosts = nm.all_hosts()
    results = []

    for host in hosts:
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                result = str(port) + " : "+ str(nm[host][proto][port]) 
                results.append(result)
                # print(port , " info ", nm[host][proto][port])
    for i in results:
        print(i)
    return (results)

def performComprhensiveScan(host_to_scan: string, nm: nmap.PortScanner):
    nm.scan(host_to_scan, arguments='-v -A')
    results = []
    hosts = nm.all_hosts()
    for host in hosts:
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                result = str(port) + " : "+ str(nm[host][proto][port])
                results.append(result)
                # print(port , " info ", nm[host][proto][port])
    return (results)
def buildTable (detectedOs, sslVersion, portScan, ComprehsniveScan):
    
    print("test")
main()