import nmap

# Prompt user for input. Target IP Address, Target Ports, and types of scans.
# target = '127.0.0.1'  # localhost
# ports = '80'


# initialize nmap object
nmap_Scan = nmap.PortScanner()

# Scan for localhosts 
nmap_Scan.scan('127.0.0.1', '80')
#nmap_Scan.scan(target, ports)

for host in nmap_Scan.all_hosts():
     print('Host : %s (%s)' % (host, nmap_Scan[host].hostname()))
     print('State : %s' % nmap_Scan[host].state())
     for proto in nmap_Scan[host].all_protocols():
         print('----------')
         print('Protocol : %s' % proto)
 
         lport = nmap_Scan[host][proto].keys()
         lport.sort()
         for port in lport:
             print ('port : %s\tstate : %s' % (port, nmap_Scan[host][proto][port]['state'])

