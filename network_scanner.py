 #!/usr/bin/python3

import nmap


def scan_single_host():
	nm = nmap.PortScanner()
	ip = input("Enter the IP")
	print("wait......")
	try:
		scan = nm.scan(hosts=ip,ports="1-100",arguments="-sS -O -v -Pn")
		print(scan["scan"][ip]["addresses"]["ipv4"],"Scanning single host")
		for host in scan["scan"][ip]['tcp'].items():
			print("___________Details_____________")
			print("Tcp Port :",host[0])
			print("State :",host[1]['state'])
			print("Reason :",host[1]['reason'])
			print("Name :",host[1]['name'])
	except:
		print("Use root privilige")

def scan_range():
	nm = nmap.PortScanner()
	ip = input("Enter the IP")
	print("wait..............")
	try:
		scan = nm.scan(hosts=ip,arguments="-sS -O -Pn")
		print("_________Host Range_________")
		for host in scan["scan"]:
			print("Ip range :",host)
	except:
		print("Use root privilige")

def scan_network():
	nm = nmap.PortScanner()
	ip = input("Enter the ip address")
	print("wait.......")
	try:
		scan = nm.scan(hosts=ip,arguments="-sS -O -Pn")
		for  i in scan["scan"][ip]["osmatch"]:
			print("__________Scan Network___________")
			print("Name :",i['name'])
			for j in i['osclass']:
				print(f"Os-type :",{j['type']})
				print(f"Vendor :",{j['vendor']})
	except:
		print("Use root priviliege")

def aggressive_scan():
	nm = nmap.PortScanner()
	ip = input("\tEnter the IP")
	print("Wait.......")
	try:
		scan = nm.scan(hosts=ip,arguments = "-sS -O -Pn -T4")
		for i in scan["scan"][ip]['osmatch']:
			print("______________Agressive Scan_____________")
			print(f"Name : {i['name']}")
			print(f"Accuracy : {i['accuracy']}")
			for j in i['osclass']:
				print(f"Os-type :,{j['type']}")
				print(f"Vendor :,{j['vendor']}")
		
	except:
		print("Use root priviliege")
	

def arp_packet():
		nm = nmap.PortScanner()
		ip = input("\tEnter the IP")
		print("wait......")
		try:
			scan = nm.scan(hosts=ip,arguments = "-sS -O -PR")
			for i in scan["scan"][ip]['osmatch']:
				print("_____________ARP Packet______________")
				print(f"Name : {i['name']}")
				print(f"Accuracy : {i['accuracy']}")
		except:
			print("Use root privilige")

def scan_all_ports():
		nm = nmap.PortScanner()
		ip = input("\tEnter the IP")
		print("wait......")
		try:
			scan = nm.scan(hosts=ip,ports="1-4",arguments="-sS -O -Pn")
			for host in scan["scan"][ip]['tcp'].items():
				print("____________Port Details_____________")
				print("Tcp Port :",host[0])
				print("State :",host[1]['state'])
				print("Reason :",host[1]['reason'])
				print("Name :",host[1]['name'])
			
		except:
			print("Use root privilige")
	
def verbose_scan():
		nm = nmap.PortScanner()
		ip = input("\tEnter the IP")
		print("Wait...........")
		try:
			scan = nm.scan(hosts = ip,arguments = "-sS -O -Pn -v")
			for i in scan["scan"][ip]["osmatch"]:
				print("____________Verbose Scan_____________")
				print(f"Name : {i['name']}")
				print(f"Accuracy : {i['accuracy']}")
				for j in i["osclass"]:
					print(f"Os-type : {j['type']}")		
		except:
			print("Use root priviliege")
