#!/usr/bin/env python3


def scan_target(target,Args):
	if target == None or Args == None:
		print("invalid arguments exiting...")
		sys.exit(1)
	try:
		nm=nmap.PortScanner()
		print(f"\n\n[+]~⟩scanning {target} with args {Args} ...")
		nm.scan(target,arguments=Args)
		print_All_Host(nm)
	except Exception as e:
		print(f"Error:{e}")

def print_All_Host(nm):
	print("\n")
	print("found hosts:")
	for host in nm.all_hosts():
		print('--------------------------------------------------')
		print('Host : %s (%s)' % (host, nm[host].hostname()))
		print('State : %s' % nm[host].state())
		for proto in nm[host].all_protocols():
			print('----------')
			print('Protocol : %s' % proto)
			lport = nm[host][proto].keys()
			for port in lport:
				print ('port : %s\tstate : %s' % (port, 		nm[host][proto][port]['state']))
				print("__________________________________________________")


if __name__ == "__main__":
	import argparse
	import nmap
	import sys
	object=argparse.ArgumentParser(description="python scanning script")
	object.add_argument("-t","--target",help="type -i|--ip <ip_address>")
	object.add_argument("-a","--Args",help="'-sn','-O',etc",default="-sn")
	args=object.parse_args()
	target=args.target
	Args=args.Args
	scan_target(target,Args)
