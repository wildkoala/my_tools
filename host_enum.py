
'''
DISCLAIMER:
THIS SCRIPT IS NOT MEANT TO BE THE ONLY ENUMERATION DONE ON A HOST
IT IS MEANT TO GIVE YOU AN INITIAL UNDERSTANDING OF THE SYSTEM, AND DOES
NOT REPLACE A CLOSE, IN-DEPTH SEARCH OF THE MACHINE.

Purpose:
 The purpose of this script is to allow faster and more complete
 INITIAL host enumeration. If you have any ideas on how to improve this
 code, please let me know - wildkoala


 IDEAS FOR IMPROVEMENT:
 1. Write all of this to a file for human readability
 2. Fix output of neighbors 
 3. By default, show everything, but give options for showing
    less than that.
'''

import subprocess
import re
import ipaddress
import nmap

# displays user and their shell right now
# should this be more verbose?
# should i cut out certain default, uninteresting users?
def read_etc_passwd():
	pswd = open("/etc/passwd", "r")
	print("[+] /etc/passwd")
	for aLine in pswd:
		fields= aLine.split( ":" )
		print("   [-] " + fields[0] + ":" + fields[-1].strip())
	pswd.close()

def read_etc_hosts():
	hosts = open("/etc/hosts", "r")
	print("[+] /etc/hosts")
	for l in hosts:
		print("   [-] " + l.strip())
	hosts.close()


def get_neighbors():
	# ip neighbors

	print("[+] ip neighbor")
	output = subprocess.check_output(["ip", "neighbor"])
	lines = output.decode().strip().split("\n")
	for l in lines:
		if "FAILED" in l:
			pass
		elif "STALE" in l:
			pass
		else:
			print("   [-] " + l)
	

	# arp -a
	print("[+] arp -a")
	output = subprocess.check_output(["arp", "-a"])
	lines = output.decode().strip().split("\n")
	for l in lines:
		if "incomplete" in l:
			pass
		elif "?" in l:
			pass
		else:
			print("   [-] " + l)

	# should i make this do an nmap scan from here?
	# really I should use ip ad and do a ping sweep

# this only works on /24 networks and smaller
def list_ips():
	output = subprocess.check_output(["ip", "addr"])
	output = output.decode().strip()
	ips = re.findall( r'[0-9]+(?:\.[0-9]+){3}/[0-9]{2}', output )
	print("[+] ip addresses")
	for ip in ips:
		print("   [-] " + ip)
		print("       [*] Scan this net with the following command:")
		#I need this to get the correct start, stop and end
		net = ipaddress.ip_network(ip, strict=False)
		first_host = (net.network_address + 1).exploded.split(".")[-1]
		last_host = (net.broadcast_address - 1).exploded.split(".")[-1]
		network_bits = re.findall( r'[0-9]+\.[0-9]+\.[0-9]+\.', (net.broadcast_address - 1).exploded)[0]
		print("          for i in {}..{} ;do (ping -c 1 {}$i | grep \"bytes from\" &) ;done".format(first_host, last_host, network_bits))


def whoami():
	output = (subprocess.check_output(["whoami"]))
	print("[+] whoami")
	print("   [-] " + output.decode().strip())


def hostname():
	output = subprocess.check_output(["hostname"])
	print("[+] hostname")
	print("   [-] " + output.decode().strip())

def ip_route():
	print("[+] ip route")
	output = subprocess.check_output(["ip", "route"])
	lines = output.decode().strip().split("\n")
	for l in lines:
		if "incomplete" in l:
			pass
		else:
			print("   [-] " + l)

# make output pretty without dirtying up the code...
# something like this, needs work though.
def format_output(data, indent_lvl):
	if indent_lvl == 1:
		print("[+] " + data)
	else:
		print("   " * indent_lvl + "[-] ", end="")
		print(data)


if __name__ == "__main__":

	#'''	
	whoami()
	hostname()
	list_ips()

	ip_route()
	get_neighbors()

	read_etc_passwd()
	read_etc_hosts()
	
	
	#'''
	#list_ips()