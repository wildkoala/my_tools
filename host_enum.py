
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
import paramiko

# displays user and their shell right now
# should this be more verbose?
# should i cut out certain default, uninteresting users?

# I want this to work over an ssh connection so that I use it with proxychains.


def read_etc_passwd(lines):
	for l in lines:
		fields= l.split( ":" )
		print("   [-] " + fields[0] + ":" + fields[-1].strip())
	

def read_etc_hosts(lines):
	for l in lines:
		print("   [-] " + l.strip())
	


def ip_neighbors(lines):
	for l in lines:
		if "FAILED" in l:
			pass
		elif "STALE" in l:
			pass
		else:
			print("   [-] " + l)
	


def arp(lines):
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
def ip_addr(lines):
	line = "".join(lines)
	output = line.strip()
	ips = re.findall( r'[0-9]+(?:\.[0-9]+){3}/[0-9]{2}', output )
	for ip in ips:
		print("   [-] " + ip)
		print("       [*] Scan this net with the following command:")
		#I need this to get the correct start, stop and end
		net = ipaddress.ip_network(ip, strict=False)
		first_host = (net.network_address + 1).exploded.split(".")[-1]
		last_host = (net.broadcast_address - 1).exploded.split(".")[-1]
		network_bits = re.findall( r'[0-9]+\.[0-9]+\.[0-9]+\.', (net.broadcast_address - 1).exploded)[0]
		print("          for i in {}..{} ;do (ping -c 1 {}$i | grep \"bytes from\" &) ;done".format(first_host, last_host, network_bits))


def whoami(lines):
	for l in lines:
		print("   [-] " + l.strip())


def hostname(lines):
	for l in lines:
		print("   [-] " + l.strip())

def ip_route(lines):
	for l in lines:
		if "incomplete" in l:
			pass
		else:
			print("   [-] " + l.strip())

# make output pretty without dirtying up the code...
# something like this, needs work though.
'''
def format_output(data, indent_lvl):
	if indent_lvl == 1:
		print("[+] " + data)
	else:
		print("   " * indent_lvl + "[-] ", end="")
		print(data)
'''

if __name__ == "__main__":

		
	host = input("Please provide the IP of the host to enumerate:\n> ")
	port = input("Please provide the port SSH is running on:\n> ")
	username = input("Please provide the user to authenticate as:\n> ")
	password = input("Please provide the password for that user:\n> ")

	
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(host,port,username,password)


	cmds = ["whoami", "hostname", "ip addr", "ip neighbors", "ip route", "arp -a", "cat /etc/passwd", "cat /etc/hosts"]


	for cmd in cmds:
		stdin, stdout, stderr = ssh.exec_command(cmd)
		print("[+] " + cmd)
		lines = stdout.readlines()
		if cmd == "whoami":
			whoami(lines)
		elif cmd == "hostname":
			hostname(lines)
		elif cmd == "ip neighbors":
			ip_neighbors(lines)
		elif cmd == "ip addr":
			ip_addr(lines)
		elif cmd == "ip route":
			ip_route(lines)
		elif cmd == "arp -a":
			arp(lines)
		elif cmd == "cat /etc/passwd":
			read_etc_passwd(lines)
		elif cmd == "cat /etc/hosts":
			read_etc_passwd(lines)


	'''
	whoami()
	hostname()
	list_ips()

	ip_route()
	get_neighbors()

	read_etc_passwd()
	read_etc_hosts()
	
	
	'''
	#list_ips()