import argparse
from scapy.all import *
import sys
import datetime
cachedPackets = {}


def displayDetails(packet, packetId, IPlist):
	print(datetime.datetime.fromtimestamp(packet.time).strftime('%Y%m%d-%H:%M:%S.%f'), "DNS poisoning attempt")
	print('TXID', hex(packet[DNS].id), 'Request', packet[DNS].qd.qname.decode('ASCII'))
        print('Answer1:', cachedPackets[packetId][0])
	print('Answer2:', IPlist)
	print('MAC 1:', cachedPackets[packetId][1])
	print('MAC 2', packet.src)
	print('TTL 1:', cachedPackets[packetId][2])
	print('TTL 2', packet[IP].ttl)

def validateIP(ip):
	split = ip.split('.')
    	if len(split) != 4:
		return False
	for element in split:
		if not element.isdigit():
			return False
		i = int(element)
		if i < 0 or i > 255:
			 return False
	return True

def startDetecting(packet):
	global cachedPackets
	if IP in packet and DNS in packet and packet[DNS].ancount >= 1 :
		DNSpacket = packet[DNS]
		packetId = DNSpacket.id
		currentIPs = []
		for i in range(DNSpacket.ancount) :
			if validateIP(DNSpacket.an[i].rdata) is True:
				currentIPs.append(DNSpacket.an[i].rdata)
		if cachedPackets.get(packetId) is not None:
			cachedIPs = cachedPackets.get(packetId)[0]
			intersection = set(currentIPs).intersection(cachedIPs)
			if len(intersection) is not 0:
                		cachedPackets[packetId][0] = list(set(currentIPs).union(cachedIPs))
			elif len(intersection) == 0:
                		if (cachedPackets[packetId][1] is not packet.src) or (cachedPackets[packetId][2] is not packet[IP].ttl):
					if len(cachedIPs) is not 0:
						displayDetails(packet, packetId, currentIPs)
				else:	
					print ("Not an ATTACK")
		else :	
			cachedPackets[packetId] = [currentIPs, packet.src, packet[IP].ttl]
			print ("Not an ATTACK")
	


def getArgs():
	parser = argparse.ArgumentParser(description='Get Input Arguments', conflict_handler='resolve')
	parser.add_argument("-i")
	parser.add_argument("-r")
	parser.add_argument("exp", nargs='*', action="store")	
	args = parser.parse_args()
	return args

if __name__ == '__main__':
	global interfaceFlag, traceFlag, expFlag, traceFile, expression
	bpf = ""
	interfaceFlag = False
	traceFlag = False
	expFlag = False
	args = getArgs()
	interface = "eth0"
	if args.i:
		interfaceFlag = True
		interface = args.i
	if args.r:
		traceFlag = True
		traceFile = args.r
	if args.exp:
		expFlag = True
		expression = args.exp
		bpf = bpf.join(expression).strip()
	if traceFlag:
		sniff(offline = traceFile, store = 0, prn = startDetecting)
	elif interfaceFlag:
		sniff(filter = bpf, iface=interface, store=0, prn=startDetecting)
	else:
		sniff(filter = bpf, store=0, prn=startDetecting)
