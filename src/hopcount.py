import ipconversions
from socket import *
from time import time

def guess_hopcount(ip, port = [53,80,443], protocol = ['icmp','udp','tcp']):
	"""
	guessing the hopcount to ip. this function tries all protocols and ip versions.
	"""
	v = None
	if ipconversions.is_valid_ipv4(ip):
		version = 4
	elif ipconversions.is_valid_ipv6(ip):
		version = 6
	for p in protocol:
		# send packet
		send_probes(ip,version,p,port)
		# guess hopcount
		# if reasonable: return result

def send_probes(ip, version, protocol, port = [53, 80,443], count = 5):
	if version == 4:
		send_probes_ipv4(ip, protocol, port, count)
	elif version ==6:
		send_probes_ipv6(ip, protocol, port, count)
	else:
		return None

def send_probes_ipv4(ip, protocol, port = [53, 80,443], count = 5):
	print("send %s probes to %s via %s" % (count,ip,protocol))
	result = {}
	ptype = socket.getprotobyname(protocol)
	try:
     	my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ptype)
     except socket.error, (errno, msg):
      if errno == 1:
      # Operation not permitted
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )
            raise socket.error(msg)
        raise # raise the original error
	if protocol == "icmp":
		for s in range(count):
      		# get a socket
      		sckt
      		result[s] = send_probe_icmp_v4(sckt, ip, s)
	else:
		for p in port:
			for s in range(count):
				if protocol == 'udp':
					result[s] = send_probe_udp_v4(ip, p, s)
				else:
					result[s] = send_probe_tcp_v4(ip, p, s)
				# calculate hopcount
				result[s]['hops'] = TTL2hopcount(result[s]['TTL'])
			print(result)
			# TODO check results and return if result available
			res = calculate_timings([result[i]['RTT'] for i in result])
			res['hopcount'] = estimate_hopcount([result[i]['hops'] for i in result] )
			res['src'] = get_source([result[i]['source'] for i in result])
			print res
			return res

def send_probes_ipv6(ip, protocol, port = [80,443], count = 5):
	print("send %s probes to %s via %s" % (count,ip,protocol))
	pass

def send_probe_icmp_v4(sckt, ip, seq = 0):
		
		# get time
		t1 = time()
		# send a packet
		# get reply
		# get time
		t2 = time()
		return {'TTL':239, 'source':'123', 'RTT': t2-t1}

def send_probe_udp_v4(ip, port = 53, seq = 0):
		
		# get time
		t1 = time()
		# send a packet
		# get reply
		# get time
		t2 = time()
		return {'TTL':239, 'source':'123', 'RTT': t2-t1}

def send_probe_tcp_v4(ip, port = 80, seq = 0):
		# get time
		t1 = time()
		# send a packet
		# get reply
		# get time
		t2 = time()
		return {'TTL':239, 'source':'123', 'RTT': t2-t1}

def TTL2hopcount(ttl):
	if ttl > 128:
		return 254 - ttl
	elif ttl > 64:
		return 127 - ttl
	else:
		return 63 -ttl

def estimate_hopcount(hopcounts):
	""" for now we take the highest hopcount we got """
	return max(hopcounts)

def calculate_timings(rtts):
	return {}

def get_source(sources):
	pass