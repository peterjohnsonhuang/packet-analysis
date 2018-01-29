import re
import zlib

from scapy.all import *


def get_http_headers(http_payload):
	try:
		# split the headers off if it is HTTP traffic
		headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
	
		# break out the headers
		headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers_raw))
	except:
		return None

	if "Content-Type" not in headers:
		return None
	
	return headers

def split_payload(http_payload,payload_list):
	i = 1
	f1 = f2 = f3 = 0
	while (True):
		try:
			i_http = http_payload.index("HTTP/1.1 ",i)
		
		except:
			f1 = 1
			i_http = 100000000000
		try:
			i_get = http_payload.index("GET /",i)
			
		except:
			f2 = 1
			i_get = 100000000000
		try:
			i_post = http_payload.index("POST /",i)
		
		except:
			f3 = 1
			i_post = 100000000000
		if (f1 == f2 == f3 == 1):
			payload = http_payload[i-1:]
			payload_list.append(payload)
			break
		payload = http_payload[i-1:min(i_http,i_get,i_post)]
	
		payload_list.append(payload)
		i = min(i_http,i_get,i_post)+1
		f1 = f2 = f3 = 0
		
def extract_data(headers,http_payload):
	
	data      = None
	data_type = None
	data_category=None
	try:
		if "application" in headers['Content-Type']:

			# grab the data type and data body
			data_category=headers['Content-Type'].split("/")[0]
			data_type = headers['Content-Type'].split("/")[1]
		
			data = http_payload[http_payload.index("\r\n\r\n")+4:]
			if ';' in data_type:
                                data_coding=data_type.split(';')[1]
                                data_type=data_type.split(';')[0]
                        
                            
		
			# if we detect compression decompress the data
			try:
				if "Content-Encoding" in headers.keys():
					if headers['Content-Encoding'] == "gzip":
						data = zlib.decompress(data,16+zlib.MAX_WBITS)
					elif headers['Content-Encoding'] == "deflate":
						data = zlib.decompress(data)
			except:
				pass	
	except:
		return None,None,None
	
	return data,data_type,data_category

def http_assembler_application(pcap_file,f):

	captured_data = {}
	payload_list = []	
	data_list = []
	try:
		a = rdpcap(pcap_file)
	except:
		print("> File doesn't exist!!!")
		return {}

	sessions      = a.sessions()	

	for session in sessions:

		http_payload = ""
		
		for packet in sessions[session]:
	
			try:
				if packet[TCP].dport == 80 or packet[TCP].sport == 80:
	
					# reassemble the stream into a single buffer
					http_payload += str(packet[TCP].payload)
	
			except:
				pass
		#print http_payload
		split_payload(http_payload,payload_list)
		for payload in payload_list:
			headers = get_http_headers(payload)
		
			if headers is None:
				continue
	
			data,data_type,data_category = extract_data(headers,payload)
	
			if data is not None and data_type is not None and data not in data_list:				
		
				# store the data
				data_list.append(data)
				if (data_type not in captured_data):
					captured_data[data_type] = 1;			
				else:
					captured_data[data_type] += 1 
				file_name = "%s-%s%d.%s" % (pcap_file.split(".")[0],data_type,captured_data[data_type],data_type)
				if not os.path.isdir("%s" % pcap_file.split(".")[0]):
                	                os.mkdir("%s" % pcap_file.split(".")[0])
				if not os.path.isdir("%s/%s" % (pcap_file.split(".")[0],data_category)):
                	                os.mkdir("%s/%s" % (pcap_file.split(".")[0],data_category))
				if not os.path.isdir("%s/%s/%s" % (pcap_file.split(".")[0],data_category,data_type)):
                	                os.mkdir("%s/%s/%s" % (pcap_file.split(".")[0],data_category,data_type))
				if (f == 0):
					fd = open("%s/%s/%s/%s" % (pcap_file.split(".")[0],data_category,data_type,file_name),"wb")				
					fd.write(data)
					fd.close()
			
					
	return captured_data

def find_password(pcap_file,password_list):
	if not os.path.isdir("%s/application/x-www-form-urlencoded"%pcap_file.split(".")[0]):
		return 
	file_list = os.listdir("%s/application/x-www-form-urlencoded"%pcap_file.split(".")[0])
	for file_name in file_list:
		f = open("%s/application/x-www-form-urlencoded/%s"%(pcap_file.split(".")[0],file_name),"r")
		for line in f:
			if ("password" in line or "pwd" in line or "Password" in line or "PWD" in line):
				password_list.append(line)
				break
		f.close()
		
