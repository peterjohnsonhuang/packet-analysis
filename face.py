import re
import zlib
import cv2
import os

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

def face_detect(path,file_name,pcap_file):

	try:        
		img     = cv2.imread(path)
        	cascade = cv2.CascadeClassifier("haarcascade_frontalface_alt.xml")
        	rects   = cascade.detectMultiScale(img, 1.3, 4, cv2.cv.CV_HAAR_SCALE_IMAGE, (20,20))
        
		if len(rects) == 0:
 	               return False
        		
        	rects[:, 2:] += rects[:, :2]

		# highlight the faces in the image        
		for x1,y1,x2,y2 in rects:
			cv2.rectangle(img,(x1,y1),(x2,y2),(127,255,0),2)
	
		faces_directory = "%s/face"%pcap_file.split(".")[0]
		if not os.path.isdir(faces_directory):
        		os.mkdir(faces_directory)
		cv2.imwrite("%s/%s" % (faces_directory,file_name),img)

       	 	return True
	except:
		return False

def extract_image(headers,http_payload):
	
	data      = None
	data_type = None
	data_category=None
	
	try:
		if "image" in headers['Content-Type']:

			# grab the image type and image body
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

def http_assembler_face(pcap_file , image_list,f):

	carved_images   = 0
	captured_image = {}
	payload_list = []
	data_list = []
	try:
		a = rdpcap(pcap_file)
	except:
		print("> File doesn't exist !!")
		return 0
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
	
		split_payload(http_payload,payload_list)
		#payload_list.append(http_payload)
		for payload in payload_list:		
			headers = get_http_headers(payload)
		
			if headers is None:
				continue
	
			data,data_type,data_category = extract_image(headers,payload)
			
		
			if data is not None and data_type is not None and data not in data_list:				
			
				# store the image
				data_list.append(data)
				if (data_type not in captured_image):
					captured_image[data_type] = 1;			
				else:
					captured_image[data_type] += 1 
				file_name = "%s-%s%d.%s" % (pcap_file.split(".")[0],data_type,captured_image[data_type],data_type)
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
				image_list.append((data_type,file_name))
				carved_images += 1
		
	return carved_images,captured_image

def get_face(image_list,pcap_file):
	faces_detected = 0
	for file_name in image_list:
		# now attempt face detection
		try:	
			if (file_name[0]!= "gif" and file_name[0]!= "x-icon"):
				pictures_directory = "%s/image/%s"%(pcap_file.split(".")[0],file_name[0])
 				result = face_detect("%s/%s" % (pictures_directory,file_name[1]),file_name[1],pcap_file)
				
				if result is True:
					faces_detected += 1
		except:
			pass
	return faces_detected













