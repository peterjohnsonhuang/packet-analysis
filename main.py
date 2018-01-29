import re
import zlib
import cv2
from face import http_assembler_face,get_face
from text import http_assembler_text
from application import http_assembler_application,find_password
from auto import http_assembler_auto

from scapy.all import *

pictures_directory = "/home/yutungliu/final/pictures"
faces_directory    = "/home/yutungliu/final/faces"


def multi(mode , pcap_file):
	image_list = []
	carved_images = 0
	faces_detected = 0
	captured_image = {}
	captured_text = {}
	captured_app = {}
	captured_data = {}
	host_list = []
	password_list = []
	f = 0
	if (mode == "1"):
		captured_data = http_assembler_auto(pcap_file,host_list)
		f = 1
		host_set = set(host_list)
		next = raw_input("Input 1 to list all data types , 2 to list all hosts , 3 to do both , 4 to leave auto mode: ")
		while (next not in ["1","2","3","4"]):
			next = raw_input("Illegal input !! Please input again (1.list data types  2.list all hosts  3.do both  4.exit): ")
		if (next == "1"):
			for i in list(captured_data.keys()):
				print ("> %s:"%i)
				for j in list(captured_data[i].keys()):
					print ("    > %s: %d"%(j,captured_data[i][j]))
			print ""

		if (next == "2"):
			print ("> There are total %d hosts."%len(host_set))
			for h in host_set:
				print ("  > %s"%h)
			print ""

		if (next == "3"):
			print ("> Listing all data types:")
			for i in list(captured_data.keys()):
				print ("  > %s:"%i)
				for j in list(captured_data[i].keys()):
					print ("      > %s: %d"%(j,captured_data[i][j]))
			print ("\n> Listing all hosts")
			print ("  > There are total %d hosts."%len(host_set))
			for h in host_set:
				print ("   > %s"%h)
			print ""

		if (next == "4"):
			next1 = raw_input("Please choose what to do next (1.image  2.text  3.application  4.exit): ")
			while (next1 not in ["1","2","3","4"]):
				next1 = raw_input("Illegal input !! Please input again (1.image  2.text  3.application  4.exit): ")
			if (next1 == "1"):
				multi("2",pcap_file)
			elif (next1 == "2"):
				multi("3",pcap_file)
			elif (next1 == "3"):
				multi("4",pcap_file)
			else:
				return

		next2 = raw_input("Please choose what to do next (1.image  2.text  3.application  4.exit): ")
		while (next2 not in ["1","2","3","4"]):
			next2 = raw_input("Illegal input !! Please input again (1.image  2.text  3.application  4.exit): ")
		if (next2 == "1"):
			multi("2",pcap_file)
		elif (next2 == "2"):
			multi("3",pcap_file)
		elif (next2 == "3"):
			multi("4",pcap_file)
		else:
			return
		return 

		
	if (mode == "2"):
		carved_images,captured_image = http_assembler_face(pcap_file,image_list,f)
		if (carved_images == 0):
			print ("> No image is extracted.\n")
		else:
			print ("> Extracted: " + str(carved_images) + " images.")
			for i in list(captured_image.keys()):
				print ("  > %s: %d"%(i,captured_image[i]))
			print ""
			face_detect = raw_input("Input 1 to do face detect , others to leave this mode: ")
			if (face_detect == "1"):
				faces_detected = get_face(image_list,pcap_file)
				if (faces_detected == 0):
					print("> No face is detected.")
				else:
					print ("> Detected: " + str(faces_detected) + " faces")
				print ""
			
		next = raw_input("Please choose what to do next (1.auto  2.text  3.application  4.exit): ")
		while (next not in ["1","2","3","4"]):
			next = raw_input("Illegal input !! Please input again (1.auto  2.text  3.application  4.exit): ")
		if (next == "1"):
			multi("1",pcap_file)
		elif (next == "2"):
			multi("3",pcap_file)
		elif (next == "3"):
			multi("4",pcap_file)
		else:
			return
		return 
	if (mode == "3"):
		captured_text = http_assembler_text(pcap_file,f)
		for i in list(captured_text.keys()):
			print ("> %s: %d"%(i,captured_text[i]))
		print ""	
		next = raw_input("Please choose what to do next (1.auto  2.image  3.application  4.exit): ")
		while (next not in ["1","2","3","4"]):
			next = raw_input("Illegal input !! Please input again (1.auto  2.image  3.application  4.exit): ")
		if (next == "1"):
			multi("1",pcap_file)
		elif (next == "2"):
			multi("2",pcap_file)
		elif (next == "3"):
			multi("4",pcap_file)
		else:
			return
		return 

	if (mode == "4"):
		captured_app = http_assembler_application(pcap_file,f)
		for i in list(captured_app.keys()):
			print ("> %s: %d"%(i,captured_app[i]))	
		print ""
		pwd = raw_input("Input 1 to detect password, others to leave this mode: ")
		if (pwd == "1"):
			find_password(pcap_file,password_list)
			if (len(password_list) == 0):
				print ("No password detected.")
			else:
				for line in password_list:
					print ("> %s"%line)
		next = raw_input("Please choose what to do next (1.auto  2.image  3.text  4.exit): ")
		while (next not in ["1","2","3","4"]):
			next = raw_input("Illegal input !! Please input again (1.auto  2.image  3.text  4.exit): ")
		if (next == "1"):
			multi("1",pcap_file)
		elif (next == "2"):
			multi("2",pcap_file)
		elif (next == "3"):
			multi("3",pcap_file)
		else:
			return
		return 


def main():
	pcap_file = raw_input("Please input the pcap file's name: ")
	print ("")
	mode = raw_input("Please choose a type to detect (1.auto  2.image  3.text  4. application): ")
	multi(mode , pcap_file)
	next = raw_input("Please choose what to do next (1.read another pcap file  2.exit): ")
	print ("")
	while(next != "1" and next != "2"):
		next = raw_input("Illegal input !! Please input again (1.read another pcap file  2.exit): ")
		print ("")
		
	if (next == "1"):
		main()
		return

	elif (next == "2"):
		print ("> See you next time !!")
		return 
	
main()
		
