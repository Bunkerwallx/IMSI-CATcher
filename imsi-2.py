#!/usr/bin/python

import sys
orig_stdout = sys.stdout
from scapy.all import sniff
import json
from optparse import OptionParser

import time

imsis=[] 
tmsis={} 
nb_IMSI=0
mcc=""
mnc=""
lac=""
cell=""
country=""
brand=""
operator=""


def str_tmsi(tmsi):
	if tmsi != "":
		new_tmsi="0x"
		for a in tmsi:
			c=hex(ord(a))
			if len(c)==4:
				new_tmsi+=str(c[2])+str(c[3])
			else:
				new_tmsi+="0"+str(c[2])
		return new_tmsi
	else:
		return ""

def str_imsi(imsi, p=""):
	new_imsi=''
	for a in imsi:
		c=hex(ord(a))
		if len(c)==4:
			new_imsi+=str(c[3])+str(c[2])
		else:
			new_imsi+=str(c[2])+"0"
	
	mcc=new_imsi[1:4]
	mnc=new_imsi[4:6]
	country=""
	brand=""
	operator=""
	if mcc in mcc_codes:
		if mnc in mcc_codes[mcc]['MNC']:
			country=mcc_codes[mcc]['c'][0]
			brand=mcc_codes[mcc]['MNC'][mnc][0]
			operator=mcc_codes[mcc]['MNC'][mnc][1]
			new_imsi=mcc+" "+mnc+" "+new_imsi[6:]
		elif mnc+new_imsi[6:7] in mcc_codes[mcc]['MNC']:
			mnc+=new_imsi[6:7]
			country=mcc_codes[mcc]['c'][0]
			brand=mcc_codes[mcc]['MNC'][mnc][0]
			operator=mcc_codes[mcc]['MNC'][mnc][1]
			new_imsi=mcc+" "+mnc+" "+new_imsi[7:]
		else:
			country=mcc_codes[mcc]['c'][0]
			brand="Unknown MNC {}".format(mnc)
			operator="Unknown MNC {}".format(mnc)
			new_imsi=mcc+" "+mnc+" "+new_imsi[6:]

	try:
		m="{:17s} ; {:12s} ; {:10s} ; {:21s}".format(new_imsi, country.encode('utf-8'), brand.encode('utf-8'), operator.encode('utf-8'))
	except:
		m=""
		print("Error", p, new_imsi, country, brand, operator)
	return m


def show_imsi(imsi1="", imsi2="", tmsi1="", tmsi2="", p=""):
	
	global imsis
	global tmsis
	global nb_IMSI
	global mcc
	global mnc
	global lac
	global cell

	do_print=False
	n=''
	if imsi1 and (not imsi_to_track or imsi1[:imsi_to_track_len] == imsi_to_track):
		if imsi1 not in imsis:
			do_print=True
			imsis.append(imsi1)
			nb_IMSI+=1
			n=nb_IMSI
		if tmsi1 and (tmsi1 not in tmsis or tmsis[tmsi1] != imsi1):
			do_print=True
			tmsis[tmsi1]=imsi1
		if tmsi2 and (tmsi2 not in tmsis or tmsis[tmsi2] != imsi1):
			do_print=True
			tmsis[tmsi2]=imsi1		
	
	if imsi2 and (not imsi_to_track or imsi2[:imsi_to_track_len] == imsi_to_track):
		if imsi2 not in imsis:
			do_print=True
			imsis.append(imsi2)
			nb_IMSI+=1
			n=nb_IMSI
		if tmsi1 and (tmsi1 not in tmsis or tmsis[tmsi1] != imsi2):
			do_print=True
			tmsis[tmsi1]=imsi2
		if tmsi2 and (tmsi2 not in tmsis or tmsis[tmsi2] != imsi2):
			do_print=True
			tmsis[tmsi2]=imsi2

	if not imsi1 and not imsi2 and tmsi1 and tmsi2:
		if tmsi2 in tmsis:
			do_print=True
			imsi1=tmsis[tmsi2]
			tmsis[tmsi1]=imsi1
			del tmsis[tmsi2]

	if do_print:
		if imsi1:
			sys.stdout.write("{:7s} ; {:10s} ; {:10s} ; {} ; {:4s} ; {:5s} ; {:6s} ; {:6s}\n".format(str(n), str_tmsi(tmsi1), str_tmsi(tmsi2), str_imsi(imsi1, p), str(mcc), str(mnc), str(lac), str(cell)))
			sys.stdout.flush()
		if imsi2:
			sys.stdout.write("{:7s} ; {:10s} ; {:10s} ; {} ; {:4s} ; {:5s} ; {:6s} ; {:6s}\n".format(str(n), str_tmsi(tmsi1), str_tmsi(tmsi2), str_imsi(imsi1, p), str(mcc), str(mnc), str(lac), str(cell)))
			sys.stdout.flush()
			#print("{:7s} ; {:10s} ; {:10s} ; {} ; {:4s} ; {:5s} ; {:6s} ; {:6s}".format(str(n), str_tmsi(tmsi1), str_tmsi(tmsi2), str_imsi(imsi2, p), str(mcc), str(mnc), str(lac), str(cell)))

	if not imsi1 and not imsi2 and show_all_tmsi:
		do_print=False
		if tmsi1 and tmsi1 not in tmsis:
			do_print=True
			tmsis[tmsi1]=""
		if tmsi1 and tmsi1 not in tmsis:
			do_print=True
			tmsis[tmsi2]=""
		if do_print:			
			#sys.stdout.write("{:7s} ; {:10s} ; {:10s} ; {} ; {:4s} ; {:5s} ; {:6s} ; {:6s}\n".format(str(n), str_tmsi(tmsi1), str_tmsi(tmsi2), str_imsi(imsi1, p), str(mcc), str(mnc), str(lac), str(cell)))
			sys.stdout.flush()
			#print("{:7s} ; {:10s} ; {:10s} ; {:17s} ; {:12s} ; {:10s} ; {:21s} ; {:4s} ; {:5s} ; {:6s} ; {:6s}\n".format(str(n), str_tmsi(tmsi1), str_tmsi(tmsi2), "", "", "", "", str(mcc), str(mnc), str(lac), str(cell)))


def find_cell(x):
	global mcc
	global mnc
	global lac
	global cell
	global country
	global brand
	global operator

	"""
			0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
	0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
	0010   00 43 9a 6b 40 00 40 11 a2 3c 7f 00 00 01 7f 00
	0020   00 01 ed d1 12 79 00 2f fe 42 02 04 01 00 00 00
	0030   cc 00 00 07 9b 2c 01 00 00 00 49 06 1b 61 9d 02
	0040   f8 02 01 9c c8 03 1e 53 a5 07 79 00 00 80 01 40
	0050   db

	Channel Type: BCCH (1)
	                          6
	0030                     01

	Message Type: System Information Type 3
		                                        c
	0030                                       1b

	Cell CI: 0x619d (24989)
		                                           d  e
	0030                                          61 9d

	Location Area Identification (LAI) - 208/20/412
	Mobile Country Code (MCC): France (208)	0x02f8
	Mobile Network Code (MNC): Bouygues Telecom (20) 0xf802
	Location Area Code (LAC): 0x019c (412)
			0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
	0030                                                02 
	0040   f8 02 01 9c
	"""
	p=str(x)
	if ord(p[0x36]) == 0x01: 
		if ord(p[0x3c]) == 0x1b: 
			m=hex(ord(p[0x3f]))
			if len(m)<4:
				mcc=m[2]+'0'
			else:
				mcc=m[3]+m[2]
			mcc+=str(ord(p[0x40]) & 0x0f)
			m=hex(ord(p[0x41]))
			if len(m)<4:
				mnc=m[2]+'0'
			else:
				mnc=m[3]+m[2]

			lac=ord(p[0x42])*256+ord(p[0x43])
			cell=ord(p[0x3d])*256+ord(p[0x3e])
			brand=""
			operator=""
			if mcc in mcc_codes:
				if mnc in mcc_codes[mcc]['MNC']:
					country=mcc_codes[mcc]['c'][0]
					brand=mcc_codes[mcc]['MNC'][mnc][0]
					operator=mcc_codes[mcc]['MNC'][mnc][1]
				else:
					country=mcc_codes[mcc]['c'][0]
					brand="Unknown MNC {}".format(mnc)
					operator="Unknown MNC {}".format(mnc)
			else:
				country="Unknown MCC {}".format(mcc)
				brand="Unknown MNC {}".format(mnc)
				operator="Unknown MNC {}".format(mnc)
			mcc=str(mcc)
			mnc=str(mnc)
			lac=str(lac)
			cell=str(cell)
			country=country.encode('utf-8')
			brand=brand.encode('utf-8')
			operator= operator.encode('utf-8')
			return mcc, mnc, lac, cell, country, brand, operator
	return None, None, None, None, None, None, None


def find_imsi(x):
	find_cell(x)
	p=str(x)
	if ord(p[0x36]) != 0x1:
		tmsi1=""
		tmsi2=""
		imsi1=""
		imsi2=""
		if ord(p[0x3c]) == 0x21: 
			if ord(p[0x3e]) == 0x08 and (ord(p[0x3f]) & 0x1) == 0x1: 
				"""
				        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
				0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
				0010   00 43 1c d4 40 00 40 11 1f d4 7f 00 00 01 7f 00
				0020   00 01 c2 e4 12 79 00 2f fe 42 02 04 01 00 00 00
				0030   c9 00 00 16 21 26 02 00 07 00 31 06 21 00 08 XX
				0040   XX XX XX XX XX XX XX 2b 2b 2b 2b 2b 2b 2b 2b 2b
				0050   2b
				XX XX XX XX XX XX XX XX = IMSI
				"""
				imsi1=p[0x3f:][:8]
				if ord(p[0x3a]) == 0x59 and ord(p[0x48]) == 0x08 and (ord(p[0x49]) & 0x1) == 0x1:
					"""
				        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
				0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
				0010   00 43 90 95 40 00 40 11 ac 12 7f 00 00 01 7f 00
				0020   00 01 b4 1c 12 79 00 2f fe 42 02 04 01 00 00 00
				0030   c8 00 00 16 51 c6 02 00 08 00 59 06 21 00 08 YY
				0040   YY YY YY YY YY YY YY 17 08 XX XX XX XX XX XX XX
				0050   XX
				YY YY YY YY YY YY YY YY = IMSI 1
				XX XX XX XX XX XX XX XX = IMSI 2
					"""
					imsi2=p[0x49:][:8]
				elif ord(p[0x3a]) == 0x59 and ord(p[0x48]) == 0x08 and (ord(p[0x49]) & 0x1) == 0x1: 
					"""
				        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
				0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
				0010   00 43 f6 92 40 00 40 11 46 15 7f 00 00 01 7f 00
				0020   00 01 ab c1 12 79 00 2f fe 42 02 04 01 00 00 00
				0030   d8 00 00 23 3e be 02 00 05 00 4d 06 21 a0 08 YY
				0040   YY YY YY YY YY YY YY 17 05 f4 XX XX XX XX 2b 2b
				0050   2b
				YY YY YY YY YY YY YY YY = IMSI 1
				XX XX XX XX = TMSI
					"""
					tmsi1=p[0x4a:][:4]

				show_imsi(imsi1, imsi2, tmsi1, tmsi2, p)

			elif ord(p[0x45]) == 0x08 and (ord(p[0x46]) & 0x1) == 0x1: 
				"""
				        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
				0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
				0010   00 43 57 8e 40 00 40 11 e5 19 7f 00 00 01 7f 00
				0020   00 01 99 d4 12 79 00 2f fe 42 02 04 01 00 00 00
				0030   c7 00 00 11 05 99 02 00 03 00 4d 06 21 00 05 f4
				0040   yy yy yy yy 17 08 XX XX XX XX XX XX XX XX 2b 2b
				0050   2b
				yy yy yy yy = TMSI/P-TMSI - Mobile Identity 1
				XX XX XX XX XX XX XX XX = IMSI
				"""
				tmsi1=p[0x40:][:4]
				imsi2=p[0x46:][:8]
				show_imsi(imsi1, imsi2, tmsi1, tmsi2, p)

			elif ord(p[0x3e]) == 0x05 and (ord(p[0x3f]) & 0x07) == 4: 
				"""
				        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
				0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
				0010   00 43 b3 f7 40 00 40 11 88 b0 7f 00 00 01 7f 00
				0020   00 01 ce 50 12 79 00 2f fe 42 02 04 01 00 03 fd
				0030   d1 00 00 1b 03 5e 05 00 00 00 41 06 21 00 05 f4
				0040   XX XX XX XX 17 05 f4 YY YY YY YY 2b 2b 2b 2b 2b
				0050   2b
				XX XX XX XX = TMSI/P-TMSI - Mobile Identity 1
				YY YY YY YY = TMSI/P-TMSI - Mobile Identity 2
				"""
				tmsi1=p[0x40:][:4]
				if ord(p[0x45]) == 0x05 and (ord(p[0x46]) & 0x07) == 4: 
					tmsi2=p[0x47:][:4]
				else:
					tmsi2=""

				show_imsi(imsi1, imsi2, tmsi1, tmsi2, p)

		elif ord(p[0x3c]) == 0x22: 
			if ord(p[0x47]) == 0x08 and (ord(p[0x48]) & 0x1) == 0x1: 
				"""
				        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f				
				0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
				0010   00 43 1c a6 40 00 40 11 20 02 7f 00 00 01 7f 00
				0020   00 01 c2 e4 12 79 00 2f fe 42 02 04 01 00 00 00
				0030   c9 00 00 16 20 e3 02 00 04 00 55 06 22 00 yy yy
				0040   yy yy zz zz zz 4e 17 08 XX XX XX XX XX XX XX XX
				0050   8b
				yy yy yy yy = TMSI/P-TMSI - Mobile Identity 1
				zz zz zz zz = TMSI/P-TMSI - Mobile Identity 2
				XX XX XX XX XX XX XX XX = IMSI
				"""
				tmsi1=p[0x3e:][:4]
				tmsi2=p[0x42:][:4]
				imsi2=p[0x48:][:8]
				show_imsi(imsi1, imsi2, tmsi1, tmsi2, p)


if __name__ == '__main__':
	parser = OptionParser(usage="%prog: [options]")
	parser.add_option("-a", "--alltmsi", action="store_true", dest="show_all_tmsi", help="Show TMSI who haven't got IMSI (default  : false)")
	parser.add_option("-i", "--iface", dest="iface", default="lo", help="Interface (default : lo)")
	parser.add_option("-m", "--imsi", dest="imsi", default="", type="string", help='IMSI to track (default : None, Example: 123456789101112 or "123 45 6789101112")')
	parser.add_option("-p", "--port", dest="port", default="4729", type="int", help="Port (default : 4729)")
	(options, args) = parser.parse_args()

	show_all_tmsi=options.show_all_tmsi
	imsi_to_track=""
	if options.imsi:
		imsi="9"+options.imsi.replace(" ", "")
		imsi_to_track_len=len(imsi)
		if imsi_to_track_len%2 == 0 and imsi_to_track_len > 0 and imsi_to_track_len <17:
			for i in range(0, imsi_to_track_len-1, 2):
				imsi_to_track+=chr(int(imsi[i+1])*16+int(imsi[i]))
			imsi_to_track_len=len(imsi_to_track)
		else:
			print("Wrong size for the IMSI to track!")
			print("Valid sizes :")
			print("123456789101112")
			print("1234567891011")
			print("12345678910")
			print("123456789")
			print("1234567")
			print("12345")
			print("123")
			exit(1)


	with open('mcc-mnc/mcc_codes.json', 'r') as file:
		mcc_codes = json.load(file)
	sys.stdout.write("{:7s} ; {:10s} ; {:10s} ; {:17s} ; {:12s} ; {:10s} ; {:21s} ; {:5s} ; {:4s} ; {:5s} ; {:6s}".format("Nb IMSI", "T-IMSI1", "T-IMSI2", "IMSI", "Country", "Brand", "Operator", "MCC", "MNC", "LAC", "CellId"))
	sniff(iface=options.iface, filter="port {} and not icmp and udp".format(options.port), prn=find_imsi, store=0)
