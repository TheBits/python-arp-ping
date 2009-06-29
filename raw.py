#!/usr/bin/python
# coding=utf-8

import optparse
import os
import re
import select
import socket
import struct
import sys


# socket timeout
TIMEOUT = 0.2

# Ethernet
TYPEFRAME = 0x0806

# ARP packet
TYPEHRD = 1

# protocol ip
PROTOCOLTYPE = 0x0800

# ARP default
PACKETSIZE = 42

ARPREQUEST = 1
ARPREPLY = 2

# command line
parser = optparse.OptionParser(usage='usage: %prog nic net_address net_mask')
args = parser.parse_args(args=None, values=None)
if len(args[1]) != 3: # need 3 arg
        parser.error("incorrect number of arguments")

# network address
try:
	socket.inet_aton(sys.argv[2])
except socket.error:
	parser.error("error net address")

# network mask
try:
	socket.inet_aton(sys.argv[3])
except socket.error:
	parser.error("error net mask")

# interface
if not re.match(r'^eth\d{1}$', sys.argv[1]):
	parser.error("error net interface")


# значения собственных MAC и IP
ifconfig = os.popen('ifconfig ' + sys.argv[1]).read()

m = re.search(r'HWaddr\s([a-f\d:]+)', ifconfig)
if m:
	MAC = m.group(1)

m = re.search(r'inet\saddr:([\d\.]+)\s', ifconfig)
if m:
	IP = m.group(1)

# arp packet
class ARPSendPacket:
	
	def _setip(self):
		'''Self IP'''
		self._ip_sedr = socket.inet_aton(IP)
		
	def _setmac(self):
		'''Self MAC'''
		macbin = ''
		for l in re.split(r':', MAC):
			macbin += chr(int('0x' + l, 16))
		self._eth_src = macbin
		self._mac_sedr = macbin

	def __init__(self, value=None):
		'''Init packet'''
		# Заголовок Ethernet
		# eth назначения
		self._eth_dest = struct.pack('6B', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
		
		# eth источника
		self._eth_src = None
		
		# тип фрейма, всегда 
		self._type_frame = struct.pack('H', socket.htons(TYPEFRAME))
		
		# ARP пакет
		# тип аппаратуры (ethernet)
		self._type_hrd = struct.pack('H', socket.htons(TYPEHRD))

		# протокол ip, всегда 0x0800
		self._type_pro = struct.pack('H', socket.htons(PROTOCOLTYPE)) 
		
		# длина mac
		self._mac_len = struct.pack('B', struct.calcsize('6B'))

		# длина ip вычисляется
		#self._ip_len = struct.pack('B', 4) 
		
		# операция
		self._op = struct.pack('H', socket.htons(ARPREQUEST))
		

		# mac отправителя
		self._mac_sedr = None

		# ip отправителя
		self._ip_sedr = None
		
		# mac получателя
		self._mac_recvr = struct.pack('6B', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		
		# ip получателя
		self._ip_recvr = socket.inet_aton(value)
		
		self._setmac()
		
		self._setip()
		self._ip_len = struct.pack('B', len(self._ip_sedr))
		

	def __str__(self):
		'''Возвращает пакет'''
		return self._eth_dest + self._eth_src + self._type_frame + \
				self._type_hrd + self._type_pro + self._mac_len + \
				self._ip_len + self._op + self._mac_sedr + \
				self._ip_sedr + self._mac_recvr + self._ip_recvr


class IPAddress:

	def __init__(self, ip, mask=None):
		self.n = []
		for l in re.split('\.', ip):
			self.n.append(int(l))
		
		# широковещательный IP
		self.limit = []
		if mask:
			net = []
			for nl in re.split('\.', sys.argv[2]):
				net.append(int(nl))
			
			for m in re.split('\.', mask):
				self.limit.append(~int(m))

			for i in range(0, 4):
				self.limit[i] = abs(256 - net[i] + self.limit[i])

	def next(self):
		'''Next IP'''
		self.n[3] += 1

		if self.n[3] == 256:
			self.n[3] = 0
			self.n[2] += 1

		if self.n[2] == 256:
			self.n[2] = 0
			self.n[1] += 1

		if self.n[1] == 256:
			self.n[1] = 0
			self.n[0] += 1

		if self.n[0] == 256:
			return False

		# широковещательный адрес
		if self.n == self.limit:
			return False
			
		return True

	def __str__(self):
		'''Возвращает строку ip адреса'''
		r = []
		for i in self.n:
			r.append(str(i))
		return '.'.join(r)


mip = IPAddress(sys.argv[2], sys.argv[3])
soc = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
soc.bind((sys.argv[1], TYPEFRAME))
while mip.next():
	print str(mip) # печать запрашиваемого IP адреса
	packet = ARPSendPacket(mip.__str__()) # создание ARP-пакета
	soc.send(packet.__str__())
	while True:
		srecv = select.select([soc], [], [], TIMEOUT)
		# data
		if srecv[0]:
			data = soc.recv(PACKETSIZE)
			# ARP-response
			if ord(data[21]) == ARPREPLY:
				# print IP and MAC
				print mip, str(ord(data[6])) + ':' + str(ord(data[7])) + ':' + \
					str(ord(data[8])) + ':' + str(ord(data[9])) + ':' + \
					str(ord(data[10])) + ':' + str(ord(data[11]))
			else:
				# не ARP-ответ
				print 'error packet'
		break
