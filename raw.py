#!/usr/bin/python
# coding=utf-8

import os
import re
import select
import socket
import struct
import sys


TIMEOUT = 0.2

# значения собственных MAC и IP
ifconfig = os.popen('ifconfig ' + sys.argv[1]).read()

m = re.search(r'HWaddr\s([a-f\d:]+)', ifconfig)
if m:
	MAC = m.group(1)

m = re.search(r'inet\saddr:([\d\.]+)\s', ifconfig)
if m:
	IP = m.group(1)

# класс пакета для отправки
class ARPSendPacket:
	
	def _setip(self):
		'''Устанавливает IP отправителя (свой)'''
		self._ip_sedr = socket.inet_aton(IP)
		
	def _setmac(self):
		'''Устанавливает MAC отправителя (свой)'''
		macbin = ''
		for l in re.split(r':', MAC):
			macbin += chr(int('0x' + l, 16))
		self._eth_src = macbin
		self._mac_sedr = macbin

	def __init__(self, value=None):
		'''Инициализация пакета
		Принимает IP получателя
		'''
		# Заголовок Ethernet
		# eth назначения
		self._eth_dest = struct.pack('6B', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
		
		# eth источника
		self._eth_src = None
		
		# тип фрейма, всегда 
		self._type_frame = struct.pack('H', socket.htons(0x0806))
		
		# ARP пакет
		# тип аппаратуры (ethernet)
		self._type_hrd = struct.pack('H', socket.htons(1))

		# протокол ip, всегда 0x0800
		self._type_pro = struct.pack('H', socket.htons(0x0800)) 
		
		# длина mac
		self._mac_len = struct.pack('B', 6)

		# длина ip
		self._ip_len = struct.pack('B', 4) 
		
		# операция
		self._op = struct.pack('H', socket.htons(1))
		
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
		'''Увличивает ip на еденицу'''
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
while mip.next():
	print str(mip)
	packet = ARPSendPacket(mip.__str__())
	#packet = ARPSendPacket('192.168.159.3')
	soc = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
	soc.bind((sys.argv[1], 0x0806))
	soc.send(packet.__str__())
	while True:
		srecv = select.select([soc], [], [], TIMEOUT)
		if srecv[0]:
			data = soc.recv(42)
			if ord(data[21]) == 2:
				print mip, str(ord(data[6])) + ':' + str(ord(data[7])) + ':' + \
					str(ord(data[8])) + ':' + str(ord(data[9])) + ':' + \
					str(ord(data[10])) + ':' + str(ord(data[11]))
			else:
				print 'error packet'
		break



#~ numaddr = socket.inet_aton(sys.argv[2])

#~ print numaddr 


#~ handly_crafted_packet =\
#~ struct.pack('BBBBBB', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)+\
#~ struct.pack('BBBBBB', 0x00, 0x0c, 0x29, 0x60, 0x3d, 0x2a)+\
#~ struct.pack('H', socket.htons(0x0806))+\
#~ struct.pack('H', socket.htons(1))+\
#~ struct.pack('H', socket.htons(0x0800))+\
#~ struct.pack('B', 6)+\
#~ struct.pack('B', 4)+\
#~ struct.pack('H', socket.htons(1))+\
#~ struct.pack('BBBBBB', 0x00, 0x0c, 0x29, 0x60, 0x3d, 0x2a)+\
#~ socket.inet_aton('192.168.159.132')+\
#~ struct.pack('BBBBBB', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)+\
#~ socket.inet_aton('192.168.159.2')

#~ handly_crafted_packet = ARPSendPacket('192.168.159.3')

#~ soc = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
#~ soc.bind((sys.argv[1], 0x0806))

#~ soc.send(handly_crafted_packet.__str__())

#~ while True:
	#~ srecv = select.select([soc], [], [], TIMEOUT)
	#~ if srecv[0]:
		#~ data = soc.recv(42)
		#~ if ord(data[21]) == 2:
			#~ print 'ok'
		#~ else:
			#~ print 'false'
	#~ break
	
#~ print 'exit'


#~ i=1
#~ for c in handly_crafted_packet.__str__():
	#~ print "%02x" % ord(c),
	#~ if i % 16 == 0:
		#~ print
	#~ i+=1

#~ print

#~ i=1
#~ for c in data:
	#~ print "%02x" % ord(c),
	#~ if i % 16 == 0:
		#~ print
	#~ i+=1


#~ print












