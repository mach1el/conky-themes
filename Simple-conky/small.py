#!/usr/bin/env python2

import requests
import os,sys,time
from random import *
from socket import *
from struct import *
from httplib import *
from threading import *
from termcolor import colored,cprint

options_num = [1,2,3]
urls		= ['nsa.gov','cia.gov','asis.gov.au','www.sis.gov.uk','www.bnd.bund.de',
               'nasa.gov','sealswcc.com','nato.int','fbi.gov','nyc.gov','apple.com',
               'microsoft.com','google.com','web.mit.edu','tesla.com','spacex.com',
]

class icmphdr(object):
    def __init__(self, data=""):
        self.type     = 8
        self.code     = 0
        self.cksum    = 0
        self.id       = randint(2**10,2**16)
        self.sequence = 0
        self.data     = data

    def assemble(self):
        part1 = pack("BB", self.type, self.code)
        part2 = pack("!HH", self.id, self.sequence)
        cksum = self.checksum(part1 + "\x00\x00" + part2 + self.data)
        cksum = pack("!H", cksum)
        self._raw = part1 + cksum + part2 + self.data
        return self._raw

    @classmethod
    def checksum(self, data):
        if len(data) & 1:
            data += "\x00"
        cksum = reduce(operator.add,
                       unpack('!%dH' % (len(data) >> 1), data))
        cksum = (cksum >> 16) + (cksum & 0xffff)
        cksum += (cksum >> 16)
        cksum = (cksum & 0xffff) ^ 0xffff
        return cksum

    @classmethod
    def disassemble(self, data):
        self._raw = data
        icmp = icmphdr()
        pkt = unpack("!BBHHH", data)
        icmp.type, icmp.code, icmp.cksum, icmp.id, icmp.sequence = pkt
        return icmp

    def __repr__(self):
        return "ICMP (type %s, code %s, id %s, sequence %s)" % \
               (self.type, self.code, self.id, self.sequence)


class IPPinger:
    def __init__(self,ip,sr,er):
        self.ip       = ip
        self.sr       = sr
        self.er       = er
        self.type     = 8
        self.code     = 0
        self.cksum    = 0
        self.toip     = []
        self.mypacket = ''
        self.id       = os.getpid() & 0xFFFF

    def create_ips(self):
        ipaddrs=[]
        ip=self.ip.split('.')
        delElement=ip.pop(3)
        mystr='.'.join(ip)
        for x in xrange(int(self.sr),int(self.er)):
            ipaddr=mystr+'.'+str(x)
            ipaddrs.append(ipaddr)
        return ipaddrs

    def checksum(self,data):
        csum = 0
        countTo = (len(data) / 2) * 2
        count = 0
        while count < countTo:
            thisVal = ord(data[count+1]) * 256 + ord(data[count])
            csum = csum + thisVal
            csum = csum & 0xffffffffL
            count = count + 2
        if countTo < len(data):
            csum = csum + ord(data[len(data) - 1])
            csum = csum & 0xffffffffL
        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    def building_packet(self):
        header=pack('bbHHh',self.type,self.code,self.cksum,self.id,1)
        data=pack('d',time.time())
        mycksum=self.checksum(header+data)
        if sys.platform == 'darwin':
            mycksum=htons(mycksum) & 0xffff
        else:
            mycksum=htons(mycksum)
        header=pack('bbHHh',self.type,self.code,mycksum,self.id,1)
        packet=header+data
        return packet

    def building_socket(self):
        try:
            sock=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)
        except Exception,e:
            raise Exception(e)
        return sock
    def get_status(self,pkt):
        try:
            icmpstatus=icmphdr.disassemble(pkt[20:28])
            if (icmpstatus.type == 8 and icmpstatus.code == 0):
                return 'Alive'
            elif (icmpstatus.type == 0 and icmpstatus.code == 0):
                return 'Alive'
            else:
                return 'Dead'
        except KeyboardInterrupt:
            sys.exit(cprint('[-] Canceled by user','red'))

    def ping_process(self):
        ips=self.create_ips()
        pkt=self.building_packet()
        mysock=self.building_socket()
        mysock.setsockopt(SOL_SOCKET,SO_BROADCAST,1)
        mysock.settimeout(0.05)
        for ip in ips:
            self.ping(ip,mysock,pkt)
        for ip in self.toip:
            self.reping(ip,mysock,pkt)

    def ping(self,ip,mysock,pkt):
        try:
            mysock.sendto(pkt,(ip,0))
            d,addr=mysock.recvfrom(4096)
            status=self.get_status(d)
            if status == 'Alive':
                print (ip)
            if status == 'Dead':
                pass
        except Exception:
            self.toip.append(ip)
        except KeyboardInterrupt:
            sys.exit(('[-] Canceled by user'))

    def reping(self,ip,mysock,pkt):
        try:
            mysock.settimeout(3)
            mysock.sendto(pkt,(ip,0))
            d,addr=mysock.recvfrom(4096)
            status=self.get_status(d)
            if status == 'Alive':
                print (ip)
            if status == 'Dead':
                pass
        except Exception:
        	pass
        except KeyboardInterrupt:
            sys.exit(('[-] Canceled by user'))

class MethodsTester:
	def __init__(self,url,port):
		self.url            = url
		self.port 			= port
		self.caches         = ['no-cache',
		                       'no-store',
		                       'max-age='+str(randint(0,10)),
		                       'max-stale='+str(randint(0,100)),
		                       'min-fresh='+str(randint(0,10)),
		                       'notransform',
		                       'only-if-cache'
		]
		self.AcceptEC       = ['*',
		                       'compress,gzip',
		                       'compress;q=0,5, gzip;q=1.0',
		                       'gzip;q=1.0, indentity; q=0.5, *;q=0'
		]
		self.User_Agent     = ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36',
		                       'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0',
		                       'Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)',
		                       'Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)',
		                       'Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25',
		                       'Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)'
		]
		self.custom_header  = self.__Create_headers()

		if self.port == 80:
			try:
				self.Requester = HTTPConnection(self.url,80)
			except Exception,e:
				raise Exception(e)
		else:
			try:
				self.Requester = HTTPSConnection(self.url,443)
			except Exception,e:
				raise Exception(e)

	def __Create_headers(self):
		headers = {
		    'User-Agent' : choice(self.User_Agent),
		    'Cache-Control' : self.caches,
		    'Accept-Encoding' : self.AcceptEC,
		    'Keep-Alive' : '42',
		    'Connection' : 'keep-alive',
		    'Host' : self.url
		}
		return headers

	def GET(self):
		try:
			self.Requester.request('GET',self.url,None,self.custom_header)
			res = self.Requester.getresponse()
			if res:
				print('GET Method')
				print 'Status => {0}\tReason => {1}'.format(res.status,res.reason)
				data = res.read()
			print data+'\n'
		except Exception,e:
			print '=>',e

	def HEAD(self):
		try:
			self.Requester.request('HEAD',self.url,None,self.custom_header)
			res = self.Requester.getresponse()
			if res:
				print('HEAD Method')
				print 'Status => {0}\tReason => {1}'.format(res.status,res.reason)
			data = res.read()
			print data+'\n'
		except Exception,e:
			print '=>',e


class get_header:
    def __init__(self,url):
        self.url = url
        self.r   = None

    def __request(self):
        headers={
            'User-Agent' : 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36',
        }
        try:
            url    = 'http://'+self.url
            self.r = requests.get(url,headers=headers)
        except Exception,e:
            sys.exit(e)

    def print_result(self):
        self.__request()
        code     = self.r.status_code
        reason   = self.r.reason
        mykeys   = self.r.headers.keys()
        myvalues = self.r.headers.values()
        print ('Code: ') + str(code) + '\t\t' +('Status: ') + (reason)
        x=0
        while x < len(mykeys):
            print '{0}[{1}]'.format(mykeys[x],myvalues[x])
            x+=1
            if x == len(mykeys):
                break


def main():
	option = choice(options_num)
	if option == 1:
		ip     = '192.168.1.1'
		srange = 0
		erange = 255
		ping   = IPPinger(ip,srange,erange)
		ping.ping_process()

	elif option == 2:
		method = ['get','head']
		url    = choice(urls)
		port   = choice([80,443])
		print 'Check Status for {0}:{1}'.format(url,port)
		tester = MethodsTester(url,port)
		if choice(method) == 'get':
			tester.GET()
		else:
			tester.HEAD()

	elif option == 3:
		url    = choice(urls)
		print '=> Get header for {}'.format(url)
		worker = get_header(url)
		worker.print_result()

if __name__ == '__main__':
	main()