#!/usr/bin/env python3 -tt

__author__ = 'Paul Morrison'
__credits__ = ""
__date__ = "Last updated on 2021-12-11"

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

ips2scan = []

## TODO:
## - Better errors when returning 200 but error page


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

	def __init__(self, number, path, ports, matchStrings, definete):

		threading.Thread.__init__(self)
		self.number = number
		self.path = path
		self.ports = ports
		self.matchStrings = matchStrings
		self.definete = definete

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
				
						url = "%s://%s:%s%s" % (scheme, ip, port, self.path)
						timeout = False
						failure = False
						success = False

						try:
							r = requests.get(url, timeout=5, verify=False)
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
						else:
							if not self.definete:
								if len(r.history) == 0:
									logging.info('Probable success: %s - %s' % (r.status_code, url))
								else:		
									logging.info('Possible success: %s - %s (%s - %s)' % (r.status_code, url, r.history[0].status_code, r.history[0].headers['Location']))

						if success:
							if len(r.content) > 0:
								for ms in self.matchStrings:
									if r.content.find(ms.encode()) >= 0:
										logging.info('Definite match: %s' % (url))
									else:
										if r.content.lower().find(ms.encode().lower()) >= 0:
											logging.info('Definete case insensitive match: %s' % (url))
							
					



		



if __name__ == '__main__':

	parser = argparse.ArgumentParser(description="Scan a single URL endpoint to see if it exists across many URLs", epilog="""EXAMPLE:
		python3 endpointScanner.py -u \"/mgmt/shared/authn/login\" -i ipList.txt
	OR
		python3 endpointScanner.py -p "/owa/auth/logon.aspx" -i ipList.txt -t 10 -s '<!-- OwaPage = ASP.auth_logon_aspx -->'
	OR
		python3 endpointScanner.py -p "/WorkArea/java/ektron.site-data.js.ashx" -i ipList.txt -t 30 -s 'Ektron.Site' -d
	OR
		python3 endpointScanner.py -p "/login" -i ipList.txt -s "Grafana" -d
	""",formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-p', '--path', help='THe endpoint to scan (URL path), format: "/mgmt/ui/tms"')
	parser.add_argument('-i', '--ips', help='File with list of IPs or Hostnames to test, can be FQDN, IP or CIDR notation, one per line')
	parser.add_argument('-t', '--threads', nargs='?', default='1', help="Number of Threads to run", type=int)
	parser.add_argument('-v', '--verbose', action='store_true', help='verbose levels of logging', default=False)
	parser.add_argument('-r', '--random', action='store_true', default=True, help='randomise order of IPs')
	parser.add_argument('-s', '--stringmatches', help='Either a single string match or a filename of line delimitered string matches. Matches to find in the HTTP response to match on')
	parser.add_argument('-n', '--port', help='What port numbers, to hit, commma seperated. Default: 80,443', default='80,443')
	parser.add_argument('-d', '--definete', help='Only print absolutely definte matches, not possible ones', action='store_true')

	args = parser.parse_args()

	''' Setup logger '''
	if args.verbose:
		logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	else:
		logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

	if not args.path:
		logging.error("You don't have a URL path specified. Use help file if necessary")
		sys.exit()

	if not args.ips:
		logging.error("You don't have a list of IPs to scan against. Use help file if necessary")
		sys.exit()
	else:
		if not os.path.exists(args.ips):
			logging.error("Tne file %s doesn't exist." % (args.ips))
			sys.exit()

	stringMatches = []

	if args.stringmatches:
		if os.path.exists(args.stringmatches):
			stringMatches = open(args.stringmatches,'r').readlines()
			stringMatches = [s.strip() for s in stringMatches]
		else:
			stringMatches = [args.stringmatches]

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
		ThreadScanner(i, args.path, args.port, stringMatches, args.definete).start()

