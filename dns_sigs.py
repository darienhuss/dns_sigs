#!/usr/bin/python -tt
# dns_sigs.py
# Create Suricata and Snort DNS signatures given a single domain or list of domains in a file.
#
# Example: ./dns_sigs.py -s google.com -m "ET DNS Query for google.com" -c policy-violation -s 1337 -r google.com
# OUTPUT:
#	alert udp $HOME_NET any -> any 53 (msg:"ET DNS Query for google.com (1337)"; content:"|01 00 00 01 00 00 00 00 00 00|"; 
#	depth:10; offset:2; content:"|04|1337|00|"; nocase; distance:0; fast_pattern; reference:url,google.com; classtype:policy-violation;
#	sid:20000000; rev:1;)

import argparse, re

def main():
	parser = argparse.ArgumentParser(description='Quickly create Suricata/Snort DNS signatures')
	parser.add_argument('-f','--file', help='File location with domain name list',required=False,default="")
	parser.add_argument('-d','--domain', help='Single domain name',required=False,default="")
	parser.add_argument('-m','--message', help='Provide full signature message, domain will be added to the end',required=True,default="")
	parser.add_argument('-r','--reference', help='Provide a md5 or url reference, or list of references separated by a |',required=False,default="")
	parser.add_argument('-c','--classtype', help='Provide signature classtype (default: trojan-activity)',required=False,default="trojan-activity")
	parser.add_argument('-s','--sid', help='Provide starting sid number (default: 20000000)',required=False,default="20000000")

	args = parser.parse_args()

	domain_list_file = args.file
	single_domain = args.domain
	message = args.message
	references = args.reference
	classtype = args.classtype
	sid = int(args.sid)

	onion_re = re.compile('^[a-z0-9]{16}$')
	skip_re = re.compile('^\s*(#.*)?$')

	domains = []
	reference = ''
	if references:
		md5_re = re.compile('^[a-f0-9]{32}$')
		references = references.split('|')

		for ref in references:
			if md5_re.search(ref):
				reference += 'reference:md5,%s; ' % ref
			else:
				reference += 'reference:url,%s; ' % ref

	if domain_list_file:
		with open(domain_list_file) as f:
			domains = f.read().splitlines()
	else:
		domains.append(single_domain)

	for domain in domains:
		if skip_re.search(domain):
			print domain
			continue
		levels = domain.split('.')
		domain_sig = ''

		#signature_message = '%s (%s)' % (message,domain) #prints domain in addition to message
		signature_message = message
		rule_stub_start = 'alert udp $HOME_NET any -> any 53 (msg:"%s"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"' % signature_message
		rule_stub_end = '"; nocase; distance:0; fast_pattern; %sclasstype:%s; sid:%s; rev:1;)' % (reference,classtype,sid)
		sid += 1
		for level in levels:
			domain_sig += '|%s|%s' % (hex(len(level)).lstrip('0x').zfill(2),level)
		if not onion_re.search(domain):
			domain_sig += '|00|'
		print rule_stub_start + domain_sig + rule_stub_end

if __name__ == '__main__':
  main()
