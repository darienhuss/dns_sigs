dns_sigs
========

Create Suricata and Snort DNS signatures given a single domain or list of domains in a file.

Example usage:
python dns_sigs.py -d google.com -m "ET DNS Query for google.com" -c policy-violation -r google.com

Example output:
alert udp $HOME_NET any -> any 53 (msg:"ET DNS Query for google.com (google.com)"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"|06|google|03|com|00|"; nocase; distance:0; fast_pattern; reference:url,google.com; classtype:policy-violation; sid:20000000; rev:1;)


usage: dns_sigs.py [-h] [-f FILE] [-d DOMAIN] -m MESSAGE [-r REFERENCE]
                   [-c CLASSTYPE] [-s SID]

Quickly create Suricata/Snort DNS signatures

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File location with domain name list
  -d DOMAIN, --domain DOMAIN
                        Single domain name
  -m MESSAGE, --message MESSAGE
                        Provide full signature message, domain will be added
                        to the end
  -r REFERENCE, --reference REFERENCE
                        Provide a reference, or list of references separated
                        by a |
  -c CLASSTYPE, --classtype CLASSTYPE
                        Provide signature classtype (default: trojan-activity)
  -s SID, --sid SID     Provide starting sid number (default: 20000000)
