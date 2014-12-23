dns_sigs
========

Create Suricata and Snort DNS signatures given a single domain or list of domains in a file.

Example usage:
python dns_sigs.py -d google.com -m "ET DNS Query for google.com" -c policy-violation -r google.com

Example output:
alert udp $HOME_NET any -> any 53 (msg:"ET DNS Query for google.com (google.com)"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"|06|google|03|com|00|"; nocase; distance:0; fast_pattern; reference:url,google.com; classtype:policy-violation; sid:20000000; rev:1;)


usage: dns_sigs.py [-h] [-f FILE] [-d DOMAIN] -m MESSAGE [-r REFERENCE]
                   [-c CLASSTYPE] [-s SID]


Warning: no error checking
