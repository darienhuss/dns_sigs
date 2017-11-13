dns_sigs
========

Create Suricata and Snort DNS signatures given a single domain or list of domains in a file.

Example usage:
python dns_sigs.py -d google.com -m "ET DNS Query for google.com" -c policy-violation -r google.com

Example output:

#Suricata 3.2+

alert dns $HOME_NET any -> any any (msg:"ET DNS Query for google.com"; dns_query; content:"google.com"; nocase; isdataat:!1,relative; reference:url,google.com; classtype:policy-violation; sid:20000000; rev:1;)


#Suricata 1.3+

alert udp $HOME_NET any -> any 53 (msg:"ET DNS Query for google.com"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|06|google|03|com|00|"; nocase; distance:0; fast_pattern; reference:url,google.com; classtype:policy-violation; sid:20000000; rev:1;)


usage: dns_sigs.py [-h] [-f FILE] [-d DOMAIN] -m MESSAGE [-r REFERENCE]
                   [-c CLASSTYPE] [-s SID]


Warning: no error checking
