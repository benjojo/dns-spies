spewer
===

Sends DNS packets with the ASN number attached.

Usage:

./bin/masscan --packet-trace --offline -p 53 --rate 50000 --excludefile exclude.list 0.0.0.0/0 | awk '{print $6}' | ./spewer

