#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Program entry point"""

from __future__ import print_function

import os
import sys
import urllib
import urllib2
import argparse
import re
import socket
import dns.resolver
from urllib2 import urlopen


URLS = [
    #TOR
    ('http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv',
     'is not a TOR Exit Node',
     'is a TOR Exit Node',
     False),

    #EmergingThreats
    ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'is not listed on EmergingThreats',
     'is listed on EmergingThreats',
     True),

    #AlienVault
    ('http://reputation.alienvault.com/reputation.data',
     'is not listed on AlienVault',
     'is listed on AlienVault',
     True),

    #BlocklistDE
    ('http://www.blocklist.de/lists/bruteforcelogin.txt',
     'is not listed on BlocklistDE',
     'is listed on BlocklistDE',
     True),

    #Dragon Research Group - SSH
    ('http://dragonresearchgroup.org/insight/sshpwauth.txt',
     'is not listed on Dragon Research Group - SSH',
     'is listed on Dragon Research Group - SSH',
     True),

    #Dragon Research Group - VNC
    ('http://dragonresearchgroup.org/insight/vncprobe.txt',
     'is not listed on Dragon Research Group - VNC',
     'is listed on Dragon Research Group - VNC',
     True),

    #OpenBLock
    ('http://www.openbl.org/lists/date_all.txt',
     'is not listed on OpenBlock',
     'is listed on OpenBlock',
     True),

    #NoThinkMalware
    ('http://www.nothink.org/blacklist/blacklist_malware_http.txt',
     'is not listed on NoThink Malware',
     'is listed on NoThink Malware',
     True),

    #NoThinkSSH
    ('http://www.nothink.org/blacklist/blacklist_ssh_all.txt',
     'is not listed on NoThink SSH',
     'is listed on NoThink SSH',
     True),

    #Feodo
    ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'is not listed on Feodo',
     'is listed on Feodo',
     True),

    #antispam.imp.ch
    ('http://antispam.imp.ch/spamlist',
     'is not listed on antispam.imp.ch',
     'is listed on antispam.imp.ch',
     True),

    #dshield
    ('http://www.dshield.org/ipsascii.html?limit=10000',
     'is not listed on dshield',
     'is listed on dshield',
     True),

    #MalWareBytes
    ('http://hosts-file.net/rss.asp',
     'is not listed on MalWareBytes',
     'is listed on MalWareBytes',
     True)]


bls = ["all.s5h.net", "b.barracudacentral.org",
       "bl.spamcannibal.org", "bl.spamcop.net",
       "blacklist.woody.ch", "cbl.abuseat.org", "cdl.anti-spam.org.cn",
       "combined.abuse.ch", "combined.rbl.msrbl.net", "db.wpbl.info",
       "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
       "dnsbl-3.uceprotect.net", "dnsbl.cyberlogic.net",
       "dnsbl.sorbs.net", "drone.abuse.ch", "drone.abuse.ch",
       "duinv.aupads.org", "dul.dnsbl.sorbs.net", "dul.ru",
       "dyna.spamrats.com", "dynip.rothen.com",
       "http.dnsbl.sorbs.net", "images.rbl.msrbl.net",
       "ips.backscatterer.org", "ix.dnsbl.manitu.net",
       "korea.services.net", "misc.dnsbl.sorbs.net",
       "noptr.spamrats.com", "ohps.dnsbl.net.au", "omrs.dnsbl.net.au",
       "orvedb.aupads.org", "osps.dnsbl.net.au", "osrs.dnsbl.net.au",
       "owfs.dnsbl.net.au", "pbl.spamhaus.org", "phishing.rbl.msrbl.net",
       "probes.dnsbl.net.au", "proxy.bl.gweep.ca", "rbl.interserver.net",
       "rdts.dnsbl.net.au", "relays.bl.gweep.ca", "relays.nether.net",
       "residential.block.transip.nl", "ricn.dnsbl.net.au",
       "rmst.dnsbl.net.au", "smtp.dnsbl.sorbs.net",
       "socks.dnsbl.sorbs.net", "spam.abuse.ch", "spam.dnsbl.sorbs.net",
       "spam.rbl.msrbl.net", "spam.spamrats.com", "spamrbl.imp.ch", "tor.dnsbl.sectoor.de",
       "torserver.tor.dnsbl.sectoor.de", "ubl.lashback.com",
       "ubl.unsubscore.com", "virus.rbl.jp", "virus.rbl.msrbl.net",
       "web.dnsbl.sorbs.net", "wormrbl.imp.ch", "xbl.spamhaus.org",
       "zen.spamhaus.org", "zombie.dnsbl.sorbs.net"]


def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text

    return '\x1b[%dm%s\x1b[0m' % (color_code, text)


def red(text):
    return color(text, 31)


def blink(text):
    return color(text, 5)


def green(text):
    return color(text, 32)


def blue(text):
    return color(text, 34)


def content_test(url, badip):
    try:
        request = urllib2.Request(url)
        opened_request = urllib2.build_opener().open(request)
        html_content = opened_request.read()
        retcode = opened_request.code

        matches = retcode == 200
        matches = matches and re.findall(badip, html_content)

        return len(matches) == 0

    except Exception, e:
        print
        "Error! %s" % e
        return False


def entry_point():
    parser = argparse.ArgumentParser(description='Is this IP blacklisted')
    parser.add_argument('-i', '--ip', help='The IP Address to check')

    args = parser.parse_args()

    if args is not None and args.ip is not None and len(args.ip) > 0:
        badip = args.ip
        print(badip)

    else:
        my_ip = urlopen('http://icanhazip.com').read().rstrip()

        print(blue('Check IP against popular IP and DNS blacklists'))
        print(red('Your public IP address is {0}\n'.format(my_ip)))
        resp = raw_input('Would you like to check {0} ? (Y/N):'.format(my_ip))

        if resp.lower() in ['y', 'yes']:
            badip = my_ip
        else:
            badip = raw_input(blue("\nWhat IP would you like to check?: "))
            if badip is None or badip == "":
                sys.exit("No IP address to check.")

    reversed_dns = socket.getfqdn(badip)
    geoip = urllib.urlopen('http://api.hackertarget.com/geoip/?q=' + badip).read().rstrip()

    print(blue('\nThe FQDN for {0} is {1}\n'.format(badip, reversed_dns)))
    print(red('Geolocation IP Information:'))
    print(blue(geoip))
    print('\n')

    bad = 0
    good = 0

    for url, succ, fail, mal in URLS:
        if content_test(url, badip):
            print(green('{0} {1}'.format(badip, succ)))
            good = good + 1
        else:
            print(red('{0} {1}'.format(badip, fail)))
            bad = bad + 1

    bad = bad
    good = good

    for bl in bls:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(badip).split("."))) + "." + bl
            my_resolver.timeout = 5
            my_resolver.lifetime = 5
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            print(red(badip + ' is listed in ' + bl) + ' (%s: %s)' % (answers[0], answer_txt[0]))
            bad = bad + 1

        except dns.resolver.NXDOMAIN:
            print(green(badip + ' is not listed in ' + bl))
            good = good + 1

        except dns.resolver.Timeout:
            print(blink('WARNING: Timeout querying ' + bl))

        except dns.resolver.NoNameservers:
            print(blink('WARNING: No nameservers for ' + bl))

        except dns.resolver.NoAnswer:
            print(blink('WARNING: No answer for ' + bl))

    print(red('\n{0} is on {1}/{2} blacklists.\n'.format(badip, bad, (good+bad))))


if __name__ == '__main__':
    raise(sys.exit(entry_point()))
