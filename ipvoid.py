#!/usr/bin/env python3

#__author__ : MangJong
#__Date__   : 2018.07.03
#__Modified : 2022.05.18

import os
import sys
import time
import requests
import re
import socket
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Run Speed Measurements
start_time = time.time()

ipvoid_url = "https://www.ipvoid.com/ip-blacklist-check/"

'''
def write_log(filename, line):
    f = open(filename, "a+")
    f.write(line.strip() + "\n")
    f.close()
'''

def check_ipvoid(ip):

    cookies = {
        'cookiebanner-accepted': '1',
        'optinmodal': 'shown',
        '__utmt': '1',
        '__utma': '67803593.580391096.1496747284.1497281718.1497345596.7',
        '__utmb': '67803593.1.10.1497345596',
        '__utmc': '67803593',
        '__utmz': '67803593.1496747284.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none)',
    }

    headers = {
        'Origin': 'http://www.ipvoid.com',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.8',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; ; HSNC5_AAPB70BF580F04) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Cache-Control': 'max-age=0',
        'Referer': 'http://www.ipvoid.com/',
        'Connection': 'keep-alive',
    }

    r = requests.post(ipvoid_url, headers=headers, cookies=cookies, data={'ip' : str(ip)}, verify=False)
    content = r.text
    #print (content)
    bad_reputations = re.findall(r'<i class="fa fa-minus-circle text-danger" aria-hidden="true"></i> (.+?)</td>', content, re.MULTILINE)  
    country_code = re.findall(r'alt="Flag" width="20" /> \((\w+)\)', content, re.MULTILINE)
    #elapsed_time = re.findall(r'Elapsed Time</td><td>(.+?)</td>', content, re.MULTILINE)
  
    blacklist_status = re.findall(r'">(.+?)</span></td></tr>', content, re.MULTILINE)   # test 3
    #asn_owner = re.findall(r'ASN Owner</td><td>(.+?)</td>', content, re.MULTILINE)
    isp = re.findall(r'ISP</td><td>(.+?)</td>', content, re.MULTILINE)

    print('IP Address Information\n')
    print('IP ADDRESS   | ', ip)
    print('COUNTRY CODE | ', str(country_code)[2:-2])
    #print('ASN_OWBER    | ', asn_owner)
    print('ISP          | ', str(isp)[2:-2])
    print('BLACKLISTED  | ', str(blacklist_status)[2:-2])

    if 0 != len(bad_reputations):
        all_bad = ""
        for bad in bad_reputations:
            all_bad += bad + ", "
        print('List Report  | ', all_bad)

if None == re.search(".txt",sys.argv[1]):
    check_ipvoid(sys.argv[1])
else:
    lines = open(sys.argv[1]).readlines()
    for line in lines:
        if line.strip() != "":
            check_ipvoid(line.strip())
            print("\n")
            time.sleep(3)

print("\nTotal Time   | %s seconds " % round((time.time() - start_time),2))
