#!/bin/python
#######################################################################
# Logical Port Bandwidth Checker
# Kohei Ogura <kogura@vmware.com>
#######################################################################

import sys
import requests
import json
import logging
import datetime
import time
from docopt import docopt

usage = """
Usage: mohg-checkbw.py -i LPORT_OR_LIFUUID [-l] [-t INTERVAL] [-r] [-m IPADDR] [-u USERNAME] [-p PASSWORD] [-v]

Options:
        -i LPORTUUID  Logical Port UUID
        -l            LIF Mode (Default is LP Mode)
        -t INTERVAL   Interval betwen data colection (seconds)
        -r            Turn OFF realtime data collection (realtime option does not work for Edge uplink connected logical ports)
        -m IPADDR     NSX Manager IP address
        -u USERNAME   NSX Manager Username
        -p PASSWORD   NSX Manager Password
        -v            verbose
"""

# nsx configurations
nsx_manager = "manager2.mgrn.net"
nsx_username = "admin"
nsx_password = ""

# NSX-T API URLs
url_base = "https://"
url_login = "/api/session/create"
url_base_lport = "/api/v1/logical-ports"
url_base_lif = "/api/v1/logical-router-ports"

# headers and body
lpstats_headers = {'content-type': 'application/json; charset=utf-8'}
lpstats_params = {'source': "realtime"}

# interval (sec)
interval = 10

# lif flag
lif_flag = False

# disalbe insequre request warning
# https://urllib3.readthedocs.org/en/latest/security.html
requests.packages.urllib3.disable_warnings()

# Login function using session based auth
# https://www.vmware.com/support/nsxt/doc/nsxt_21_api.html#Overview
def nsxt_login(ipaddr, username, password):
    # prepare payload, headers
    login_headers = {'content-type': 'application/x-www-form-urlencoded'}
    login_payload = {'j_username': username, 'j_password': password}

    r = requests.post(url_base + ipaddr + url_login, data=login_payload, headers=login_headers, verify=False)
    logging.info(str(r.status_code) +  " " + r.url)

    if r.status_code != requests.codes.ok:
        logging.error(r.text)
        r.raise_for_status()

    # return cookie and token
    token = r.headers['X-XSRF-TOKEN']
    cookie = r.cookies
    return {'token':token, 'cookie':cookie}

def nsxt_checkbw(lp_uuid, lif_flag, **kwargs):
    # ToDo: Error handling around passing key value variable length argument
    # update token to the header
    lpstats_headers['X-XSRF-TOKEN'] = kwargs['token']
    #lpstats_params['source'] = "realtime"
    lpstats_url = url_base + nsx_manager + url_base_lport + "/" + lp_uuid + "/statistics"
    lpstats_cookies = kwargs['cookie']

    # Send API request
    r = requests.get(lpstats_url, headers=lpstats_headers, params=lpstats_params, cookies=lpstats_cookies, verify=False)
    #logging.info(str(r.status_code) +  " " + r.url)

    if r.status_code != requests.codes.ok:
      logging.error(r.text)
      r.raise_for_status()

    j = r.json()
    
    # json scraping will differ between logical port and logical interface
    if lif_flag == True:
        bittx = float((j['per_node_statistics'][0]['tx']['total_bytes']))
        bitrx = float((j['per_node_statistics'][0]['rx']['total_bytes']))
        utsec = float((j['per_node_statistics'][0]['last_update_timestamp']) / 1000)
    elif lif_flag == False:
        bittx = float((j['tx_bytes']['total']) * 8)
        bitrx= float((j['rx_bytes']['total']) * 8)
        utsec = float((j['last_update_timestamp']) / 1000)

    return {'bittx':bittx, 'bitrx':bitrx, 'utsec':utsec}

def diffbw(currbittx, currbitrx, currutsec, prevbittx, prevbitrx, prevutsec):
    difbittx = currbittx - prevbittx
    difbitrx = currbitrx - prevbitrx
    difutsec = currutsec - prevutsec
    
    return {'difbittx':difbittx,'difbitrx':difbitrx,'difutsec':difutsec }

# main code starts here
if __name__ == '__main__':
    # check options
    args = docopt(usage)

    if args.get('-m'):
        nsx_manager = str(args.get('-m'))

    if args.get('-u'):
        nsx_username = str(args.get('-u'))

    if args.get('-p'):
        nsx_password = str(args.get('-p'))

    if args.get('-v') == True:
        logging.basicConfig(level=logging.INFO)

    if args.get('-i'):
        lp_uuid = args.get('-i')

    if args.get('-t'):
        interval = float(args.get('-t'))

    if args.get('-l'):
        url_base_lport = url_base_lif
        lif_flag = True

    # clear the realtime parameter if option is set
    if args.get('-r') == True:
        lpstats_params = {}

    # initial login and save cookie and token
    sessioninfo = nsxt_login(nsx_manager, nsx_username, nsx_password)

    # check first data
    firstdata = nsxt_checkbw(lp_uuid, lif_flag, **sessioninfo)
    
    # save initial utime
    initialutsec = firstdata['utsec']

    # main loop starts here
    while (1):
        time.sleep(interval)
        seconddata = nsxt_checkbw(lp_uuid, lif_flag, **sessioninfo)
        diffdata = diffbw(seconddata['bittx'], seconddata['bitrx'], seconddata['utsec'], firstdata['bittx'], firstdata['bitrx'], firstdata['utsec'])
        
        if diffdata['difutsec'] == 0:
            # generate info syslog if no update are in the data
            currtime = datetime.datetime.fromtimestamp(seconddata['utsec'])
            logging.info("No data update observed. Last update at " + str(seconddata['utsec']) + " = " + currtime.strftime('%Y-%m-%d %H:%M:%S'))
        else:
            # Using kbps for now
            kbpstx = ((diffdata['difbittx'] / diffdata['difutsec']) / 1000 )
            kbpsrx = ((diffdata['difbitrx'] / diffdata['difutsec']) / 1000 )
            currutsec = seconddata['utsec'] - initialutsec
            print '{0:.2f}'.format(kbpstx), '{0:.2f}'.format(kbpsrx), '{0:.2f}'.format(currutsec)

        firstdata = nsxt_checkbw(lp_uuid, lif_flag, **sessioninfo)

