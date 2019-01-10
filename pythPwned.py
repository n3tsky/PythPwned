#!/usr/bin/env python
# Inspired by https://github.com/thewhiteh4t/pwnedOrNot
import sys
from argparse import ArgumentParser, RawTextHelpFormatter
import requests
#import cfscrape
from signal import signal, SIGINT
import json
from time import sleep
from tabulate import tabulate

# Constant
BASE_URL="https://haveibeenpwned.com/api/v2"
USER_AGENT="Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0"
DEFAULT_WAIT=2
# Color
GREEN="\033[0;32m"
RED="\033[0;31m"
ORANGE="\033[0;33m"
NOCOLOR="\033[0m"

# Perform HTTP query
def make_query(cf, HTTP_REQ):
    # Request through cfscrape (Cloud-flare)
    if cf:
        return None
        #return cfscrape.get_tokens(HTTP_REQ["url"], user_agent=HTTP_REQ["user-agent"])
    else: # Normal request
        headers = {
            "User-Agent": "%s" % (HTTP_REQ["user-agent"]),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept_language": "en-US,en;q=0.5",
            "Accept_encoding": "gzip, deflate, br"
        }
        return requests.get(HTTP_REQ["url"], headers=headers, proxies=HTTP_REQ["proxy"])

def http_query(cf, HTTP_REQ):
    try:
        return make_query(cf, HTTP_REQ)
    except requests.exceptions.HTTPError as e:
        print "[!] Exception while performing HTTP request to %s" % (HTTP_REQ["url"])
        return None

# Display data to user (grid)
def display_data(data, headers):
    print(tabulate(data, headers, "grid"))

# Check if value is in given dictionary or return None
def check_and_get(d, value):
    return d[value] if value in d else None

# Parse JSON result from HIBP
def parse_json(data, needed):
    g = list()
    for d in data:
        l = list()
        for n in needed:
            l.append(check_and_get(d, n))
        g.append(l)
    return g

# Lookup for Pastebin's paste (still available or not)
def check_pastebin(HTTP_REQ, url):
    HTTP_REQ["url"] = "%s" % (url)
    req = http_query(0, HTTP_REQ)
    if req.status_code == 200:
        if "This page has been removed" in req.text:
            return "%sX%s" % (RED, NOCOLOR)
        else:
            return "%sV%s" %(GREEN, NOCOLOR)
    elif req.status_code == 404:
            return "%sX%s" % (RED, NOCOLOR)
    else: 
        return ""

# Have I Been Pwned related
def hibp_get_cookies():
    HTTP_REQ = {}
    HTTP_REQ["url"] = "%s/%s" % (BASE_URL, "test@test.com")
    HTTP_REQ["user-agent"] = USER_AGENT
    #return http_query(1, HTTP_REQ)

# Query HIBP
def hibp_query(HTTP_REQ, append_url, user_account):
    HTTP_REQ["url"] = "%s/%s" % (BASE_URL, append_url)
    req = http_query(0, HTTP_REQ)

    if req.status_code == 200:
        # Parse results
        try:
            return json.loads(req.text)
        except ValueError as e:
            print e
    elif req.status_code == 429:
        print "[!]  HTTP 429 - Too many requests. Sleeping a bit..."
        sleep(1)
    elif req.status_code == 404:
        print "[-]  %sNo data (HTTP 404)%s" % (RED, NOCOLOR)
    else:
        print "[!]  HTTP error (code: %s)" % (req.status_code)

    return None

# Query Have I Been Powned for breached accounts
def hibp_query_breach(HTTP_REQ, user_account):
    print "[*] Looking for account in leak(s)"
    json_data = hibp_query(HTTP_REQ, "breachedaccount/%s" % (user_account), "")
    if json_data != None:
        NEEDED = ["Title", "BreachDate", "Domain", "DataClasses","IsVerified", "IsFabricated", "IsSensitive", "IsRetired", "IsRetired"]
        GRID_HEADERS = ["Title", "Date", "Domain", "Leaked data", "Verified", "Fabricated", "Sensitive", "Retired", "Spam"]

        GRID_DATA = parse_json(json_data, NEEDED)
        ## Refining
        # Order by date
        GRID_DATA.sort(key=lambda r: r[1], reverse=True)
        for g in GRID_DATA:
            g[3] = "\n".join(g[3])

        # Display
        display_data(GRID_DATA, GRID_HEADERS)

# Query Have I Been Powned for pasted accounts
def hibp_query_paste(HTTP_REQ, user_account):
    print "[*] Looking for account in paste(s)"
    json_data = hibp_query(HTTP_REQ, "pasteaccount/%s" % (user_account), "")
    if json_data != None:
        NEEDED = ["Source", "Id", "Title", "Date"]
        GRID_DATA = parse_json(json_data, NEEDED)
        ## Refining
        # Order by date
        GRID_DATA.sort(key=lambda r: r[3], reverse=True)
        for g in GRID_DATA:
            if g[0] == "Pastebin":
                g[1] = "https://www.pastebin.com/raw/%s" % (g[1])
                g[1] += " (%s)" % (check_pastebin(HTTP_REQ, g[1]))
        display_data(GRID_DATA, NEEDED)

## Generic functions

# Read file to a Python list
def read_file_2_list(filename):
    try:
        with open(filename, "r") as fin:
            return [l.rstrip() for l in fin.readlines()]
    except IOError as e:
        print "[!] Cannot open file \"%s\" (%s).\nExiting..." % (filename, e)
        sys.exit(1)

# SIGINT handler
def interruptHandler(signal, frame):
    print "\n[!] Interrupted by user.\nStopping..."
    sys.exit(0)

# Main
def main(args):
    # Set up HTTP_REQ
    HTTP_REQ = {}
    HTTP_REQ["user-agent"] = args.user
    HTTP_REQ["proxy"] = {} if (len(args.proxy) == 0) else {"https": args.proxy, "http": args.proxy}
    HTTP_REQ["time"] = args.t

    print "[-] Starting %s" % (sys.argv[0])
    print "[*]   User-Agent: %s" % (HTTP_REQ["user-agent"])
    print "[*]   Proxy: %s" % (HTTP_REQ["proxy"])
    print "[*]   Time: %ss.\n" % (HTTP_REQ["time"])

    # if user provided a file
    if args.f:
        emails = read_file_2_list(args.f)
    else:
        emails = {args.e}
    print "[*] Loaded %d email(s)\n" % (len(emails))

    # Loop through email(s)
    for email in emails:
        #cookies = hibp_get_cookies()
        print "\n[*] Results for \"%s%s%s\"\n" % (ORANGE, email, NOCOLOR)
        hibp_query_breach(HTTP_REQ, email)
        sleep(args.t)
        hibp_query_paste(HTTP_REQ, email)
        sleep(args.t)


# Parse arguments
def parse_args():
    parser = ArgumentParser(description="Python utility to query HaveIBeenPwned API", formatter_class=RawTextHelpFormatter)
    parser.add_argument("-e", required=False, metavar="email", help="Email to test for leakage/paste")
    parser.add_argument("-f", required=False, metavar="file", help="File with emails to test for leakage/paste")
    parser.add_argument("-t", required=False, metavar="time", default=DEFAULT_WAIT, type=int, help="Time to wait between requests (default: %ss.)" % DEFAULT_WAIT)
    parser.add_argument("--user", required=False, metavar="User-agent", default=USER_AGENT, help="Change default user-agent (default: %s)" % USER_AGENT)
    parser.add_argument("--proxy", required=False, metavar="proxy", default="", help="Proxy to perform HTTP requests (ie.: http://localhost:8080, socks://localhost:8080)")
    args = parser.parse_args()
   
    if (not args.e) and (not args.f):
        print "[!] %s requires either a single email (-e) or file with multiple emails (-m)\nExiting..." % (sys.argv[0])
        sys.exit(1)
    return args

if __name__ == "__main__":
    signal(SIGINT, interruptHandler)
    args = parse_args()
main(args)
