#!/usr/bin/env python
# Inspired by https://github.com/thewhiteh4t/pwnedOrNot
import argparse
import requests
import cfscrape
import json

# Constant
BASE_URL="https://haveibeenpwned.com/api/v2/breachedaccount"
USER_AGENT="Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0"

def make_query():
    # Request through cfscrape (Cloud-flare)
    if cfscrape:
        return cfscrape.get_tokens(HTTP_REQ["url"], user_agent=HTTP_REQ["user-agent"])
    else: # Normal request
        proxy = {} # {'http': "socks://127.0.0.1:8181"}
        headers = {
            "User-Agent": "%s" % (HTTP_REQ["user-agent"]),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept_language": "en-US,en;q=0.5",
            "Accept_encoding": "gzip, deflate, br"
        }
        return requests.get(HTTP_REQ["url"], headers=headers, proxy=HTTP_REQ["proxy"])

def http_query(csfscrape, HTTP_REQ):
    try:
        return make_query(csfscrape, HTTP_REQ)
    except requests.exceptions.HTTPError as e:
        print "[!] Exception while performing HTTP request"
        return None

# Have I Been Pwned related
def hibp_get_cookies():
    HTTP_REQ = {}
    HTTP_REQ["url"] = "%s/%s" % (BASE_URL, "test@test.com")
    HTTP_REQ["user-agent"] = USER_AGENT
    return http_query(1, HTTP_REQ)

def hibp_query_breach():
    HTTP_REQ = {}
    HTTP_REQ["url"] = "%s/%s" % (BASE_URL, "contact@contact.com")
    HTTP_REQ["user-agent"] = USER_AGENT
    HTTP_REQ["proxy"] = ""
    req = http_query(1, HTTP_REQ)

    print req.status_code
    if req.status_code == 200:
        print "OK"
    else:
        print "error"
        print req.text

# Main
def main():
    cookies = hibp_get_cookies()

# Parse arguments
def parse_args():
    parser = argparse.ArgumentParser(description="")

if __name__ == "__main__":
    query_breach()
