import argparse
import string
import sys
import subprocess
import plistlib
import os
import hashlib
from os.path import join, isdir
from threading import Thread

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

parser = argparse.ArgumentParser(description="Listen for new Jamf policy processes to determine insecure credential storage.")
parser.add_argument('--output', nargs='?', default="explorer_output", help='Folder to output results')

args = parser.parse_args()

if not isdir("/Library/Application Support/JAMF"):
    print("[!] Jamf Application Support folder not found... are you sure Jamf is installed?")
    sys.exit()

try:
    with open("/Library/Preferences/com.jamfsoftware.jamf.plist", "rb") as f:
        jss_prefs = plistlib.load(f) 
except Exception as e:
    print("[!] Jamf Preferences PLIST not found. Is Jamf enrolled correctly?")
    print(e)
    sys.exit()

print("[*] Determining privilege to Jamf temp directories.")
if os.access("/Library/Application Support/JAMF/tmp", os.R_OK):
    print("[*] We have access! Listening for scripts and EAs.")
    privileged_access = True
else:
    print("[*] Access denied. That's okay... listening for process arguments only")
    privileged_access = False

def tmp_listener():
    known = []
    known_filenames = []

    try:
        os.mkdir(args.output)
    except:
        pass

    while True:
        for file in os.listdir("/Library/Application Support/JAMF/tmp"):
            try:
                with open(join("/Library/Application Support/JAMF/tmp", file), "rb") as in_f:
                    file_data = in_f.read()
            except FileNotFoundError:
                continue

            hash = hashlib.md5(file_data).hexdigest()

            if hash not in known:
                path = join(args.output, file)

                with open(path, "wb") as out_f:
                    out_f.write(file_data)

                os.chmod(path, 0o777)
                known.append(hash)

                if file not in known_filenames:
                    print("[*] New File: %s (%s)" % (file, hash))
                    known_filenames.append(file)
                else:
                    print("[*] File Updated: %s (%s)" % (file, hash))


def args_listener():
    known = []

    while True:
        p = subprocess.Popen(["ps", "-ax", "-o", "command,"], stdout=subprocess.PIPE)
        results = p.stdout.read().splitlines()[1:]

        for res in results:
            cmd = res.decode('utf-8')
            if "jamf" in cmd.lower() and not cmd.startswith("(") and not cmd.endswith(")"):
                if cmd.startswith("sh -c PATH=$PATH:/usr/local/jamf/bin;"):
                    hash = hashlib.md5(res).hexdigest()

                    if hash not in known:
                        args = cmd.split(";")[1].strip().split("'")[1::2]

                        if args[0] == "/bin/sh":
                            args = args[1:]

                        print("[*] New Process: %s" % args[0])
                        print("    - Mount Point: %s" % args[1])
                        print("    - Computer Name: %s" % args[2])
                        print("    - Username: %s" % args[3])
                        print("    - Parameters:")
                        
                        for i, arg in enumerate(args[4:13]):
                            print("        %i: %s" % (i+4, arg))

                        known.append(hash)

threads = []

if privileged_access:
    threads.append(Thread(target=tmp_listener))

threads.append(Thread(target=args_listener))

for t in threads:
    t.start()

# Spin
while True:
    pass
