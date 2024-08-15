#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#          PYTHON SCRIPT FILE FOR THE CONFIRMATION OF HTTP SECURITY HEADERS
#                       BY TERENCE BROADBENT BSc CYBER SECURITY
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                               
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import requests

from termcolor import colored # pip3 install termcolor  

# Supress only InsecureRequestWarning
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

colour1 = 'green'
colour2 = 'yellow'
colour3 = 'blue'
colour4 = 'red'
colour5 = 'cyan'

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0                                                               
# Details : Conduct simple and routine tests on any user supplied arguements.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
   print("\nPlease run this python script as root...")
   exit(True)

if len(sys.argv) < 2:
   print("Use the command python3 securityheaders.py pentestpeople.co.uk...")
   exit()
host = sys.argv[1]

# os.system("xdotool key Alt+Shift+S; xdotool type 'HTTP SECURITY HEADERS'; xdotool key Return")
    
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Create functional subroutine calls from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def scanhost(filename, host, port):
   os.system("nmap -p " + str(port) + " --script=http-security-headers -oN " + filename + " " + host + " 2>&1 > scan.tmp")
   return   

def parsehost(file):
   a = 0
   b = 0
   c = 0
   d = 0
   with open(file) as search:
      for line in search:
         if ("Strict-Transport-Security".upper() in line.upper()): 
            print(colored("Strict-Transport-Security: Found", colour1))
            a = 1
         if ("Content-Security-Policy".upper() in line.upper()): 
            print(colored("Content-Security-Policy: Found", colour1))
            b = 1
         if ("X-Frame-Options".upper() in line.upper()): 
            print(colored("X-Frame-Options: Found", colour1))
            c = 1
         if ("X-Content-Type-Options".upper() in line.upper()): 
            print(colored("X-Content-Type-Options: Found", colour1)) 
            d =1
   if a == 0:
      print(colored("Strict-Transport-Security: Not Found", colour4))
   if b == 0:
      print(colored("Content-Security-Policy: Not Found", colour4))
   if c ==  0:
      print(colored("X-Frame-Options: Not Found", colour4))
   if d == 0:
      print(colored("X-Content-Type-Options: Not Found", colour4))  
   return
   
def scanpage(host):
   page = requests.get("http://" + host, verify=False)
   os.system("echo " + str(page.headers) + " > securityheaders3.tmp")
   return
   
def banner():
   print(colored("HTTP Security Header Checker.", colour5))
   print("Target:", host)   
   print("- - - - - - - - - - - - - - - - - - - - - - -")   
   return
   
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : MAIN PROGRAM.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

# os.system("clear")
banner()
try:
   print("HOST CHECK PORT 80:")
   scanhost("securityheaders1.txt", host, 80)
   parsehost("securityheaders1.txt")
except:
   print("Port 80 potentially not in use...")
try:   
   print("WEBPAGE CHECK:")
   scanpage(host)
   parsehost("securityheaders3.tmp")
except:
   print("Port 80 potentially not in use...")
print("\n")
