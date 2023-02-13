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

colour1 = 'green'
colour2 = 'yellow'
colour3 = 'blue'
colour4 = 'red'
colour5 = 'cyan'
colour6 = 'magenta'

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
   with open(file) as search:
      for line in search:
         if ("X-XSS-Protection".upper() in line.upper()):
            print(colored("X-XSS-Protection: Found, but depreciated", colour2))
            a = 1
   if a == 0:
      print(colored("X-XSS-Protection: Not Found", colour1))
   return
   
def scanpage(host):
   page = requests.get("https://" + host)
   os.system("echo " + str(page.headers) + " > securityheaders3.txt")
   return
   
def banner():
   print(colored("HTTP Depreciated Security Header Checker.", colour5))
   print("Target:", host)
   print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
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
print("HOST CHECK PORT 80:")
scanhost("securityheaders1.txt", host, 80)
parsehost("securityheaders1.txt")
print("WEBPAGE CHECK:")
scanpage(host)
parsehost("securityheaders3.txt")
print("\n")
banner()
print("HOST CHECK PORT 443:")
scanhost("securityheaders2.txt", host, 443)
parsehost("securityheaders2.txt")
print("WEBPAGE CHECK:")
parsehost("securityheaders3.txt")
print("\n")


   

