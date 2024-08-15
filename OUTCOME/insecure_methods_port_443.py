#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#          PYTHON SCRIPT FILE FOR THE CONFIRMATION OF HTTP SECURITY METHODS
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
colour6 = 'magenta'

method_list = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE']

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
   os.system("nmap -p " + str(port) + " --script=http-methods -oN " + filename + " " + host + " 2>&1 > scan.tmp")
   return   

def parsehost(file):
   a = 0
   b = 0
   c = 0
   d = 0
   e = 0
   f = 0
   g = 0
   h = 0
   with open(file) as search:
      for line in search:
         if ("GET".upper() in line.upper()): 
            print(colored("GET: Found", colour1))
            a = 1
         if ("HEAD".upper() in line.upper()): 
            print(colored("HEAD: Found", colour4))
            b = 1
         if ("POST".upper() in line.upper()): 
            print(colored("POST: Found", colour1))
            c = 1
         if ("PUT".upper() in line.upper()): 
            if d != 1:
               print(colored("PUT: Found", colour4)) 
            d = 1
         if ("DELETE".upper() in line.upper()): 
            if e != 1:
               print(colored("DELETE: Found", colour4)) 
            e = 1
         if ("CONNECT".upper() in line.upper()): 
            if f !=1 :
               print(colored("CONNECT: Found", colour4)) 
            f =1
         if ("OPTIONS".upper() in line.upper()): 
            print(colored("OPTIONS: Found", colour5)) 
            g = 1
         if ("TRACE".upper() in line.upper()): 
            if h != 1:
               print(colored("TRACE: Found", colour4)) 
            h = 1  
   if a == 0:
      print(colored("GET: Not Found", colour2))
   if b == 0:
      print(colored("HEAD: Not Found", colour2))
   if c ==  0:
      print(colored("POST: Not Found", colour2))
   if d == 0:
      print(colored("PUT: Not Found", colour2))        
   if e == 0:
      print(colored("DELETE: Not Found", colour2))        
   if f == 0:
      print(colored("CONNECT: Not Found", colour2))        
   if g == 0:
      print(colored("OPTIONS: Not Found", colour2))        
   if h == 0:
      print(colored("TRACE: Not Found", colour2))       
   return
   
def scanhttp(host):
   for method in method_list:
      req = requests.request(method, "https://" + host, verify=False)
      print(colored(method, colour6), end=' ')
      print(colored(req.status_code, colour6), end=' ')
      print(colored(req.reason, colour6)) 
   return
   
def scanhttps(host):
   for method in method_list:
      req = requests.request(method, "https://" + host, verify=False)
      print(colored(method, colour6), end=' ')
      print(colored(req.status_code, colour6), end=' ')
      print(colored(req.reason, colour6))     
   return
   
def banner():
   print(colored("HTTP Insecure Methods Checker.", colour5))
   print("Target:", host)   
   print("- - - - - - - - - - - - - - - - - - - - - - - -")   
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
   print("HOST CHECK PORT 443:")
   scanhost("insecuremethods2.tmp", host, 443)
   parsehost("insecuremethods2.tmp")
except:
   print("Port 433 potentially not in use...")   
try:
   print("WEBPAGE CHECK:")
   scanhttps(host)
except:
   print("Port 433 potentially not in use...")
print("\n")
