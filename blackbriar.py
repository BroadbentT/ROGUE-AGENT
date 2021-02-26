#!/usr/bin/python
# coding:UTF-8

# -------------------------------------------------------------------------------------
#      PYTHON SCRIPT FILE FOR THE FORENSIC ANALYSIS OF WINDOWS MEMORY DUMP-FILES
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS AND CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar                                                                
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import shutil
import os.path
import fileinput
import linecache
import subprocess

from termcolor import colored					# pip install termcolor

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Black Briar                                                                
# Details : Conduct simple and routine tests on user supplied arguements.   
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
    print("\nPlease run this python script as root...")
    exit(True)

if len(sys.argv) < 2:
    print("\nUse the command python memory_master.py memorydump.ram\n")
    exit(True)

fileName = sys.argv[1]

if os.path.exists(fileName) == 0:
    print("\nFile " + fileName + " was not found, did you spell it correctly?")
    exit(True)

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Black Briar
# Details : Create function calls from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def padding(variable,value):
   while len(variable) < value:
      variable += " "
   return variable

def rpadding(variable,value):
   while len(variable) < value:
      temp = variable
      variable = "." + temp
   return variable
   
def parFile(variable):
   os.system("sed -i '/Failed/d' ./" + variable)
   return

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Black Briar
# Details : Initialise program variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

COL1 = 19
COL2 = 18
COL3 = 26
COL4 = 32
MAN1 = 0
MAN2 = 0
PRO  = "UNSELECTED         "
PR2  = "UNSELECTED         "
DA1  = "NOT FOUND          "
PI1  = "0                  "
PI2  = "0                  "
OFF  = "0                  "
PRM  = "UNSELECTED         "
DIR  = "WORKAREA           "
SAM = "0x0000000000000000"
SEC = "0x0000000000000000"
COM = "0x0000000000000000"
SOF = "0x0000000000000000"
SYS = "0x0000000000000000"
NTU = "0x0000000000000000"
HRD = "0x0000000000000000"
DEF = "0x0000000000000000"
BCD = "0x0000000000000000"
CUS = "0x0000000000000000"
NAM = "CUSTOM   "
HST = "BLANK              "
PRC = "0                  "
SVP = "0                  "
DA2 = "NOT FOUND          "
HIP = "000.000.000.000    "
POR = "000                "
MAX = 11 				# Display 0 - 9 users and >=10 triggers 9 to be displayed red.
X1 = " "*COL3
X2 = " "*COL4
US = [X1]*MAX
PA = [X2]*MAX

colour1 = 'yellow'
colour2 = 'green'
colour3 = 'white'

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar                                                                
# Details : Display universal header.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

os.system("clear")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Black Briar
# Details : Boot the system and populate program variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

print("Booting - Please wait...\n")

if not os.path.exists('WORKAREA'):
   os.mkdir("WORKAREA")

# -------------------------------------------------------------------------------------
# Grab image information.
# -------------------------------------------------------------------------------------

profiles = "NOT FOUND"

os.system("vol.py imageinfo -f '" + fileName + "' > image.log")
parFile("image.log")

with open("image.log") as search:
   for line in search:
      if "Suggested Profile(s) :" in line:
         profiles = line
      if "Number of Processors" in line:
         PRC = line
      if "Image Type (Service Pack) :" in line:
         SVP = line
      if "Image date and time :" in line:
         DA1 = line
      if "Image local date and time :" in line:
         DA2 = line

if profiles == "NOT FOUND":
   print("ERROR #001 - A windows profile was not found, see 'image.log' for further information.")
   exit(True)
   
#-------------------------------------------------------------------------------------
# Now search for appropriate profile.
#-------------------------------------------------------------------------------------

profiles = profiles.replace("Suggested Profile(s) :","")
profiles = profiles.replace(" ","")
profiles = profiles.split(",")
PRO = " --profile " + profiles[0]
PR2 = profiles[0]
if (PR2[:1] == "W") or (PR2[:1] == "V"):
   PR2 = padding(PR2,COL1)
   os.remove("image.log")
else:
   print("ERROR #002- A windows profile was not found, see 'image.log' for further information.")
   exit(True)

#-------------------------------------------------------------------------------------
# Find number of processors, service pack details, creation and local dates and times.
#-------------------------------------------------------------------------------------

PRC = PRC.replace("Number of Processors :","")
PRC = PRC.replace(" ","")
PRC = PRC.replace("\n","")
PRC = padding(PRC, COL3)

SVP = SVP.replace("Image Type (Service Pack) :","")
SVP = SVP.replace(" ","")
SVP = SVP.replace("\n","")
SVP = padding(SVP, COL1)

DA1 = DA1.replace("Image date and time :","")
DA1 = DA1.lstrip()
DA1 = DA1.rstrip("\n")
a,b,c = DA1.split()
DA1 = a + " @ " + b

DA2 = DA2.replace("Image local date and time :","")
DA2 = DA2.lstrip()
DA2 = DA2.rstrip("\n")
a,b,c = DA2.split()
DA2 = a + " " + b
DA2 = padding(DA2, COL1)

#-------------------------------------------------------------------------------------
# Grab hive information if available.
#-------------------------------------------------------------------------------------

os.system("vol.py -f '" + fileName + "'" + PRO + " hivelist > hivelist.txt")
parFile("hivelist.txt")
with open("hivelist.txt") as search:
   for line in search:
      if "\sam" in line.lower():
         SAM = line.split(None, 1)[0]
         SAM = padding(SAM, COL2)
      if "\security" in line.lower():
         SEC = line.split(None, 1)[0]
         SEC = padding(SEC, COL2)
      if "\software" in line.lower():
         SOF = line.split(None, 1)[0]
         SOF = padding(SOF, COL2)
      if "\system" in line.lower():
         SYS = line.split(None, 1)[0]
         SYS = padding(SYS, COL2)
      if "\components" in line.lower():
         COM = line.split(None, 1)[0]
         COM = padding(SYS, COL2)
      if "\\administrator\\ntuser.dat" in line.lower(): # \Administrator\NTUSER.DAT as there are usually multiple NTUSERS files. 
         NTU = line.split(None, 1)[0]
         NTU = padding(SYS, COL2)
      if "\hardware" in line.lower():
         HRD = line.split(None,1)[0]
         HRD = padding(HRD, COL2)
      if "\default" in line.lower():
         DEF = line.split(None,1)[0]
         DEF = padding(DEF, COL2)
      if "\\bcd" in line.lower():
         BCD = line.split(None,1)[0]
         BCD = padding(BCD, COL2)
os.remove("hivelist.txt")

#-------------------------------------------------------------------------------------
# Grab host name if avialable.
#-------------------------------------------------------------------------------------

os.system("vol.py -f '" + fileName + "'" + PRO + " printkey -o " + SYS + " -K 'ControlSet001\Control\ComputerName\ComputerName' > host.txt")
parFile("host.txt")
with open("host.txt") as search:
   wordlist = (list(search)[-1])
wordlist = wordlist.split()
HST = str(wordlist[-1])
if HST == "searched":					# Looks like a host name has not been found.
   HST = "NOT FOUND          "				# So set a defualt value.
else:
   HST = HST.encode(encoding='UTF-8',errors='strict')	# Deal with a encoding issue with hostname.
   HST = str(HST)
   HST = HST.replace("b'","")
   HST = HST.replace("\\x00'","")
   HST = padding(HST, COL1)
os.remove('host.txt')

#-------------------------------------------------------------------------------------
# Grab user information if available.
#-------------------------------------------------------------------------------------

os.system("vol.py hashdump -f '" + fileName + "'" + PRO + " -y " + SYS + " -s " + SAM + " >> hash.txt")
parFile("hash.txt")
with open("hash.txt") as search:
   count = 0
   for line in search:
      if line != "":
         catch = line.replace(":"," ")
         catch2 = catch.split()
         catch3 = catch2[3]
         PA[count] = catch3
         US[count] = catch2[0][:COL3-1] + " "
         US[count] = rpadding(US[count], COL3)
         count = count + 1				# 0 - 9 Users
         if count > MAX: count = MAX			# 10 - Maximum threshold reached for user display.
os.remove("hash.txt")

#-------------------------------------------------------------------------------------
# Grab local IP if alvailable.
#-------------------------------------------------------------------------------------

os.system("vol.py -f '" + fileName + "'" + PRO + " connscan > connscan.txt")
parFile("connscan.txt")
os.system("sed '1d' connscan.txt > conn1.txt")
os.system("sed '1d' conn1.txt > connscan.txt")
os.remove("conn1.txt")
os.system("cut -f 2 -d ' ' connscan.txt > conn1.txt")
os.system("strings conn1.txt | sort | uniq -c | sort -nr > connscan.txt")
os.system("sed '1d' conn1.txt > connscan.txt")
getip = linecache.getline('connscan.txt', 1)
if getip != "":
   getip = getip.split()
   getip = getip[0].replace(':',' ')  
   HIP = getip.rsplit(' ', 1)[0]
   POR = getip.rsplit(' ', 1)[1]
   HIP = padding(HIP, COL1)
   POR = padding(POR, COL1)
os.remove('connscan.txt')
os.remove('conn1.txt')

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Black Briar
# Details : Build the top half of the screen display as a function call.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def Display():
   print('\u2554' + ('\u2550')*36 + '\u2566' + ('\u2550')*33 + '\u2566' + ('\u2550')*61 + '\u2557')
   print('\u2551' + (" ")*15 + colored("SYSTEM",colour3) +  (" ")*15 + '\u2551' + (" ")*10 + colored("SYSTEM HIVES",colour3) + (" ")*11 + '\u2551' + (" ")*24 +  colored("USER INFORMATION",colour3) + (" ")*21 + '\u2551') 
   print('\u2560' + ('\u2550')*14 + '\u2564' + ('\u2550')*21 + '\u256C' + ('\u2550')*12 + '\u2564' + ('\u2550')*20 + '\u256C' + ('\u2550')*61 + '\u2563')
   
   print('\u2551' + " PROFILE      " + '\u2502', end=' ')
   if PR2 == "UNSELECTED         ":
      print(colored(PR2,colour2), end=' ')
   else:
      print(colored(PR2,colour1), end=' ')
   print('\u2551' + " SAM        " + '\u2502', end=' ')
   if SAM == "0x0000000000000000":
      print(colored(SAM,colour2), end=' ')
   else:
      print(colored(SAM,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[0].upper(),colour1), end=' ')
   print(colored(PA[0],colour1), end=' ')
   print('\u2551')
   
   print('\u2551' + " HOST NAME    " + '\u2502', end=' ')
   if HST == "NOT FOUND          ":
      print(colored(HST[:20],colour2), end=' ')
   else:
      print(colored(HST[:20],colour1), end=' ')
   print('\u2551' + " SECURITY   " + '\u2502', end=' ')
   if SEC == "0x0000000000000000":
      print(colored(SEC,colour2), end=' ')
   else:
      print(colored(SEC,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[1].upper(),colour1), end=' ')
   print(colored(PA[1],colour1), end=' ')
   print('\u2551')
   
   print('\u2551' + " SERVICE PACK " + '\u2502', end=' ')
   if SVP == "0                  ":
      print(colored(SVP,colour2), end=' ')
   else:
      print(colored(SVP,colour1), end=' ')
   print('\u2551' + " COMPONENTS " + '\u2502', end=' ')
   if COM == "0x0000000000000000":
      print(colored(COM,colour2), end=' ')
   else:
      print(colored(COM,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[2].upper(),colour1), end=' ')
   print(colored(PA[2],colour1), end=' ')
   print('\u2551')
   
   print('\u2551' + " TIME STAMP   " + '\u2502', end=' ')
   if DA2 == "NOT FOUND          ":
      print(colored(DA2,colour2), end=' ')
   else:
      print(colored(DA2,colour1), end=' ')
   print('\u2551' + " SOFTWARE   " + '\u2502', end=' ')
   if SOF == "0x0000000000000000":
      print(colored(SOF,colour2), end=' ')
   else:
      print(colored(SOF,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[3].upper(),colour1), end=' ')
   print(colored(PA[3],colour1), end=' ')
   print('\u2551')
   
   print('\u2551' + " LOCAL IP     " + '\u2502', end=' ')
   if HIP == "000.000.000.000    ":
      print(colored(HIP[:COL1],colour2), end=' ')
   else:
      print(colored(HIP[:COL1],colour1), end=' ')
   print('\u2551' + " SYSTEM     " + '\u2502', end=' ')
   if SYS == "0x0000000000000000":
      print(colored(SYS,colour2), end=' ')
   else:
      print(colored(SYS,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[4].upper(),colour1), end=' ')
   print(colored(PA[4],colour1), end=' ')
   print('\u2551')
   
   print('\u2551' + " LOCAL PORT   " + '\u2502', end=' ')
   if POR == "000                ":
      print(colored(POR[:COL1],colour2), end=' ')
   else:
      print(colored(POR[:COL1],colour1), end=' ')
   print('\u2551' + " NTUSER     " + '\u2502', end=' ')
   if NTU == "0x0000000000000000":
      print(colored(NTU,colour2), end=' ')
   else:
      print(colored(NTU,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[5].upper(),colour1), end=' ')
   print(colored(PA[5],colour1), end=' ')
   print('\u2551')
   
   print('\u2551' + " PID VALUE    " + '\u2502', end=' ')
   if PI1 == "0                  ":
      print(colored(PI1[:COL1],colour2), end=' ')
   else:
      print(colored(PI1[:COL1],'yellow'), end=' ')
   print('\u2551' + " HARDWARE   " + '\u2502', end=' ')
   if HRD == "0x0000000000000000":
      print(colored(HRD,colour2), end=' ')
   else:
      print(colored(HRD,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[6].upper(),colour1), end=' ')
   print(colored(PA[6],colour1), end=' ')
   print('\u2551')
   
   print('\u2551' + " OFFSET VALUE " + '\u2502', end=' ')
   if OFF == "0                  ":
      print(colored(OFF[:COL1],colour2), end=' ')
   else:
      print(colored(OFF[:COL1],'yellow'), end=' ')
   print('\u2551' + " DEFUALT    " + '\u2502', end=' ')
   if DEF == "0x0000000000000000":
      print(colored(DEF,colour2), end=' ')
   else:
      print(colored(DEF,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[7].upper(),colour1), end=' ')
   print(colored(PA[7],colour1), end=' ')
   print('\u2551')
   
   print('\u2551' + " PARAMETER    " + '\u2502', end=' ')
   if PRM == "UNSELECTED         ":
      print(colored(PRM[:COL1],colour2), end=' ')
   else:
      print(colored(PRM[:COL1],'yellow'), end=' ')
   print('\u2551' + " BOOT BCD   " + '\u2502', end=' ')
   if BCD == "0x0000000000000000":
      print(colored(BCD,colour2), end=' ')
   else:
      print(colored(BCD,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[8].upper(),colour1), end=' ')
   print(colored(PA[8],colour1), end=' ')
   print('\u2551')
   
   print('\u2551' + " DIRECTORY    " + '\u2502', end=' ')
   if DIR == "WORKAREA           ":
      print(colored(DIR[:COL1],colour2), end=' ')
   else:
      print(colored(DIR[:COL1],'yellow'), end=' ')
   print('\u2551' + " " + NAM[:9] + "  " + '\u2502', end=' ')
   if CUS == "0x0000000000000000":
      print(colored(CUS,colour2), end=' ')
   else:
      print(colored(CUS,colour1), end=' ')
   print('\u2551', end=' ')
   if US[10] != "":						# MAX user threshold reached.
      print(colored(US[9].upper(),'red'), end=' ')
      print(colored(PA[9],'red'), end=' ')
   else:
      print(colored(US[9].upper(),colour1), end=' ')
      print(colored(PA[9],colour1), end=' ')   
   print('\u2551')

   print('\u2560' + ('\u2550')*14 + '\u2567'+ ('\u2550')*21  + '\u2569' + ('\u2550')*12 + '\u2567' + ('\u2550')*20 + '\u2569' + ('\u2550')*61 + '\u2563')

# ----------------------------------------------------------------------------------------------------------------------------------------------------

   print('\u2551', end=' ')
   print(" "*7, end=' ')
   print(colored("SETTINGS",colour3), end=' ')
   print(" "*12, end=' ')
   print(colored("IDENTIFY",colour3), end=' ')
   print(" "*17, end=' ')
   print(colored("ANALYSE",colour3), end=' ')
   print(" "*24, end=' ')
   print(colored("INVESTIGATE",colour3), end=' ')
   print(" "*16, end=' ')
   print(colored("EXTRACT",colour3), end=' ')
   print(" "*3, end=' ')
   print('\u2551')

# ----------------------------------------------------------------------------------------------------------------------------------------------------

   print('\u2560' + ('\u2550'*132) + '\u2563')
   print('\u2551' + "(0) Re/Set PROFILE   (10) Users/Passwords   (20) SAM        (30) Re/Set   (40) PrintKey         (50) Desktop   (60) Malfind PID DIR " + '\u2551')
   print('\u2551' + "(1) Re/Set PID       (11) Default Password  (21) SECURITY   (31) Re/Set   (41) ShellBags        (51) Clipboard (61) Vaddump PID DIR " + '\u2551')
   print('\u2551' + "(2) Re/Set OFFSET    (12) Running Processes (22) COMPONENTS (32) Re/Set   (42) SlimCache Data   (52) Notepad   (62) Prodump PID DIR " + '\u2551')
   print('\u2551' + "(3) Re/Set PARAMETER (13) Hidden Processes  (23) SOFTWARE   (33) Re/Set   (43) Connections Scan (53) Explorer  (63) Memdump PID DIR " + '\u2551')
   print('\u2551' + "(4) Re/Set DIRECTORY (14) Running Services  (24) SYSTEM     (34) Re/Set   (44) Network Scan     (54) Files     (64) PARAMETER OFFSET" + '\u2551')
   print('\u2551' + "(5) Re/Set IP        (15) Command History   (25) NTUSER     (35) Re/Set   (45) Socket Scan      (55) SymLinks  (65) Timelines       " + '\u2551')
   print('\u2551' + "(6) Re/Set PORT      (16) Console History   (26) HARDWARE   (36) Re/Set   (46) Mutant Scan      (56) Drivers   (66) Screen Shots    " + '\u2551')
   print('\u2551' + "(7) Re/Set " + NAM[:9] + " (17) Cmdline Arguments (27) DEFUALT    (37) Re/Set   (47) DLL List         (57) SIDs      (67) MFT Table       " + '\u2551')
   print('\u2551' + "(8) Exit             (18) User Assist Keys  (28) BOOT BCD   (38) Re/Set   (48) Sessions         (58) EnvVars   (68) PCAP File       " + '\u2551')
   print('\u2551' + "(9) Clean/Exit       (19) Hive List         (29) " + NAM[:9] + "  (39) Re/Set   (49) PARAMETER Search (59) TrueCrypt (69) Bulk Extract    " + '\u2551')
   print('\u255A' + ('\u2550')*132 + '\u255D')

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Black Briar
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   os.system("clear")
   Display()
   selection=input("Please Select: ")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Lets the user select a new Windows profile.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='0':
      BAK = PRO
      MATCH = 0
      PRO = input("Please enter profile: ")
      if PRO == "":
         PRO = BAK      
      with open("profiles.txt") as search:
         line = search.readline()
         while line:
            line = search.readline()
            if PRO in line:
               MATCH = 1  
      if MATCH == 0:
         PRO = BAK
      else:
         PRO = " --profile " + PRO
         PR2 = PRO.replace(" --profile ","")
         PR2 = padding(PR2, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Allowd the user to set the PID value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '1':
      temp = input("Please enter PID value: ")
      if temp != '':
         PI1 = padding(temp, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Allows the user to set the OFFSET value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '2':
      temp = input("Please enter OFFSET value: ")
      if temp != '':
         OFF = padding(temp, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Allows the user to set the Parameter string.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '3':
      temp = input("Please enter parameter value: ")
      if temp != '':
         PRM = padding(temp,COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Allows the user to set the Parameter string.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '4':
      directory = input("Please enter new working directory value: ")
      if os.path.exists(directory):
         print("Directory already Exists....")
      else:
         if len(directory) > 0:
            os.mkdir(directory)
            DIR = directory
            DIR = padding(DIR, COL1)
            print("Working directory changed...")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Set host IP Value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '5':
      temp = input("Please enter IP value: ")
      if temp != '':
         HIP = padding(temp, COL1)
         MAN1 = 1

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Set host PORT Value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '6':
      temp = input("Please enter PORT value: ")
      if temp != '':
         POR = padding(temp, COL1)
         MAN2 = 1

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Rename CUSTOM hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '7':
      temp = input("Please enter HIVE name: ")
      if temp != '':
         NAM = padding(temp, 9)
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Exit the program, leaving files undeleted.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '8':
      exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Clean up system files and exit the program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '9':
      if os.path.exists('WORKAREA'):
         shutil.rmtree('WORKAREA')
      if os.path.exists('timeline.txt'):
         os.remove('timeline.txt')
      if os.path.exists('time.txt'):
         os.remove('time.txt')
      if os.path.exists('mfttable.txt'):
         os.remove('mfttable.txt')
      exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Dumps the SAM file hashes for export to hashcat.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '10':
      if SAM == "0x0000000000000000":
         print(colored("SAM HIVE missing - its not possible to extract the hashes...",colour2))
      else:
         os.system("vol.py -f '" + fileName + "'" + PRO + " hashdump -y " + SYS + " -s " + SAM + " > sam.tmp")
         parFile("sam.tmp")
         catFile("sam.tmp")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Display any LSA secrets
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '11':
      os.system("vol.py -f '" + fileName + "'" + PRO + " lsadump | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows running processes and provides a brief analyse.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
      os.system("vol.py -f '" + fileName + "'" + PRO + " psscan | more")
      os.system("vol.py -f '" + fileName + "'" + PRO + " psscan --output greptext > F1.txt")
      os.system("tail -n +2 F1.txt > F2.txt")
      os.system("sed -i 's/>//g' F2.txt")
      with open("F2.txt") as read1:
         for line in read1:
            for word in line.split('|'):
                output = subprocess.check_output("echo " + word + " >> F3.txt", shell=True)
      os.system("tail -n +2 F3.txt > F4.txt")
      os.system("wc -l F2.txt > NUM.txt")
      NUMLINES = open("NUM.txt").readline().replace(' F2.txt','') 
      COUNT = int(NUMLINES)
      print("\n[1].\tThere were",COUNT,"processes running at the time of the memory dump.\n")
      read2 = open('PID.txt','w')
      read3 = open('PPID.txt','w')
      with open('F4.txt') as read4:
         while COUNT > 0:
            A = read4.readline()
            B = read4.readline() # Executable name
            C = read4.readline().rstrip('\n') # PI1
            print(C, file=read2)
            D = read4.readline().rstrip('\n') # OFF             
            print(D, file=read3)		
            E = read4.readline()
            G = read4.readline()
            H = read4.readline() # blank
            COUNT = (COUNT-1)
      read2.close() # required
      read3.close() # required
      os.remove('F1.txt')
      os.remove('F2.txt')
      os.remove('F3.txt')
      os.remove('F4.txt')
      os.system("echo 'comm -13 <(sort -u PID.txt) <(sort -u PPID.txt) > SUSPECT.txt' > patch.sh")
      os.system("bash patch.sh")
      os.system("sort -n SUSPECT.txt > SUSPECT2.txt")
      print("[2].\tAnalyse of these processes reveals that:")
      with open('SUSPECT2.txt') as read5:
         line = read5.readline().rstrip('\n')
         while line != "":
            if line != "0":
               print("\tParent process PPID",line,"does not have a process spawn! and should be investigated further...")
            line = read5.readline().strip('\n')
      os.remove("patch.sh")
      os.remove("PID.txt")
      os.remove("PPID.txt")
      os.remove("NUM.txt")
      os.remove("SUSPECT.txt")
      os.remove("SUSPECT2.txt")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows hidden processes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '13':
      os.system("vol.py -f '" + fileName + "'" + PRO + " psxview | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows running services.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      os.system("vol.py -f '" + fileName + "'" + PRO + " svcscan | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Last commands run.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      os.system("vol.py -f '" + fileName + "'" + PRO + " cmdscan")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Last commands run.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '16':
      os.system("vol.py -f '" + fileName + "'" + PRO + " consoles")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Last commands run.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      os.system("vol.py -f '" + fileName + "'" + PRO + " cmdline")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Show userassist key values.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
      os.system("vol.py -f '" + fileName + "'" + PRO + " userassist")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Hivelist all
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      os.system("vol.py -f '" + fileName + "'" + PRO + " hivelist")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows SAM hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      if (SAM == "0x0000000000000000"):
         print(colored("SAM Hive missing - it is not possible to extract data...",colour2))
      else:
         os.system("vol.py -f '" + fileName + "'" + PRO + " hivedump -o " + SAM + " | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows SECURITY hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='21':
      if (SEC == "0x0000000000000000"):
         print(colored("SECURITY Hive missing - it is not possible to extract data...",colour2))
      else:
         os.system("vol.py -f " + fileName + PRO + " hivedump -o " + SEC + " | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows COMPONENTS hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='22':
      if (COM == "0x0000000000000000"):
         print(colored("COMPONENTS Hive missing - it is not possible to extract data...",colour2))
      else:
         os.system("vol.py -f '" + fileName + "'" + PRO + " hivedump -o " + COM + " | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows SOFTWARE hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='23':
      if (SOF == "0x0000000000000000"):
         print(colored("SOFTWARE Hive missing - it is not possible to extract data...",colour2))
      else:
         os.system("vol.py -f '" + fileName + "'" + PRO + " hivedump -o " + SOF + " | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows SYSTEM hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='24':
      if (SYS == "0x0000000000000000"):
         print(colored("SYSTEM Hive missing - it is not possible to extract data...",colour2))
      else:
         os.system("vol.py -f '" + fileName + "'" + PRO + " hivedump -o " + SYS + " | more")
      input("\nPress ENTER to continue...")    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows NTUSER hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='25':
      if (NTU == "0x0000000000000000"):
         print(colored("NTUSER (Administrator) Hive missing - it is not possible to extract data...",colour2))
      else:
         os.system("vol.py -f '" + fileName + "'" + PRO + " hivedump -o " + NTU + " | more")
      input("\nPress ENTER to continue...") 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows HARDWARE hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='26':
      if (HRD == "0x0000000000000000"):
         print(colored("HARDWARE Hive missing - it is not possible to extract data...",colour2))
      else:
         os.system("vol.py -f '" + fileName + "'" + PRO + " hivedump -o " + HRD + " | more")
      input("\nPress ENTER to continue...")     

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows DEFUALT hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='27':
      if (DEF == "0x0000000000000000"):
         print(colored("DEFUALT Hive missing - it is not possible to extract data...",colour2))
      else:
         os.system("vol.py -f '" + fileName + "'" + PRO + " hivedump -o " + DEF + " | more")
      input("\nPress ENTER to continue...")   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows BOOT BCD hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='28':
      if (BCD == "0x0000000000000000"):
         print(colored("BOOT BCD Hive missing - it is not possible to extract data...",colour2))
      else:
         os.system("vol.py -f '" + fileName + "'" + PRO + " hivedump -o " + BCD + " | more")
      input("\nPress ENTER to continue...")   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows CUSTOM hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='29':
      if (CUS == "0x0000000000000000"):
         print(colored(NAM + " missing - it is not possible to extract data...",colour2))
      else:
         os.system("vol.py -f '" + fileName + "'" + PRO + " hivedump -o " + CUS + " | more")
      input("\nPress ENTER to continue...")  

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Change SAM via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '30':
      temp = input("Please enter SAM value: ")
      if temp != "":
         SAM = padding(temp, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Change SECURITY via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '31':
      temp = input("Please enter SECURITY value: ")
      if temp != "":
         SEC = padding(temp, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Change COMPENENTS via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '32':
      temp = input("Please enter COMPENENTS value: ")
      if temp != "":
         COM = padding(temp, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Change SOFTWARE via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '33':
      temp = input("Please enter SOFTWARE value: ")
      if temp != "":
         SOF = padding(temp, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Change SYSTEM via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '34':
      temp = input("Please enter SYSTEM value: ")
      if temp != "":
         SYS = padding(temp, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Change NTUSER via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '35':
      temp = input("Please enter NTUSER value: ")
      if temp != "":
         NTU = padding(temp, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Change HARDWARE via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '36':
      temp = input("Please enter HARDWARE value: ")
      if temp != "":
         HRD = padding(temp, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Change DEFAULT via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '37':
      temp = input("Please enter DEFUALT value: ")
      if temp != "":
         DEF = padding(temp, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Change BOOT BCD via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      temp = input("Please enter BOOT BCD value: ")
      if temp != "":
         BCD = padding(temp, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Change BOOT BCD via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '39':
      temp = input("Please enter " + NAM.rstrip() + " value: ")
      if temp != "":
         CUS = padding(temp, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Print specified key from hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='40':
      KEY = input("Please enter the key value in quotes: ")
      if KEY != "":
         os.system("vol.py -f '" + fileName + "'" + PRO + " printkey -K " + KEY)
         input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shellbags.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='41':
      os.system("vol.py -f '" + fileName + "'" + PRO + " shellbags | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shellbags.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='42':
      os.system("vol.py -f '" + fileName + "'" + PRO + " shimcache | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Analyse the NETWORK connections.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='43':
      os.system("vol.py -f '" + fileName + "'" + PRO + " connscan | more")
      input("\nPress ENTER to continue...") 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Analyse the NETWORK traffic.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='44':
      os.system("vol.py -f '" + fileName + "'" + PRO + " netscan | more")
      input("\nPress ENTER to continue...") 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Analyse the NETWORK sockets.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='45':
      os.system("vol.py -f '" + fileName + "'" + PRO + " sockets | more")
      input("\nPress ENTER to continue...") 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Finds Mutants.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='46':
      os.system("vol.py -f '" + fileName + "'" + PRO + " mutantscan | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - List dll's.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='47':
      os.system("vol.py -f '" + fileName + "'" + PRO + " dlllist | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows sessions history.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='48':
      os.system("vol.py -f '" + fileName + "'" + PRO + " sessions | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Search image for occurences of string.
# Modified: N/A
# ------------------------------------------------------------------------------------- 
   
   if selection =='49':
      os.system("vol.py -f '" + fileName + "'" + PRO + " pslist | grep " + PRM)
      os.system("vol.py -f '" + fileName + "'" + PRO + " filescan | grep " + PRM)
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows desktop information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='50':
      os.system("vol.py -f '" + fileName + "'" + PRO + " deskscan | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows clipboard information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='51':
      os.system("vol.py -f '" + fileName + "'" + PRO + " clipboard | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows notepad information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='52':
      os.system("vol.py -f '" + fileName + "'" + PRO + " notepad | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows IE history.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='53':
      os.system("vol.py -f '" + fileName + "'" + PRO + " iehistory | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows files.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='54':
      os.system("vol.py -f '" + fileName + "'" + PRO + " filescan | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows symlinks.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='55':
      os.system("vol.py -f '" + fileName + "'" + PRO + " symlinkscan | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Shows drivers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='56':
      os.system("vol.py -f '" + fileName + "'" + PRO + " devicetree | more")
      os.system("vol.py -f '" + fileName + "'" + PRO + " driverscan | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Display all SID's.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='57':
      os.system("vol.py -f '" + fileName + "'" + PRO + " getsids | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Display environmental variables.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='58':
      os.system("vol.py -f '" + fileName + "'" + PRO + " envars | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - TrueCrypt info
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='59':
      os.system("vol.py -f '" + fileName + "'" + PRO + " truecryptsummary | more")
      os.system("vol.py -f '" + fileName + "'" + PRO + " truecryptmaster | more")
      os.system("vol.py -f '" + fileName + "'" + PRO + " truecryptpassphrase | more")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Finds Malware.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='60':
      os.system("vol.py -f '" + fileName + "'" + PRO + " malfind -p " + PI1 + " -D " + DIR)
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected -  Vad dump PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='61':
      os.system("vol.py -f '" + fileName + "'" + PRO + " vaddump -p " + PI1 + " --dump-dir " + DIR)
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Proc dump PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      os.system("vol.py -f '" + fileName + "'" + PRO + " procdump  -p " + PI1 + " --dump-dir " + DIR)
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Memory dump PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='63':
      os.system("vol.py -f '" + fileName + "'" + PRO + " memdump  -p " + PI1 + " --dump-dir " + DIR)
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Extract a single file based on physical OFFSET.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='64':
      os.system("vol.py -f '" + fileName + "'" + PRO + " dumpfiles -Q " + OFF + " -D " + DIR + " -u -n")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Extract timeline.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='65':
      os.system("vol.py -f '" + fileName + "'" + PRO + " timeliner --output-file timeline.txt")
      os.system("vol.py -f '" + fileName + "'" + PRO + " shellbags --output-file time.txt")
      print("A timeline has sucessfully been exported...")
      input("\nPress ENTER to continue...")

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Extract windows screenshots.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='66':
      os.system("vol.py -f '" + fileName + "'" + PRO + " -D " + DIR + " screenshot")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Extract the MFT table and it contents.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='67':
      os.system("vol.py -f '" + fileName + "'" + PRO + " mftparser --output-file mfttable.txt")
      print("The MFT has sucessfully been exported to mfttable.txt...")
      os.system("strings mfttable.txt | grep '0000000000:' > count.txt")
      fileNum = sum(1 for line in open('count.txt'))
      print("The table contains " + str(fileNum) + " local files < 1024 bytes in length.")
      os.remove("count.txt")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Bulk Extract all known files.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='68':
      os.system("bulk_extractor -x all -e net -o " + DIR + " '" + fileName + "'")
      input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Black Briar
# Details : Menu option selected - Bulk Extract all known files.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='69':
      os.system("bulk_extractor -o " + DIR + " '" + fileName + "'")
      input("\nPress ENTER to continue...")

#Eof...
