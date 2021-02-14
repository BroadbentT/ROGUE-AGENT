#!/usr/bin/python
# coding:UTF-8

# -------------------------------------------------------------------------------------
#                  PYTHON UTILITY SCRIPT FILE FOR ROP EXPLOITATION
#               BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Load any required imports and initialise program variables.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
from pwn import *						# pip install pwn
from termcolor import colored					# pip install termcolor

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0                                                                
# Details : Conduct simple and routine tests on user supplied arguements.   
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
    print("\nPlease run this python script as root...")
    exit(True)

if len(sys.argv) < 2:
    print("\nUse the command: python RopCrasher.py rop_file mode...")
    exit(True)

ropFile = sys.argv[1]

if os.path.exists(ropFile) == 0:
    print("\nFile " + ropFile + " was not found, did you spell it correctly?..")
    exit(True)

if len(sys.argv) < 3:
    print("\nUse the command: python RopCrasher.py rop_file mode...")
    exit(True)

ropMode = sys.argv[2]

chkMode = False
sysMode = ["critical", "debug", "error", "info", "notset", "warn", "warning"]

for mode in sysMode:
   if mode == ropMode:
      chkMode = True

if chkMode == False:
   print("Error - Recognised modes include: critical, debug, error, info, notset, warn and warning...")
   exit (True)

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0                                                                
# Details : Create function calls for main.
# Modified: N/A                                                              
# -------------------------------------------------------------------------------------

def header():
   print("[+] ROP PROGRAM:", end=' ')
   print(colored (ropFile.upper(),'white'))
   print("[+] DEBUG MODE :", end=' ')
   print(colored(ropMode.upper() + "",'white')) 

def message(message):
   print("[" + colored("-",'yellow') + "]", end=' ')
   print(colored(message,'white'))

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0                                                                
# Details : Examine file structure
# Modified: N/A                                                              
# -------------------------------------------------------------------------------------

header()
message("Setting up PWNLIB and examining file")

context.clear()
context(terminal=['tmux', 'new-window'])			# GDP in new window.
context.timeout = 3

info("------------------------------------- PERTINENT INFORMATION -------------------------------------")
info("If NIX is enabled, then the stack is read-only and you will need to use a return to libc exploit.")
info("If CANARY is enabled, then the program checks to see if the stack has been smashed.")
info("If FORTIFY is enabled, then the program checks for buffer overflow.")
info("If PIE is disabled, then the program memory locations will stay the same.")
#info("-------------------------------------------------------------------------------------------------")

# Automatic
context.binary    = ropFile

#manual
#context.arch      = ""
#context.os        = ""
#context.endian    = ""
#context.bits	   = ""

#others
#context.log_file  = 'log.txt'
context.log_level = ropMode
success("Successfully completed")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0                                                                
# Details : Stage one - Determine the segmentation-fault offset.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

message("Starting program")
target = ELF(ropFile)
shell  = process(target.path)

shell.recvuntil("\n")			# Enter program specific instructions code here

message("Crashing program")
crash = cyclic(1024)
shell.sendline(crash)
shell.wait()
success("Successfully completed")

message("Examining core dump file")
core = shell.corefile
rsp = core.rsp
offset = core.read(rsp, 4)
offset = cyclic_find(offset)
success("Successfully completed")

message("Exploit found @ " + str(offset) + " bytes")
success("Successfully completed")

#Eof
