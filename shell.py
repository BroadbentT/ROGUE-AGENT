#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#                  PYTHON SCRIPT FILE FOR THE CREATION OF A REVERSE SHELL
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

os.system("clear")
os.system("xdotool key Alt+Shift+S; xdotool type 'REVERSE SHELL'; xdotool key Return")
os.system("pyfiglet 'REVERSE SHELL'")
    
# -------------------------------------------------------------------------------------

print (colored("USE THE FOLLOWING COMMANDS TO STABALISE THE SHELL IF NECESSARY..\n",colour3))
print (colored("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'", colour1))
print (colored("Ctrl Z", colour1))
print (colored("stty raw -echo", colour1))
print (colored("fg", colour1))
print (colored("export TERM=xterm\n", colour1))

os.system("rlwrap nc -nvlp 1234")

