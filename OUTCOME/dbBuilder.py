#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#         PYTHON3 SCRIPT FILE FOR THE REMOTE ANALYSIS OF COMPUTER NETWORKS
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

import os
import sys
import sqlite3

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TREADSTONE                                                             
# Details : Check running as root 
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
   print("\n[*] Please run this python3 script as root...")
   exit(1)

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Create rogue agent database
# Modified: N/A
# -------------------------------------------------------------------------------------

os.system("rm RA.db")
conn = sqlite3.connect('RA.db')

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Create rogue agent database tables
# Modified: N/A
# -------------------------------------------------------------------------------------

# OSF
# COM
# DNS
# TIP
# POR
# PTS
# WEB
# WAF
# HST
# CSP
# XOP
# CON
# USR
# PAS
# NTM
# TGT
# DOM
# SID
# SDM
# FIL
# TSH
# UN1
# UN2
# UN3
# UN4

# RU1QVFkK = EMPTY
# VU5LTk9XTgo= = UNKNOWN

conn.execute('''CREATE TABLE REMOTETARGET
         (IDS INT PRIMARY KEY	NOT NULL,
         OSF		TEXT	NOT NULL,
         COM		TEXT	NOT NULL,
         DNS		TEXT	NOT NULL,
         TIP		TEXT	NOT NULL,
         POR		TEXT	NOT NULL,
         PTS		TEXT	NOT NULL,
         WEB		TEXT	NOT NULL,
         WAF		TEXT	NOT NULL,
         HST		TEXT	NOT NULL,
         CSP		TEXT	NOT NULL,
         XOP		TEXT	NOT NULL,
         CON		TEXT	NOT NULL,
         USR		TEXT	NOT NULL,
         PAS		TEXT	NOT NULL,
         NTM		TEXT	NOT NULL,
         TGT		TEXT	NOT NULL,
         DOM		TEXT	NOT NULL,
         SID		TEXT	NOT NULL,
         SDM		TEXT	NOT NULL,
         FIL		TEXT	NOT NULL,
         TSH		TEXT	NOT NULL,
         UN1		TEXT	NOT NULL,
         UN2		TEXT	NOT NULL,
         UN3		TEXT	NOT NULL,
         UN4		TEXT	NOT NULL);''')
        
conn.execute("INSERT INTO REMOTETARGET (IDS,OSF,COM,DNS,TIP,POR,PTS,WEB,WAF,HST,CSP,XOP,CON,USR,PAS,NTM,TGT,DOM,SID,SDM,FIL,TSH,UN1,UN2,UN3,UN4) \
      VALUES (1, 'RU1QVFkK', 'RU1QVFkK', 'RU1QVFkK', 'RU1QVFkK', 'RU1QVFkK', 'RU1QVFkK', 'RU1QVFkK', 'VU5LTk9XTgo=','VU5LTk9XTgo=','VU5LTk9XTgo=','VU5LTk9XTgo=','VU5LTk9XTgo=','Cg==', 'Cg==', 'RU1QVFkK', 'RU1QVFkK', 'RU1QVFkK', 'RU1QVFkK', 'RU1QVFkK', 'RU1QVFkK', 'RU1QVFkK','RU1QVFkK','RU1QVFkK','RU1QVFkK','RU1QVFkK')");

conn.commit()
conn.close()

#EoF
