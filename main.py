import os
import subprocess
import re
import threading
import time
import sys
import sqlite3



def banner():
    font = """


███████╗███████╗██╗  ██╗    ██╗      ██████╗  ██████╗     ████████╗██████╗  █████╗  ██████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
██╔════╝██╔════╝██║  ██║    ██║     ██╔═══██╗██╔════╝     ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██║████╗  ██║██╔════╝ 
███████╗███████╗███████║    ██║     ██║   ██║██║  ███╗       ██║   ██████╔╝███████║██║     █████╔╝ ██║██╔██╗ ██║██║  ███╗
╚════██║╚════██║██╔══██║    ██║     ██║   ██║██║   ██║       ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██║██║╚██╗██║██║   ██║
███████║███████║██║  ██║    ███████╗╚██████╔╝╚██████╔╝       ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗██║██║ ╚████║╚██████╔╝
╚══════╝╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝  ╚═════╝        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝   by Sergio Iniguez 	
                                                                  
 """
    print(font)



def animate():
    chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"] 
    sys.stdout.write("\033[?25l") 
    try:
        i = 0
        while not done:
            sys.stdout.write(f"\r\033[94m{chars[i % len(chars)]}\033[0m Monitoring SSH Logs...")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
    finally:
        sys.stdout.write("\033[?25h")


failed_ips = {}
already_banned = set()

def check_root():
    if os.geteuid() != 0:
        print("\033[91m[-] Error: This script requires root privileges.\033[0m")
        print("Try executing: sudo python3 main.py")
        sys.exit(1)


def check_database():
    name = "iplist.sqlite"
    if not os.path.exists(name):
        open(name,"x")
        con = sqlite3.connect("iplist.sqlite")
        cur = con.cursor()
        cur.execute("CREATE TABLE whitelist(ip TEXT PRIMARY KEY)")
        cur.execute("CREATE TABLE blacklist(ip TEXT, user TEXT, time TEXT PRIMARY KEY)")
        con.close()
    

def add_ip_to_whitelist():
    ip = str(input("IP Address to add to the whitelist: "))
    con = sqlite3.connect("iplist.sqlite")
    cur = con.cursor()
    cur.execute("INSERT INTO whitelist VALUES (?)",(str(ip),))
    con.commit()
    con.close()

def add_ip_to_blacklist(ip, user, timestamp):
    con = sqlite3.connect("iplist.sqlite")
    cur = con.cursor()
    cur.execute("INSERT INTO blacklist VALUES (?,?,?)",(str(ip),str(user),timestamp))
    con.commit()
    con.close()

def extract_whitelist():
    con = sqlite3.connect("iplist.sqlite")
    cur = con.cursor()
    res = cur.execute("SELECT * FROM whitelist")
    whitelist = res.fetchall()
    con.close()
    return whitelist

def log_event(message, type="info"):
    sys.stdout.write("\r\033[K") 
    
    if type == "fail":
        print(f"[\033[91m!\033[0m] {time.strftime('%H:%M:%S')} - {message}")
    elif type == "success":
        print(f"[\033[92m+\033[0m] {time.strftime('%H:%M:%S')} - {message}")
    elif type == "ban":
        print(f"\033[41m\033[97m BANNED \033[0m {message}")
    else:
        print(f"[*] {message}")

def sshparameters(sourceip, sourceuser, timestamp, failed_ips, invaliduser):
    if invaliduser:
        log_event(f"[+] Failed authentication from {sourceip} with an invalid login user", "fail")
        subprocess.run(["/usr/bin/notify-send", "--icon=error", "SSH Log Tracker",f"Failed authentication from {sourceip} with an invalid login user"])

    else:
        log_event(f"[+] Failed authentication from {sourceip} to the user {sourceuser}","fail")
        subprocess.run(["/usr/bin/notify-send", "--icon=error", "SSH Log Tracker",f"Failed authentication from {sourceip} to the user {sourceuser}"])
    
    if sourceip in failed_ips:
        
        if timewindow(failed_ips[sourceip][0],timestamp):
            failed_ips[sourceip].append(timestamp)
        else:
            failed_ips[sourceip] = list()
    else:
        failed_ips[sourceip] = list()
        failed_ips[sourceip].append(timestamp)
    add_ip_to_blacklist(sourceip, sourceuser, timestamp)


def checkfailedIPs(failed_ips,sourceip):
    if sourceip in already_banned:
        return
    
    fails = failed_ips.get(sourceip, [])
    if len(fails) >= 3:
        already_banned.add(sourceip) 
        
        log_event(f"BANNED: Banning attack from IP: {sourceip}", "ban")
        banIP(sourceip)
    else:
        log_event(f"Attempt number {len(fails)} from {sourceip}", "info")


def timewindow(firsttimestamp, timestamp):
    final_difference = timestamp - firsttimestamp
    if final_difference < 300:
        return True
    else:
        return False



def extractlogs():
    
    process = subprocess.Popen(
        ["journalctl","-u", "ssh", "-f", "-n","0"],
        stdout=subprocess.PIPE,
        text=True
    )

    for line in process.stdout: #type: ignore
        if re.search("Failed password", line):
            ipregex = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
            sourceip = ipregex.group(0) #type: ignore
            timestamp = time.time()
            ip_in_whitelist = False
            for a in whitelist_cache:
                if sourceip == a[0]:
                    log_event(f"[+] The IP: {sourceip} is on the whitelist. \n [+] Skipping this attempt...")
                    ip_in_whitelist = True
            if ip_in_whitelist:
                continue
            if re.search("invalid user", line):
                sshparameters(sourceip,"Invalid",timestamp,failed_ips, True)

            else:
                sourceuser = line.split()[8]
                sshparameters(sourceip,sourceuser,timestamp,failed_ips, False)
                
            checkfailedIPs(failed_ips,sourceip)
            

def check_if_rule_exists(sourceip):
    code = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-p", "tcp", "--dport", "22", "-s", sourceip, "-j", "DROP"], capture_output=True, text=True)
    if code.returncode == 0:
        return True
    else:
        return False

def banIP(sourceip):
    if not check_if_rule_exists(sourceip):
        subprocess.run(["sudo", "iptables", "-t","filter","-I","INPUT","1","-p","tcp","--dport","22","-s",sourceip,"-j","DROP"])

thread1 = threading.Thread(target=extractlogs)


if __name__ == '__main__':
    try:
        check_root()
        banner()
        check_database()
        loop = True
        while loop:
            addIP = str(input("[+] Do you want to add an IP address to the whitelist (S/N)?: "))
            if addIP.upper() == "S":
                add_ip_to_whitelist()
            else:
                loop = False
        whitelist_cache = set(extract_whitelist())
        thread1.start()
        time.sleep(0.5)
        done = False
        animate()
    except KeyboardInterrupt:
        print("\n[X] Exiting tool...")
        sys.exit()
    