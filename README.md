
# Note
recommend using the python one.

SHS is not fully working and some function may not work properly, if you achieve/got an error with this code.

contact me: sunshinexjuhari@protonmail.com

# BF-WiFi

Hey there! This Python script is like a available Swiss army knife for managing WiFi stuff in your pc or computer, particularly if it's jogging Linux. With this script, you can do things like scanning for close by WiFi networks, seeking to crack passwords (yeah, it is known as bruteforcing), and connecting to WiFi networks.

**What it does:**

1. **Scanning WiFi Networks:**
   - Ever wanted to know what WiFi networks are floating around you? Well, this feature does precisely that! It'll show you all the close by WiFi networks it may find and tell you stuff like their names (SSID), in which they're hanging out (BSSID), how suitable their indicators are, and whether they are locked up tight (encryption status).

2. **Bruteforcing WiFi:**
   - Okay, so you realize those WiFi networks that have passwords? This function takes a shot at guessing those passwords. It's like trying each key within the international until you discover the one that unlocks the WiFi. It makes use of a few fancy gear known as `airmon-ng`, `wash`, `airodump-ng`, and `aircrack-ng` to do its factor. If it is a hit, it will even spill the beans and let you know the WiFi network's name (SSID) and password.

3. **Connecting to WiFi:**
   - Ever desired to leap on a particular WiFi community but didn't have the password? This function lets you do just that! Just supply it the name of the WiFi community (SSID) and the password, and it's going to paintings its magic to get you connected. It makes use of a device called `nmcli` to make the relationship occur.

**How to Use it:**

1. **Scanning WiFi Networks:**
   - Just kind `test` and hit Enter. It'll exit and discover all the nearby WiFi networks for you.

2. **Bruteforcing WiFi:**
   - Type `bruteforce [SSID]` and hit Enter. Replace `[SSID]` with the name of the WiFi network you need to crack.

3. **Connecting to WiFi:**
   - Type `connect [SSID]:[password]` and hit Enter. Replace `[SSID]` with the name of the WiFi network you want to hook up with, and `[password]` with the password for that community.

**A Quick Note:**
- Make certain your computer or computer is running Linux earlier than you dive into the usage of this script.
- Some of the instructions it makes use of, like `sudo` and `nmcli`, might need greater permissions or setup.
- And recollect, best use this script on WiFi networks you are allowed to debris with. Hacking into someone else's WiFi without permission is a huge no-no!

