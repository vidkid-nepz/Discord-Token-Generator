import pyautogui as ca
import os
import asyncio
import requests
import random
import string
import json
import re
import socket
import httpx
import base64
import tls_client
import time
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from dateutil.parser import isoparse
from colorama import Fore, Style, init
from pystyle import Colorate, Colors, Center
import websocket
from notifypy import Notify
from playwright.async_api import async_playwright, Page, Browser, BrowserContext
from hcaptcha_challenger import AgentV, AgentConfig, CaptchaResponse
import logging
import multiprocessing
from typing import Optional, Dict, List
from dataclasses import dataclass
from pathlib import Path
import traceback

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress aiohttp unclosed session warnings
import warnings
warnings.filterwarnings("ignore", message="unclosed", category=ResourceWarning)
warnings.filterwarnings("ignore", message="Unclosed client session")
warnings.filterwarnings("ignore", message="Unclosed connector")

# Suppress Pydantic validation errors from hcaptcha_challenger library
# These are library bugs when hCaptcha sends malformed payloads
import logging as _logging
_logging.getLogger("asyncio.events").setLevel(_logging.CRITICAL)  # Hide asyncio error traces
_logging.getLogger("pydantic").setLevel(_logging.WARNING)

init(autoreset=True)

with open('config.json', 'r') as f:
    config = json.load(f)

INCOGNITO_API_URL = config.get("mail_api", "https://api.incognitomail.co/")
INCOGNITO_DOMAIN = config.get("mail_domain", "vorlentis.xyz")

USE_HUMANIZER = False
USE_VPN = False 

@dataclass
class ProxyConfig:
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    protocol: str = 'http'

class ProxyPool:
    """Proxy pool with round-robin rotation - EXACT COPY from UK.py"""
    def __init__(self, proxy_list: List[Dict[str, str]], manager):
        self.proxies = manager.list()
        self.lock = manager.Lock()
        self.proxy_usage_count = manager.dict()
        self.current_proxy_index = manager.Value('i', 0)
        self._load_proxies(proxy_list)
        
    def _load_proxies(self, proxy_list: List[Dict[str, str]]):
        logger.info(f"[DEBUG] Loading {len(proxy_list)} proxies...")
        for i, proxy in enumerate(proxy_list):
            try:
                logger.info(f"[DEBUG] Processing proxy {i+1}: {proxy}")
                # Handle different proxy formats
                if isinstance(proxy, str):
                    # Handle URL format like "http://user:pass@host:port" or "http://host:port:user:pass"
                    if '://' in proxy:
                        # Parse URL format
                        protocol_part, rest = proxy.split('://', 1)
                        protocol_part = protocol_part.strip().lstrip(';').strip()
                        logger.info(f"[DEBUG] URL format detected - protocol: {protocol_part}, rest: {rest}")
                        
                        # Check if it's the standard format with @ symbol
                        if '@' in rest:
                            # Standard format: http://username:password@host:port
                            auth_part, host_port = rest.rsplit('@', 1)
                            logger.info(f"[DEBUG] Standard format - auth: {auth_part}, host_port: {host_port}")
                            # Split auth_part on last : to handle passwords with colons
                            if ':' in auth_part:
                                username, password = auth_part.rsplit(':', 1)
                            else:
                                username = auth_part
                                password = None
                            host, port = host_port.split(':', 1)
                        else:
                            # Non-standard format: http://host:port:username:password
                            logger.info(f"[DEBUG] Non-standard format detected")
                            # Split on colons and handle the last two parts as username:password
                            parts = rest.split(':')
                            if len(parts) >= 4:
                                # Extract host, port, username, password
                                host = parts[0]
                                port = parts[1]
                                # Join all remaining parts except the last one as username
                                username = ':'.join(parts[2:-1])
                                password = parts[-1]
                            elif len(parts) == 3:
                                # Format: host:port:username (no password)
                                host, port, username = parts
                                password = None
                            elif len(parts) == 2:
                                # Format: host:port (no authentication)
                                host, port = parts
                                username = password = None
                            else:
                                logger.error(f"[DEBUG] Invalid proxy format: {proxy}")
                                continue
                        
                        proxy_config = ProxyConfig(
                            host=host.strip(),
                            port=int(port.strip()),
                            username=username.strip() if username else None,
                            password=password.strip() if password else None,
                            protocol=protocol_part.strip()
                        )
                        
                        logger.info(f"[DEBUG] Parsed proxy: {proxy_config.protocol}://{proxy_config.host}:{proxy_config.port} (user: {proxy_config.username}, pass: {'*' * len(proxy_config.password) if proxy_config.password else 'None'})")
                    else:
                        # Handle simple format WITHOUT protocol prefix
                        logger.info(f"[DEBUG] Simple format detected: {proxy}")
                        
                        # Check if format is username:password@host:port
                        if '@' in proxy:
                            # Format: username:password@host:port
                            auth_part, host_port = proxy.rsplit('@', 1)
                            if ':' in auth_part:
                                username, password = auth_part.rsplit(':', 1)
                            else:
                                username = auth_part
                                password = None
                            
                            if ':' in host_port:
                                host, port = host_port.rsplit(':', 1)
                            else:
                                logger.error(f"[DEBUG] Invalid proxy format (missing port): {proxy}")
                                continue
                            
                            proxy_config = ProxyConfig(
                                host=host.strip(),
                                port=int(port.strip()),
                                username=username.strip() if username else None,
                                password=password.strip() if password else None,
                                protocol='http'  # Default to HTTP
                            )
                        else:
                            # Format: host:port:user:pass or host:port
                            parts = proxy.split(':')
                            if len(parts) >= 4: # Allow for colons in password
                                host = parts[0]
                                port = parts[1]
                                username = parts[2]
                                password = ':'.join(parts[3:]) # Join the rest for the password
                                proxy_config = ProxyConfig(
                                    host=host.strip(),
                                    port=int(port.strip()),
                                    username=username.strip(),
                                    password=password.strip(),
                                    protocol='http'  # Default to HTTP
                                )
                            elif len(parts) == 2:
                                host, port = parts
                                proxy_config = ProxyConfig(
                                    host=host.strip(),
                                    port=int(port.strip()),
                                    protocol='http'  # Default to HTTP
                                )
                            else:
                                logger.error(f"[DEBUG] Invalid proxy format: {proxy}")
                                continue
                elif isinstance(proxy, dict):
                    proxy_config = ProxyConfig(
                        host=proxy.get('host'),
                        port=int(proxy.get('port')),
                        username=proxy.get('username'),
                        password=proxy.get('password'),
                        protocol=proxy.get('protocol', 'http')
                    )
                else:
                    logger.error(f"[DEBUG] Invalid proxy format: {proxy}")
                    continue
                
                self.proxies.append(proxy_config)
                logger.info(f"[DEBUG] Successfully loaded proxy {i+1}: {proxy_config.protocol}://{proxy_config.host}:{proxy_config.port}")
                
            except Exception as e:
                logger.error(f"[DEBUG] Error loading proxy {i+1} ({proxy}): {str(e)}")
                logger.error(f"[DEBUG] Error details: {traceback.format_exc()}")
        
        if not self.proxies:
            logger.warning("[DEBUG] No valid proxies loaded!")
        else:
            logger.info(f"[DEBUG] Successfully loaded {len(self.proxies)} proxies")
            for i, proxy in enumerate(self.proxies):
                logger.info(f"[DEBUG] Proxy {i+1}: {proxy.protocol}://{proxy.host}:{proxy.port} (user: {proxy.username}, pass: {'*' * len(proxy.password) if proxy.password else 'None'})")
    
    def get_all_proxies(self):
        with self.lock:
            return list(self.proxies)

    def is_empty(self):
        with self.lock:
            return len(self.proxies) == 0
    
    def get_next_proxy(self) -> Optional[ProxyConfig]:
        """Get next proxy in round-robin fashion - EXACT COPY from UK.py"""
        with self.lock:
            if not self.proxies:
                return None
            
            import time
            current_time = time.time()
            failed_proxies = getattr(self, 'failed_proxies', {})
            retry_delay = 300  # Retry failed proxies after 5 minutes
            
            # Try to find a proxy that's not recently failed
            attempts = 0
            max_attempts = len(self.proxies) * 2  # Allow cycling through all proxies twice
            
            while attempts < max_attempts:
                # Round-robin rotation
                proxy = self.proxies[self.current_proxy_index.value]
                self.current_proxy_index.value = (self.current_proxy_index.value + 1) % len(self.proxies)
                
                proxy_id = f"{proxy.host}:{proxy.port}"
                
                # Check if this proxy was recently failed
                if proxy_id in failed_proxies:
                    time_since_failed = current_time - failed_proxies[proxy_id]
                    if time_since_failed < retry_delay:
                        attempts += 1
                        continue  # Try next proxy
                    else:
                        # Enough time passed, remove from failed list and use this proxy
                        del failed_proxies[proxy_id]
                
                # Track usage
                self.proxy_usage_count[proxy_id] = self.proxy_usage_count.get(proxy_id, 0) + 1
                
                return proxy
            
            # If all proxies are recently failed, just return the next one anyway
            proxy = self.proxies[self.current_proxy_index.value]
            self.current_proxy_index.value = (self.current_proxy_index.value + 1) % len(self.proxies)
            
            proxy_id = f"{proxy.host}:{proxy.port}"
            self.proxy_usage_count[proxy_id] = self.proxy_usage_count.get(proxy_id, 0) + 1
            
            logger.info(f"[PROXY POOL] All proxies recently failed, retrying proxy: {proxy.host}:{proxy.port}")
            return proxy
    
    def mark_proxy_failed(self, proxy: ProxyConfig):
        """Mark proxy as temporarily failed - EXACT COPY from UK.py"""
        with self.lock:
            # DON'T REMOVE PROXIES - just mark them as temporarily failed
            proxy_id = f"{proxy.host}:{proxy.port}"
            if not hasattr(self, 'failed_proxies'):
                self.failed_proxies = {}
            
            import time
            self.failed_proxies[proxy_id] = time.time()
            logger.warning(f"Marked proxy as temporarily failed: {proxy.host}:{proxy.port} (will retry later)")
    
    def get_proxy_usage_stats(self) -> Dict:
        """Get detailed proxy usage statistics - EXACT COPY from UK.py"""
        with self.lock:
            total_assignments = sum(self.proxy_usage_count.values())
            unique_proxies_used = len(self.proxy_usage_count)
            failed_count = len(getattr(self, 'failed_proxies', {}))
            return {
                "total_proxies": len(self.proxies),
                "total_assignments": total_assignments,
                "unique_proxies_used": unique_proxies_used,
                "failed_proxies": failed_count,
                "usage_per_proxy": dict(self.proxy_usage_count),
                "rotation_efficiency": (unique_proxies_used / total_assignments * 100) if total_assignments > 0 else 100
            }
    
    def reset_failed_proxies(self):
        """Reset failed proxy list to retry all proxies - EXACT COPY from UK.py"""
        with self.lock:
            if hasattr(self, 'failed_proxies'):
                failed_count = len(self.failed_proxies)
                self.failed_proxies.clear()
                logger.info(f"[PROXY POOL] Reset {failed_count} failed proxies - all proxies available again")

def send_notification(title, message):
    if not config.get("notify", False):
        return
    try:
        notification = Notify()
        notification.application_name = "Discord Account Generator"
        notification.title = title
        notification.message = message
        icon_path = "data/pack.ico"
        if icon_path and os.path.isfile(icon_path):
            notification.icon = icon_path
        notification.send()
    except Exception as e:
        pass

def account_ratelimit(email=None, username=None):
    try:
        headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.5",
            "Content-Type": "application/json",
            "DNT": "1",
            "Host": "discord.com",
            "Origin": "https://discord.com",
            "Referer": "https://discord.com/register",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-GPC": "1",
            "TE": "trailers",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "X-Debug-Options": "bugReporterEnabled",
            "X-Discord-Locale": "en-US",
            "X-Discord-Timezone": "America/New_York",
        }
        
        test_email = email if email else ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10)) + "@gmail.com"
        test_username = username if username else ''.join(random.choices(string.ascii_letters, k=8))
        
        data = {
            'email': test_email,
            'password': "TestPassword123!",
            'date_of_birth': "2000-01-01",
            'username': test_username,
            'global_name': test_username,
            'consent': True,
            'captcha_service': 'hcaptcha',
            'captcha_key': None,
            'invite': None,
            'promotional_email_opt_in': False,
            'gift_code_sku_id': None
        }
        
        req = requests.post('https://discord.com/api/v9/auth/register', json=data, headers=headers)
        try:
            resp_data = req.json()
        except Exception:
            return 1
            
        if req.status_code == 429 or 'retry_after' in resp_data:
            limit = resp_data.get('retry_after', 1)
            return int(float(limit)) + 1 if limit else 1
        else:
            return 1
    except Exception as e:
        log("ERROR", f"Rate limit check failed: {e}")
        return 1

def log(type, message):
    now = datetime.now().strftime("%H:%M:%S")
    type_map = {
        "SUCCESS": Fore.GREEN + "SUCCESS" + Style.RESET_ALL,
        "ERROR": Fore.RED + "ERROR" + Style.RESET_ALL,
        "INFO": Fore.CYAN + "INFO" + Style.RESET_ALL,
        "WARNING": Fore.YELLOW + "WARNING" + Style.RESET_ALL
    }
    tag = type_map.get(type.upper(), type.upper())

    if type.upper() == "INFO":
        message = f"{Fore.LIGHTBLACK_EX}{message}{Style.RESET_ALL}"
    elif ':' in message:
        parts = message.split(':', 1)
        key = parts[0].upper().strip()
        val = parts[1].strip()
        message = f"{key}: {Fore.LIGHTBLACK_EX}{val}{Style.RESET_ALL}"

    print(f"{Fore.LIGHTBLACK_EX}{now}{Style.RESET_ALL} - {tag} • {message}")

def get_device_id():
    return socket.gethostname()

def set_console_title(title="Rizzers token gen"):
    if os.name == 'nt':
        os.system(f"title {title}")
    else:
        print(f"\33]0;{title}\a", end='', flush=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def cleanup_playwright():
    try:
        import gc
        gc.collect()
        
        for task in asyncio.all_tasks() if hasattr(asyncio, 'all_tasks') else ():
            if not task.done() and task != asyncio.current_task():
                task.cancel()
    except Exception as e:
        log("ERROR", f"Cleanup error: {e}")
        pass

def vertical_gradient(lines, start_rgb=(0, 255, 200), end_rgb=(0, 100, 180)):
    total = len(lines)
    result = []
    for i, line in enumerate(lines):
        r = start_rgb[0] + (end_rgb[0] - start_rgb[0]) * i // max(1, total - 1)
        g = start_rgb[1] + (end_rgb[1] - start_rgb[1]) * i // max(1, total - 1)
        b = start_rgb[2] + (end_rgb[2] - start_rgb[2]) * i // max(1, total - 1)
        result.append(f'\033[38;2;{r};{g};{b}m{line}\033[0m')
    return result

def print_ascii_logo():
    ascii_art = [
        "██████╗ ██╗███████╗███████╗███████╗██████╗ ███████╗",
        "██╔══██╗██║╚══███╔╝╚══███╔╝██╔════╝██╔══██╗██╔════╝",
        "██████╔╝██║  ███╔╝   ███╔╝ █████╗  ██████╔╝███████╗",
        "██╔══██╗██║ ███╔╝   ███╔╝  ██╔══╝  ██╔══██╗╚════██║",
        "██║  ██║██║███████╗███████╗███████╗██║  ██║███████║",
        "╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝",
        "",
        "Made by rizzler_dev with love"
    ]

    print('\n' * 2)
    gradient_lines = vertical_gradient(ascii_art)
    for colored_line in gradient_lines:
        print(Center.XCenter(colored_line))
    print('\n' * 2)

def generate_random_string(length=10):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def random_username():
    return 'rizzlers' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

def get_user_input(prompt, valid_options=["yes", "no", "y", "n"]):
    while True:
        try:
            response = input(f"{Fore.CYAN}[+] {prompt}: {Style.RESET_ALL}").strip().lower()
            if response in valid_options:
                return response
        except KeyboardInterrupt:
            exit(0)
        except Exception as e:
            pass

def configure_user_options():
    global USE_HUMANIZER, USE_VPN
    
    print(f"\n{Fore.CYAN}Configuration Options{Style.RESET_ALL}\n")
    
    humanizer_choice = get_user_input("Do you want to use humanizer (y/n)")
    USE_HUMANIZER = humanizer_choice in ["yes", "y"]
    
    vpn_choice = get_user_input("Do you want to use VPN (y/n)")
    USE_VPN = vpn_choice in ["yes", "y"]
    
    print(f"\n{Fore.GREEN}Configuration completed!{Style.RESET_ALL}\n")

async def validate_license_key(license_key: str):
    return True

class IncognitoMailClient:
    def __init__(self):
        self.email = None
        self.inbox_id = None
        self.inbox_token = None
        self.session = requests.Session()
        self.secret_key = None
        self._initialize_secret()

    def _initialize_secret(self):
        scrambled = "4O)QqiTV+(U+?Vi]qe|6..Xe"
        self.secret_key = ''.join([chr(ord(c) - 2) for c in scrambled])

    def _sign_payload(self, payload: dict) -> str:
        message = json.dumps(payload, separators=(',', ':')).encode()
        key = self.secret_key.encode()
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def _get_random_fr_ip(self):
        return f"90.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

    def debug_inbox_status(self):
        if not self.inbox_id or not self.inbox_token:
            log("ERROR", "No inbox credentials for debugging")
            return False
            
        try:
            ts = int(time.time() * 1000)
            payload = {
                "inboxId": self.inbox_id,
                "inboxToken": self.inbox_token,
                "ts": ts
            }
            payload["key"] = self._sign_payload(payload)
            
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            
            response = requests.post(
                f"{INCOGNITO_API_URL}inbox/v1/list", 
                json=payload, 
                headers=headers, 
                timeout=10
            )
            
            log("INFO", f"API Status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                items = data.get("items", [])
                log("INFO", f"Inbox accessible, {len(items)} emails found")
                
                for i, item in enumerate(items[:3]):
                    log("INFO", f"Email {i+1}: messageURL present = {bool(item.get('messageURL'))}")
                    
                return True
            else:
                log("ERROR", f"API Error: {response.text[:100]}")
                return False
                
        except Exception as e:
            log("ERROR", f"Exception: {e}")
            return False

    async def create_temp_email(self):
        for attempt in range(1, 3):
            try:
                timestamp = int(time.time() * 1000)
                payload = {
                    "ts": timestamp,
                    "domain": INCOGNITO_DOMAIN
                }
                payload["key"] = self._sign_payload(payload)
                
                fake_ip = self._get_random_fr_ip()
                headers = {
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
                    "X-Forwarded-For": fake_ip,
                    "X-Real-IP": fake_ip,
                    "Via": fake_ip
                }
                
                response = httpx.post(
                    f"{INCOGNITO_API_URL}inbox/v2/create", 
                    json=payload, 
                    headers=headers,
                    timeout=15
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "id" in data and "token" in data:
                        self.inbox_id = data["id"]
                        self.inbox_token = data["token"]
                        self.email = self.inbox_id
                        log("SUCCESS", f"Email created: {self.email}")
                        return self.email
                
            except Exception as e:
                if attempt == 2:
                    log("ERROR", f"Failed to create email: {e}")
                await asyncio.sleep(2)
                    
        return None

    def check_verification_email(self):
        if not self.inbox_id or not self.inbox_token:
            return None
            
        for attempt in range(1, 30):
            try:
                ts = int(time.time() * 1000)
                payload = {
                    "inboxId": self.inbox_id,
                    "inboxToken": self.inbox_token,
                    "ts": ts
                }
                payload["key"] = self._sign_payload(payload)
                
                headers = {
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
                
                response = requests.post(
                    f"{INCOGNITO_API_URL}inbox/v1/list", 
                    json=payload, 
                    headers=headers, 
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    items = data.get("items", [])
                    
                    if items:
                        for item in items:
                            message_url = item.get("messageURL")
                            if message_url:
                                try:
                                    email_data = requests.get(message_url, timeout=5).json()
                                    subject = email_data.get("subject", "")
                                    
                                    if "verify" in subject.lower():
                                        content = str(email_data.get("text", "")) + str(email_data.get("html", ""))
                                        
                                        patterns = [
                                            r'https:\/\/click\.discord\.com[^\s"\'\'<>\\]+',
                                            r'https://click\.discord\.com[^\s"\'\'<>\\]+',
                                            r'https://discord\.com/verify[^\s"\'\'<>\\]+'
                                        ]
                                        
                                        for pattern in patterns:
                                            match = re.search(pattern, content)
                                            if match:
                                                link = match.group(0).replace('\\/', '/').split("\n")[0].strip()
                                                link = link.replace('&amp;', '&')
                                                log("SUCCESS", "Verification link found")
                                                return link
                                except:
                                    continue
                    
            except:
                pass
            
            time.sleep(2.0)
        
        log("ERROR", "Verification email not received")
        return None

def check_chrome_installation():
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Users\{}\AppData\Local\Google\Chrome\Application\chrome.exe".format(os.getenv('USERNAME', '')),
    ]
    
    for path in chrome_paths:
        if os.path.exists(path):
            return True
    
    log("ERROR", "Chrome not found")
    log("INFO", "Install from: https://www.google.com/chrome/")
    return False

class HCaptchaSolver:
    """Dedicated hCaptcha solver using hcaptcha_challenger library"""
    
    def __init__(self, gemini_api_key: str = None):
        """Initialize hCaptcha solver with Gemini API key"""
        # Use provided key or get from config
        if gemini_api_key:
            os.environ['GEMINI_API_KEY'] = gemini_api_key
        elif 'GEMINI_API_KEY' not in os.environ:
            # Try to get from config
            gemini_key = config.get("gemini_api_key", "")
            if gemini_key:
                os.environ['GEMINI_API_KEY'] = gemini_key
        
        # Configure AgentConfig - Using gemini-2.5-flash for better speed and accuracy
        # INCREASED TIMEOUTS for complex challenges (image_drag_single, etc.)
        self.agent_config = AgentConfig(
            DISABLE_BEZIER_TRAJECTORY=True,
            CHALLENGE_CLASSIFIER_MODEL='gemini-2.5-flash',
            IMAGE_CLASSIFIER_MODEL='gemini-2.5-flash',
            SPATIAL_POINT_REASONER_MODEL='gemini-2.5-flash',
            SPATIAL_PATH_REASONER_MODEL='gemini-2.5-flash',
            EXECUTION_TIMEOUT=120,  # Increased from 60 to 120 seconds
            RESPONSE_TIMEOUT=30,     # Increased from 12 to 30 seconds
            RETRY_ON_FAILURE=True,
            CONSTRAINT_RESPONSE_SCHEMA=False
        )
        logger.info("HCaptcha Solver initialized with gemini-2.5-flash (extended timeouts)")
    
    async def fill_form(self):
        try:
            send_notification("Account Generation", "Starting new account creation...")
            
            email = await self.mail_client.create_temp_email()
            if not email:
                send_notification("Error", "Failed to create temporary email")
                log("ERROR", "Failed to create email")
                return None

            self.email = email
            
            try:
                page = await self.browser_mgr.start("https://discord.com/register")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log("ERROR", f"Failed to start browser: {e}")
                return None
            
            try:
                await self._fill_basic_fields(page, email)
                await self._select_birth_date(page)
                
                log("SUCCESS", "All form fields filled and submitted!")
                
                # IMPORTANT: hCaptcha appears AFTER clicking "Create Account" button
                # The _select_birth_date method already clicks the submit button
                # Now we wait for hCaptcha to appear
                
                log("INFO", "⏳ Waiting for hCaptcha to appear after form submission...")
                await asyncio.sleep(2)
                
                # Wait for hCaptcha iframe to appear (it should appear now after submission)
                hcaptcha_found = False
                log("INFO", "🔍 Starting hCaptcha detection loop...")
                
                for wait_attempt in range(15):  # Wait up to 30 seconds
                    try:
                        # Debug: Check what's on the page
                        if wait_attempt % 5 == 0:  # Log every 5 attempts
                            try:
                                # Count all iframes
                                all_iframes = await page.query_selector_all('iframe')
                                log("INFO", f"📊 Detection attempt {wait_attempt + 1}/15 - Found {len(all_iframes)} total iframes on page")
                                
                                # Check for any hcaptcha-related elements
                                for i, iframe in enumerate(all_iframes):
                                    src = await iframe.get_attribute('src')
                                    if src:
                                        log("INFO", f"   Iframe {i + 1}: {src[:80]}...")
                            except:
                                pass
                        
                        iframe = await page.wait_for_selector('iframe[src*="hcaptcha.com"]', state='attached', timeout=2000)
                        if iframe:
                            iframe_src = await iframe.get_attribute('src')
                            log("SUCCESS", f"✅ hCaptcha widget appeared! Source: {iframe_src[:100]}...")
                            hcaptcha_found = True
                            break
                    except:
                        if wait_attempt < 14:
                            await asyncio.sleep(1)
                            continue
                
                if not hcaptcha_found:
                    log("WARNING", "⚠️ hCaptcha widget not detected after 30 seconds")
                    log("WARNING", "This might be a rate limit or the form didn't submit properly")
                    
                    # DEBUG: Check for Discord error messages
                    try:
                        log("INFO", "🔍 Checking for Discord error messages...")
                        
                        # Check for error text on page
                        error_texts = [
                            'rate', 'limit', 'slow', 'wait', 'error', 'captcha', 
                            'human', 'verify', 'suspicious', 'try again'
                        ]
                        
                        page_content = await page.content()
                        found_errors = [text for text in error_texts if text.lower() in page_content.lower()]
                        
                        if found_errors:
                            log("WARNING", f"📝 Found possible error indicators: {', '.join(found_errors)}")
                        
                        # Check page URL
                        current_url = page.url
                        log("INFO", f"📍 Current page URL: {current_url}")
                        
                        # Check for visible error messages
                        error_selectors = [
                            '[class*="error"]',
                            '[class*="message"]',
                            '[role="alert"]',
                            'div:has-text("error")',
                            'div:has-text("wait")',
                        ]
                        
                        for selector in error_selectors:
                            try:
                                elements = await page.query_selector_all(selector)
                                if elements:
                                    for elem in elements[:3]:  # Check first 3
                                        text = await elem.text_content()
                                        if text and len(text.strip()) > 0:
                                            log("WARNING", f"⚠️ Found message: {text.strip()[:100]}")
                            except:
                                pass
                    except Exception as e:
                        log("WARNING", f"Debug check failed: {e}")
                else:
                    # Give hCaptcha time to fully initialize
                    log("INFO", "Waiting for hCaptcha to fully initialize...")
                    await asyncio.sleep(3)
                
                # AUTOMATIC HCAPTCHA SOLVING WITH RETRY - Up to 8 attempts for maximum success
                log("INFO", "🤖 Starting hCaptcha solver (up to 8 attempts)...")
                captcha_solved = await self.hcaptcha_solver.solve_with_retry(page, max_retries=8)
                
                if captcha_solved:
                    log("SUCCESS", "✅ hCaptcha solved automatically!")
                    send_notification("Success", "hCaptcha solved automatically!")
                else:
                    log("ERROR", "❌ Failed to solve hCaptcha automatically")
                    send_notification("Error", "Failed to solve hCaptcha")
                    await self.browser_mgr.stop()
                    return None
                
                # Wait a moment for Discord to process
                await asyncio.sleep(2)
                
                token = await self._verify_email()
                
                await self.browser_mgr.stop()
                
                if token:
                    send_notification("Success", f"Account: {token[:12]}...")
                    return token
                else:
                    send_notification("Error", "Failed to complete account verification")
                    return None
                
            except asyncio.CancelledError:
                log("INFO", "Form filling cancelled")
                raise
            except Exception as e:
                log("ERROR", f"Form filling failed: {e}")
                try:
                    await self.browser_mgr.stop()
                except Exception:
                    pass
                return None
                
        except asyncio.CancelledError:
            log("INFO", "Account generation cancelled")
            try:
                await self.browser_mgr.stop()
            except Exception:
                pass
            raise
        except Exception as e:
            log("ERROR", f"Account generation failed: {e}")
            try:
                await self.browser_mgr.stop()
            except Exception:
                pass
            return None

    async def _fill_basic_fields(self, page, email):
        """Fill basic registration fields - OPTIMIZED and ROBUST"""
        display_name = "Rizzers runs cord"
        username = random_username()
        password = self.mail_client.inbox_token
        
        if not password:
            password = "MAXX$" + generate_random_string(8) + "@7836"

        log("INFO", "Starting form field filling...")
        
        # SMART WAIT: Ensure page JavaScript is fully loaded before interaction
        await asyncio.sleep(1)
        
        # Fill email - with retry logic
        for attempt in range(3):
            try:
                email_field = await page.wait_for_selector('input[name="email"]', state='visible', timeout=10000)
                await email_field.click()  # Focus the field
                await asyncio.sleep(0.1)
                await email_field.fill(self.mail_client.inbox_id)
                log("SUCCESS", f"Email filled: {self.mail_client.inbox_id}")
                break
            except Exception as e:
                if attempt == 2:
                    log("ERROR", f"Failed to fill email after 3 attempts: {e}")
                    raise
                log("WARNING", f"Email fill attempt {attempt + 1} failed, retrying...")
                await asyncio.sleep(0.5)

        await asyncio.sleep(0.2)

        # Fill display name - with retry logic
        for attempt in range(3):
            try:
                display_name_field = await page.wait_for_selector('input[name="global_name"]', state='visible', timeout=10000)
                await display_name_field.click()
                await asyncio.sleep(0.1)
                await display_name_field.fill(display_name)
                log("SUCCESS", f"Display name filled: {display_name}")
                break
            except Exception as e:
                if attempt == 2:
                    log("ERROR", f"Failed to fill display name after 3 attempts: {e}")
                    raise
                log("WARNING", f"Display name fill attempt {attempt + 1} failed, retrying...")
                await asyncio.sleep(0.5)

        await asyncio.sleep(0.2)

        # Fill username - with retry logic
        for attempt in range(3):
            try:
                username_field = await page.wait_for_selector('input[name="username"]', state='visible', timeout=10000)
                await username_field.click()
                await asyncio.sleep(0.1)
                await username_field.fill(username)
                log("SUCCESS", f"Username filled: {username}")
                break
            except Exception as e:
                if attempt == 2:
                    log("ERROR", f"Failed to fill username after 3 attempts: {e}")
                    raise
                log("WARNING", f"Username fill attempt {attempt + 1} failed, retrying...")
                await asyncio.sleep(0.5)

        await asyncio.sleep(0.2)

        # Fill password - with retry logic
        for attempt in range(3):
            try:
                password_field = await page.wait_for_selector('input[name="password"]', state='visible', timeout=10000)
                await password_field.click()
                await asyncio.sleep(0.1)
                await password_field.fill(password)
                log("SUCCESS", "Password filled")
                break
            except Exception as e:
                if attempt == 2:
                    log("ERROR", f"Failed to fill password after 3 attempts: {e}")
                    raise
                log("WARNING", f"Password fill attempt {attempt + 1} failed, retrying...")
                await asyncio.sleep(0.5)
        
        self.password = password
        self.email = self.mail_client.inbox_id
        
        log("SUCCESS", "All form fields filled successfully!")

    async def _select_birth_date(self, page):
        """Fast random birth date selection with optimized timeouts"""
        try:
            await asyncio.sleep(0.5)  # Reduced wait time
            
            # Generate random birthday (18+ years old) - like reference file
            current_year = 2024
            birth_year = random.randint(1980, current_year - 18)
            birth_month = random.randint(1, 12)
            birth_day = random.randint(1, 28)  # Use 28 to avoid month-specific day issues
            
            month_names = ["January", "February", "March", "April", "May", "June", 
                          "July", "August", "September", "October", "November", "December"]
            
            # Fast method: Try text-based clicking first (fastest)
            try:
                log("INFO", f"Fast random date selection: {birth_month}/{birth_day}/{birth_year}")
                
                # Click month dropdown
                await page.click('text="Month"', timeout=2000)
                await asyncio.sleep(0.2)
                await page.click(f'text="{month_names[birth_month-1]}"', timeout=2000)
                await asyncio.sleep(0.2)
                
                # Click day dropdown
                await page.click('text="Day"', timeout=2000)
                await asyncio.sleep(0.2)
                await page.click(f'text="{birth_day}"', timeout=2000)
                await asyncio.sleep(0.2)
                
                # Click year dropdown
                await page.click('text="Year"', timeout=2000)
                await asyncio.sleep(0.2)
                await page.click(f'text="{birth_year}"', timeout=2000)
                
                log("SUCCESS", f"Random birthday set (fast): {birth_month}/{birth_day}/{birth_year}")
                
            except Exception as e:
                log("WARNING", f"Fast text method failed: {e}")
                
                # Fallback: Try selectors with short timeout
                try:
                    log("INFO", "Trying selectors with short timeout...")
                    
                    # Month dropdown
                    month_selector = 'select[name="date_of_birth_month"], [aria-label*="month"]'
                    await page.select_option(month_selector, str(birth_month), timeout=2000)
                    
                    # Day dropdown  
                    day_selector = 'select[name="date_of_birth_day"], [aria-label*="day"]'
                    await page.select_option(day_selector, str(birth_day), timeout=2000)
                    
                    # Year dropdown
                    year_selector = 'select[name="date_of_birth_year"], [aria-label*="year"]'
                    await page.select_option(year_selector, str(birth_year), timeout=2000)
                    
                    log("SUCCESS", f"Random birthday set (selectors): {birth_month}/{birth_day}/{birth_year}")
                    
                except Exception as e2:
                    log("WARNING", f"Selectors failed: {e2}")
                    # Continue anyway - form might still work
            
            await asyncio.sleep(0.5)  # Reduced wait
            
            # Check ALL checkboxes (consent + terms of service)
            try:
                # Find all checkboxes on the page
                checkboxes = await page.query_selector_all('input[type="checkbox"]:not([disabled])')
                
                if checkboxes:
                    log("INFO", f"Found {len(checkboxes)} checkbox(es) to check")
                    
                    for idx, checkbox in enumerate(checkboxes):
                        try:
                            # Check if already checked
                            is_checked = await checkbox.is_checked()
                            if not is_checked:
                                await checkbox.click()
                                await asyncio.sleep(0.2)
                                log("SUCCESS", f"Checkbox {idx + 1} checked")
                            else:
                                log("INFO", f"Checkbox {idx + 1} already checked")
                        except Exception as e:
                            log("WARNING", f"Failed to check checkbox {idx + 1}: {e}")
                    
                    log("SUCCESS", "All checkboxes processed (consent + terms of service)")
                else:
                    log("WARNING", "No checkboxes found")
                    
            except Exception as e:
                log("WARNING", f"Checkbox processing failed: {e}")
            
            await asyncio.sleep(0.5)  # Reduced wait
            
            # Click submit button
            try:
                submit_button = await page.wait_for_selector('button[type="submit"], button:has-text("Continue"), button:has-text("Next")', timeout=2000)
                if submit_button:
                    # Debug: Check button state before clicking
                    is_disabled = await submit_button.is_disabled()
                    is_visible = await submit_button.is_visible()
                    button_text = await submit_button.text_content()
                    log("INFO", f"📝 Submit button state - Disabled: {is_disabled}, Visible: {is_visible}, Text: {button_text.strip()}")
                    
                    if not is_disabled:
                        await submit_button.click()
                        await asyncio.sleep(0.5)
                        log("SUCCESS", "✅ Submit button clicked successfully")
                    else:
                        log("WARNING", "⚠️ Submit button is disabled - form might be invalid")
            except Exception as e:
                log("WARNING", f"❌ Submit button click failed: {e}")
            
            await asyncio.sleep(1)  # Reduced final wait

        except Exception as e:
            log("ERROR", f"Date selection error: {e}")
            # Final fallback: just try to submit the form
            try:
                log("INFO", "Trying final fallback - pressing Enter")
                await page.keyboard.press('Enter')
                await asyncio.sleep(1)
            except Exception as final_error:
                log("ERROR", f"Final fallback also failed: {final_error}")

    def get_token(self, inbox_id=None, inbox_token=None):
        try:
            login_id = inbox_id or self.mail_client.inbox_id
            login_password = inbox_token or self.mail_client.inbox_token
            
            if not login_id or not login_password:
                return None
                
            payload = {
                'login': login_id,
                'password': login_password
            }
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'Origin': 'https://discord.com',
                'Referer': 'https://discord.com/login'
            }
            
            res = requests.post('https://discord.com/api/v9/auth/login', json=payload, headers=headers)
            
            if res.status_code == 200:
                try:
                    response_data = res.json()
                    if 'token' in response_data:
                        token = response_data['token']
                        log("SUCCESS", f"Token: {token[:12]}...")
                        
                        os.makedirs("OUTPUT", exist_ok=True)
                        
                        with open("OUTPUT/tokens.txt", "a", encoding="utf-8") as tf:
                            tf.write(token + "\n")
                        
                        with open("OUTPUT/accounts.txt", "a", encoding="utf-8") as af:
                            af.write(f"{login_id}:{login_password}:{token}\n")
                        
                        self.token = token
                        return token
                except json.JSONDecodeError:
                    pass
                
        except Exception:
            pass
        return None

    def check_email_verified_api(self, token):
        url = "https://discord.com/api/v9/users/@me"
        headers = {
            "Authorization": token,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "DNT": "1",
            "Origin": "https://discord.com",
            "Referer": "https://discord.com/channels/@me",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "X-Debug-Options": "bugReporterEnabled",
            "X-Discord-Locale": "en-US",
            "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyMC4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTIwLjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwLjAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjUxNDQxLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="
        }
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                verified = data.get("verified", False)
                email = data.get("email", "No Email")
                return verified, email
            else:
                return None, None
        except:
            return None, None

    async def _verify_email(self):
        for attempt in range(150):
            try:
                verification_link = self.mail_client.check_verification_email()
                if verification_link:
                    break
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                log("INFO", "Verification check cancelled")
                return None
            except Exception:
                pass
        
        if not verification_link:
            return None

        verification_page = None
        try:
            log("SUCCESS", "Opening verification link in new tab (resolving redirects first)...")
            
            # 1) Resolve redirects server-side to get the final direct URL
            #    This avoids navigating through click.discord.com which can trigger hCaptcha
            final_url = None
            try:
                log("INFO", "Resolving verification redirect server-side...")
                rs_headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": "https://discord.com/"
                }
                # Follow redirects to final destination
                resp = requests.get(verification_link, headers=rs_headers, timeout=10, allow_redirects=True)
                if resp.ok:
                    final_url = resp.url
                    log("SUCCESS", f"Resolved redirect: {verification_link[:50]}... -> {final_url[:80]}...")
                else:
                    log("WARNING", f"Redirect resolution returned status {resp.status_code}, using original link")
            except Exception as e:
                log("WARNING", f"Redirect resolution failed: {e} — using original link")
            
            # Use resolved URL or fall back to original
            target_url = final_url or verification_link
            
            # 2) Create new page in existing context (shares cookies/localStorage/session)
            verification_page = await self.browser_mgr.context.new_page()
            
            # 3) Set extra HTTP headers to make navigation look like normal Discord flow
            #    This reduces risk of hCaptcha challenge
            try:
                await verification_page.set_extra_http_headers({
                    "Referer": "https://discord.com/",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept-Language": "en-US,en;q=0.9"
                })
                log("INFO", "Set verification page headers (Referer, User-Agent)")
            except Exception as e:
                log("WARNING", f"Could not set extra headers: {e}")
            
            # 4) Optional: Explicitly copy cookies from context to verification page
            #    (Context should share cookies, but this is defensive)
            try:
                cookies = await self.browser_mgr.context.cookies()
                if cookies:
                    await verification_page.context.add_cookies(cookies)
                    log("INFO", f"Copied {len(cookies)} cookies to verification page")
            except Exception as e:
                log("WARNING", f"Cookie copy skipped: {e}")
            
            # 5) Navigate to final target URL (bypassing redirector)
            log("INFO", f"Navigating to final verification URL...")
            await verification_page.goto(target_url, timeout=60000)
            await asyncio.sleep(1.0)
            log("SUCCESS", "Verification page loaded!")

            token = None
            for check_attempt in range(80):
                try:
                    token = self.get_token(self.mail_client.inbox_id, self.mail_client.inbox_token)
                    if token:
                        break
                    await asyncio.sleep(0.5)
                except asyncio.CancelledError:
                    log("INFO", "Token check cancelled")
                    return None
                except Exception:
                    pass

            if not token:
                return None

            verification_complete = False
            
            for verify_attempt in range(300):
                try:
                    verified, email_address = self.check_email_verified_api(token)
                    if verified:
                        verification_complete = True
                        log("SUCCESS", "Email verified successfully!")
                        break
                    await asyncio.sleep(0.5)
                except asyncio.CancelledError:
                    log("INFO", "Email verification cancelled")
                    return None
                except Exception:
                    pass
            
            if not verification_complete:
                return None
                
            if USE_HUMANIZER and self.humanizer.config.get("Humanize", False):
                try:
                    await self.humanizer.humanize_account(
                        token, 
                        self.mail_client.inbox_id, 
                        self.mail_client.inbox_token
                    )
                    log("SUCCESS", "Account humanized successfully")
                except asyncio.CancelledError:
                    log("INFO", "Humanization cancelled")
                except Exception as e:
                    log("ERROR", f"Humanization failed: {e}")
            
            return token
            
        except asyncio.CancelledError:
            log("INFO", "Verification process cancelled")
            return None
        except Exception as e:
            log("ERROR", f"Verification error: {e}")
            return None
        finally:
            # Close the verification tab (not the entire browser)
            if verification_page:
                try:
                    await verification_page.close()
                    log("INFO", "Verification tab closed")
                except:
                    pass

def worker_process(worker_id: int, num_accounts: int, num_processes: int, config_data: Dict, proxy_pool=None):
    """Worker process for Discord account generation - EXACT PATTERN from UK.py"""
    try:
        # Set minimal logging for background processes
        logging.getLogger().setLevel(logging.WARNING)

        async def worker_async():
            assigned_proxy = None

            # Track credentials for this worker
            worker_credentials = []
            successful_accounts = 0
            failed_accounts = 0

            # Account distribution - ensure all accounts are covered
            base = num_accounts // num_processes
            extra = num_accounts % num_processes
            start_account = worker_id * base + min(worker_id, extra)
            end_account = start_account + base + (1 if worker_id < extra else 0)
            
            accounts_to_process = end_account - start_account
            logger.info(f"[WORKER {worker_id}] Assigned accounts {start_account+1} to {end_account} ({accounts_to_process} accounts total)")
            logger.info(f"[WORKER {worker_id}] Will process ALL {accounts_to_process} accounts regardless of individual failures")

            # ENSURE PROXY AVAILABILITY
            if config_data.get('use_proxies', False) and not proxy_pool:
                logger.error(f"[WORKER {worker_id}] ERROR: Proxies are required but proxy pool is not available. Worker cannot continue.")
                return

            # Process accounts
            for i in range(start_account, end_account):
                account_num = i + 1
                logger.info(f"[WORKER {worker_id}] Started creating account {account_num}")

                try:
                    # Get proxy if enabled
                    if config_data.get('use_proxies', False) and proxy_pool:
                        assigned_proxy = proxy_pool.get_next_proxy()
                        if not assigned_proxy:
                            logger.warning(f"[WORKER {worker_id}] No proxy available for account {account_num}")
                            failed_accounts += 1
                            continue
                        logger.info(f"[WORKER {worker_id}] Account {account_num} - Using proxy: {assigned_proxy.host}:{assigned_proxy.port}")
                    
                    # Create form filler with proxy
                    filler = DiscordFormFiller(account_number=account_num, proxy=assigned_proxy)
                    
                    # Try to fill form and create account
                    try:
                        token = await filler.fill_form()
                        
                        if token:
                            logger.info(f"[WORKER {worker_id}] Account {account_num} created successfully")
                            successful_accounts += 1
                            
                            # Save credentials
                            if filler.email and filler.password:
                                account_credentials = {
                                    'email': filler.email,
                                    'password': filler.password,
                                    'token': token,
                                    'account_num': account_num,
                                    'status': 'success'
                                }
                                worker_credentials.append(account_credentials)
                        else:
                            logger.warning(f"[WORKER {worker_id}] Failed to create account {account_num}")
                            failed_accounts += 1
                            if assigned_proxy and proxy_pool:
                                proxy_pool.mark_proxy_failed(assigned_proxy)
                    
                    except Exception as e:
                        logger.error(f"[WORKER {worker_id}] Error creating account {account_num}: {str(e)[:100]}")
                        failed_accounts += 1
                        if assigned_proxy and proxy_pool:
                            proxy_pool.mark_proxy_failed(assigned_proxy)
                
                except Exception as e:
                    logger.error(f"[WORKER {worker_id}] Unexpected error for account {account_num}: {str(e)[:100]}")
                    failed_accounts += 1

            # Save credentials quietly
            successful_creds = [c for c in worker_credentials if c['status'] == 'success']
            if successful_creds:
                try:
                    Path('OUTPUT').mkdir(exist_ok=True)
                    summary_file = Path('OUTPUT') / f'worker_{worker_id}_summary.txt'
                    with open(summary_file, 'w', encoding='utf-8') as f:
                        f.write(f"Worker {worker_id} Summary Report\n")
                        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Total processed: {end_account - start_account}\n")
                        f.write(f"Successful: {successful_accounts}\n")
                        f.write(f"Failed: {failed_accounts}\n\n")
                        f.write("Successful Credentials:\n")
                        for cred in successful_creds:
                            f.write(f"{cred['email']}:{cred['password']}:{cred['token']}\n")
                except Exception as e:
                    logger.error(f"[WORKER {worker_id}] Error saving summary: {e}")

            # Worker completion summary
            total_processed = successful_accounts + failed_accounts
            logger.info(f"[WORKER {worker_id}] ✅ COMPLETED: Processed {total_processed}/{accounts_to_process} accounts")
            logger.info(f"[WORKER {worker_id}] ✅ SUCCESS: {successful_accounts} accounts created")
            logger.info(f"[WORKER {worker_id}] ❌ FAILED: {failed_accounts} attempts failed")
            
            if total_processed == accounts_to_process:
                logger.info(f"[WORKER {worker_id}] 🎯 ALL ASSIGNED ACCOUNTS PROCESSED SUCCESSFULLY!")
            else:
                logger.warning(f"[WORKER {worker_id}] ⚠️  WARNING: Only {total_processed}/{accounts_to_process} accounts were processed")

        # Run with timeout
        try:
            asyncio.run(asyncio.wait_for(worker_async(), timeout=36000))  # 10 hours max per worker
        except asyncio.TimeoutError:
            logger.warning(f"[WORKER {worker_id}] Worker process timed out after 10 hours.")
        except Exception as e:
            logger.error(f"[WORKER {worker_id}] Unhandled exception in worker_async: {e}")
            logger.error(traceback.format_exc())
    finally:
        # Force cleanup any remaining resources
        import gc
        gc.collect()

def get_user_input() -> Dict:
    """Gets user input for account creation settings - EXACT PATTERN from UK.py"""
    print("\n=== Discord Account Generator Configuration ===")
    
    # Number of accounts
    while True:
        try:
            num_accounts = int(input("\nHow many accounts do you want to create? (1-50000): "))
            if 1 <= num_accounts <= 50000:
                break
            print("Please enter a number between 1 and 50000")
        except ValueError:
            print("Please enter a valid number")
    
    # Number of processes
    while True:
        try:
            num_processes = int(input("\nHow many parallel processes? (1-20): "))
            if 1 <= num_processes <= 20:
                break
            print("Please enter a number between 1 and 20")
        except ValueError:
            print("Please enter a valid number")
    
    # Ask if user wants to use proxies
    use_proxies = input("\nDo you want to use proxies? (y/n): ").lower() == 'y'
    
    # Load proxies if requested
    proxy_list = []
    if use_proxies:
        try:
            # Try multiple possible proxy file locations
            proxy_files = ['proxies.txt', 'proxies', 'ev gen/proxies.txt']
            proxy_file_found = None
            
            for proxy_file in proxy_files:
                if os.path.exists(proxy_file):
                    proxy_file_found = proxy_file
                    break
            
            if not proxy_file_found:
                print(f"Error: No proxy file found. Tried: {', '.join(proxy_files)}")
                use_proxies = False
            else:
                with open(proxy_file_found, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            proxy_list.append(line)
                
                if proxy_list:
                    print(f"\nSuccessfully loaded {len(proxy_list)} proxies from {proxy_file_found}")
                else:
                    print("No valid proxies found in file")
                    use_proxies = False
        except Exception as e:
            print(f"Error reading proxies file: {str(e)}")
            use_proxies = False
    
    # Humanizer and VPN options
    humanizer_choice = input("\nDo you want to use humanizer (y/n): ").strip().lower()
    use_humanizer = humanizer_choice in ["yes", "y"]
    
    vpn_choice = input("\nDo you want to use VPN (y/n): ").strip().lower()
    use_vpn = vpn_choice in ["yes", "y"]
    
    # Save configuration
    config_data = {
        "num_accounts": num_accounts,
        "num_processes": num_processes,
        "use_proxies": use_proxies,
        "proxy_list": proxy_list if use_proxies else [],
        "use_humanizer": use_humanizer,
        "use_vpn": use_vpn
    }
    
    return config_data

def run_account_creation(config_data: Dict):
    """Main function to run account creation with multiprocessing - EXACT PATTERN from UK.py"""
    num_accounts = config_data['num_accounts']
    num_processes = config_data['num_processes']
    use_proxies = config_data['use_proxies']

    print("\n" + "="*60)
    print(f"Creating {num_accounts} Discord accounts using {num_processes} processes...")
    print(f"Proxy usage: {'Enabled' if use_proxies else 'Disabled'}")
    print("="*60 + "\n")

    if use_proxies:
        proxy_list = config_data.get('proxy_list', [])
        if not proxy_list:
            print("ERROR: Proxies are enabled, but the proxy list is empty.")
            return

        print("=== ENHANCED PROXY ROTATION STRATEGY ===")
        print("📊 PROXY CONFIGURATION:")
        print(f"  Total proxies available: {len(proxy_list)}")
        print(f"  Total accounts to create: {num_accounts}")
        print(f"  Worker processes: {num_processes}")
        print("\n🔄 ROTATION STRATEGY:")
        print("  ✅ Each account = Different proxy (GUARANTEED)")
        print("  ✅ Round-robin rotation through all proxies")
        print("  ✅ Perfect proxy isolation for maximum anonymity")

        if len(proxy_list) < num_accounts:
            print("\n📈 DISTRIBUTION:")
            print(f"  ⚠️  WARNING: Fewer proxies ({len(proxy_list)}) than accounts ({num_accounts})")
            print("  ⚠️  Proxies will be reused, but still rotated for each new account.")
        else:
            print("\n📈 DISTRIBUTION:")
            print("  🎯 PERFECT: More proxies than accounts!")
            print("  🎯 Each account will use a completely different proxy")
        print("="*40)

    # Use multiprocessing Manager to share state
    with multiprocessing.Manager() as manager:
        proxy_pool = None
        if use_proxies:
            proxy_list = config_data.get('proxy_list', [])
            if not proxy_list:
                print("ERROR: Proxies are enabled, but the proxy list is empty.")
                return
            
            proxy_pool = ProxyPool(proxy_list, manager)

        processes = []
        for i in range(num_processes):
            p = multiprocessing.Process(
                target=worker_process,
                args=(i, num_accounts, num_processes, config_data, proxy_pool)
            )
            processes.append(p)
            p.start()
            print(f"✅ Started worker process {i} (PID: {p.pid})")

        print(f"🚀 All {num_processes} worker processes started successfully!")
        print("🔍 Monitoring processes to ensure they all stay active...")

        try:
            import time
            while True:
                # Check if all processes are still alive
                alive_processes = [p for p in processes if p.is_alive()]
                
                if len(alive_processes) != num_processes:
                    dead_count = num_processes - len(alive_processes)
                    print(f"⚠️  WARNING: {dead_count} processes have stopped!")
                    print(f"Active processes: {len(alive_processes)}/{num_processes}")
                
                # Check if all processes are done
                if all(not p.is_alive() for p in processes):
                    print("✅ All worker processes completed their work normally")
                    break
                
                # Status update every 2 minutes
                time.sleep(120)
                active_count = len([p for p in processes if p.is_alive()])
                print(f"📊 Status: {active_count}/{num_processes} processes still active")
                
        except KeyboardInterrupt:
            print("\n⏹️  Process interrupted by user")
            for p in processes:
                if p.is_alive():
                    p.terminate()
                    p.join()

    print("\nAll workers finished.")

async def main():
    """Main entry point with multiprocessing support"""
    try:
        clear_screen()
        set_console_title()
        
        if not check_chrome_installation():
            log("ERROR", "Chrome not installed")
            input("Press Enter to exit...")
            return
        
        print_ascii_logo()
        
        print("\n=== Discord Account Generator ===")
        print("1. Start new session (multiprocessing)")
        print("2. Single account mode (legacy)")
        print("3. Exit")
        
        while True:
            try:
                choice = int(input("\nChoose an option (1-3): "))
                if 1 <= choice <= 3:
                    break
                print("Please enter a number between 1 and 3")
            except ValueError:
                print("Please enter a valid number")
        
        if choice == 3:
            print("\nGoodbye!")
            return
        
        if choice == 2:
            # Legacy single account mode
            configure_user_options()
            
            try:
                filler = DiscordFormFiller(account_number=1)
                token = await filler.fill_form()
                
                if token:
                    log("SUCCESS", "Account created successfully")
                else:
                    log("ERROR", "Account generation failed")
            except Exception as e:
                log("ERROR", f"Error generating account: {e}")
        else:
            # Multiprocessing mode
            config_data = get_user_input()
            
            # Run with multiprocessing
            run_account_creation(config_data)
        
        cleanup_playwright()
        log("SUCCESS", "Finished!")
                
    except KeyboardInterrupt:
        log("SUCCESS", "Exiting...")
    except Exception as e:
        log("ERROR", f"Error: {e}")
        traceback.print_exc()

if __name__ == '__main__':
    # Set up multiprocessing start method
    multiprocessing.set_start_method('spawn', force=True)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProgram interrupted by user. Exiting gracefully...")
    except asyncio.CancelledError:
        print("\nAsyncio tasks were cancelled. Exiting gracefully...")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        traceback.print_exc()

