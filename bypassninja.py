#!/usr/bin/env python3
import requests
import argparse
import random
import json
import sys
import time
import re
import platform
import socket
from urllib.parse import urljoin, urlparse
from colorama import init, Fore, Style, Back
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Event
import traceback 
import subprocess
import ipaddress
import binascii

init(autoreset=True)

VERSION = "1.0.1"


# list of user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    
    # Bots de Google
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.77 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Googlebot-Image/1.0",
    "Googlebot-News",
    "Googlebot-Video/1.0",
    "AdsBot-Google (+http://www.google.com/adsbot.html)",
    "AdsBot-Google-Mobile-Apps",
    "Mozilla/5.0 (compatible; Google-Site-Verification/1.0)",
    
    # Bots de Bing/Microsoft
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534+ (KHTML, like Gecko) BingPreview/1.0b",
    "Mozilla/5.0 (compatible; adidxbot/2.0; +http://www.bing.com/bingbot.htm)",
    "msnbot/2.0b (+http://search.msn.com/msnbot.htm)",
    "Mozilla/5.0 (compatible; MicrosoftPreview/2.0; +https://www.bing.com/bingbot.htm)",
    
    # Yahoo
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    
    # DuckDuckGo
    "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    
    # Baidu
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    
    # Yandex
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)",
    
    # Facebook
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    
    # Twitter/X
    "Twitterbot/1.0",
    
    # LinkedIn
    "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
    
    # Pinterest
    "Mozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)",
    
    # Navegadores más recientes o adicionales
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
]


HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]

HEADERS_BYPASS = [
    {"X-Forwarded-For": "127.0.0.1"}, {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-For": "192.168.1.1"}, {"X-Forwarded-For": "10.0.0.1"},
    {"X-Forwarded-For": "169.254.169.254"}, {"X-Forwarded-For": "2130706433"},
    {"X-Forwarded-Host": "localhost"}, {"X-HTTP-Method-Override": "GET"},
    {"X-Original-URL": "{path}"}, {"X-Rewrite-URL": "{path}"},
    {"X-Custom-IP-Authorization": "127.0.0.1"}, {"X-Real-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"}, {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "localhost"}, {"X-Remote-Addr": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"}, {"Referrer": "https://www.google.com"},
    {"Referer": "https://www.google.com"}, {"Origin": "https://www.google.com"},
    {"CF-Connecting-IP": "127.0.0.1"}, {"True-Client-IP": "127.0.0.1"},
    {"X-WAF-Bypass": "1"}, {"Content-Security-Policy-Report-Only": "*"},
    {"X-ProxyUser-Ip": "127.0.0.1"}, {"X-Bypass-403": "1"},
    {"X-Authorization": "Bearer {random}"}, {"X-Requested-With": "XMLHttpRequest"},
    {"X-Forwarded-Proto": "https"},
    {"X-Forwarded-Proto": "http"},
    {"Ali-CDN-Real-IP": "127.0.0.1"},
    {"X-NF-Client-Connection-IP": "127.0.0.1"},
    {"X-Vercel-Forwarded-For": "127.0.0.1"},
    {"X-Vercel-IP-Country": "US"},
    {"X-Vercel-IP-City": "San Francisco"},
    {"X-Vercel-IP-Timezone": "America/Los_Angeles"},
    {"Cache-Status": "BYPASS"},
    {"X-Cache-Status": "BYPASS"},
    {"X-Served-By": "cache-1"},
    {"X-Forwarded-Scheme": "https"},
    {"Fastly-Client-IP": "127.0.0.1"},
    {"X-Azure-ClientIP": "127.0.0.1"},
    {"X-Azure-SocketIP": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"}
]
# Enhanced path mutations
PATH_MUTATIONS = [
    "{path}", "{path}/", "{path}//", "{path}/.", "{path}/..", "{path}/../",
    "{path}%20", "{path}%09", "{path}?", "{path}??", "{path}?&", "{path}#",
    "{path}%23", "{path}%2e", "{path}.html", "{path}.php", "{path}.json",
    "{path}.xml", "{path}.aspx", "{path}.asp", "{path}.jsp", "{path};",
    "{path};/", "{path};a=1", "/%2e/{path}", "..;/{path}", "/.../{path}",
    "/..%2f{path}", "/..%252f{path}", "/./{path}", "//{path}",
    "{path}?random={random}", "{path}#bypass", "../{path}", "../../{path}",
    "{path}/.json", "{path}?debug=true", "{path}?test=true",
    "{path}?oauth=true", "{path}.bak", "{path}.old", "{path}.original",
    "{path}.txt", "{path}.html.bak", "{path}%2f.%2f", "{path}%252e%252e%252f",
    "{path}/..%2f..%2f", "{path}//..%2f", "{path}/%2f%2e%2e/", "/api/{path}",
    "/public{path}", "/v1{path}", "/v2{path}", "/v3{path}", "/api/v1{path}",
    "/api/v2{path}",
]

# WAF and service signatures
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "cf-chl-bypass", "__cfduid", "cf-request-id", "_cf_bm"],
    "AWS WAF": ["aws-waf-token", "x-amzn-requestid", "x-amz-cf-id", "x-amz-cf-pop"],
    "Akamai": ["akamai", "akamaighost", "akamaicdn", "aka-debug", "x-akamai-transformed"],
    "Imperva/Incapsula": ["incapsula", "visid_incap", "_incapsula_", "incap_ses"],
    "Sucuri": ["sucuri", "x-sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "ModSecurity": ["modsecurity", "mod_security", "was blocked", "blocked by mod_security"],
    "F5 BIG-IP ASM": ["bigip", "ts", "f5apm"],
    "Barracuda": ["barracuda", "barra_counter"],
    "Fastly": ["fastly", "x-fastly", "x-served-by", "x-cache"],
    "Varnish": ["varnish", "x-varnish", "via: varnish"],
    "Nginx": ["nginx", "server: nginx"],
    "Apache": ["apache", "server: apache"],
    "IIS": ["iis", "server: microsoft-iis"],
    "DDoS-Guard": ["ddos-guard", "__ddg"],
    "Wordfence": ["wordfence", "wfCBL"],
    "Radware": ["radware", "x-sl-compstate"],
    "Fortinet/FortiWeb": ["fortinet", "fortiweb", "fortigate", "fortiwebid"],
    "MercadoLibre WAF": ["mercadolibre", "meli", "ml-waf"]
}

# CAPTCHA signatures
CAPTCHA_SIGNATURES = {
    "reCAPTCHA": ["recaptcha", "g-recaptcha", "grecaptcha"],
    "hCaptcha": ["hcaptcha", "h-captcha"],
    "Cloudflare Turnstile": ["turnstile", "cf-turnstile", "cf_challenge"],
    "Arkose Labs": ["arkoselabs", "funcaptcha"],
    "Generic CAPTCHA": ["captcha", "human-verification", "are you human", "bot-detection", "challenge"]
}

# Unicode bypasses
UNICODE_BYPASSES = {
    'zero_width': '\u200B',  # Zero Width Space
    'negative_thin': '\u200C',  # Zero Width Non-Joiner
    'word_joiner': '\u2060',  # Word Joiner
    'soft_hyphen': '\u00AD',  # Soft Hyphen
    'line_separator': '\u2028',  # Line Separator
    'paragraph_separator': '\u2029'  # Paragraph Separator
}
# --- End Constants ---


def generate_ip_variations(ip):
    """Generate different representations of an IPv4 address."""
    try:
        # Validar y convertir la dirección IP
        ip_obj = ipaddress.IPv4Address(ip)
        octets = list(map(int, str(ip_obj).split('.')))
        
        variations = {
            # Formato original
            'ipv4': str(ip_obj),
            
            # Formato octal
            'octal': '.'.join(f'{octet:04o}' for octet in octets),
            
            # Formato hexadecimal
            'hex': '.'.join(f'0x{octet:02X}' for octet in octets),
            
            # Formato binario
            'binary': '.'.join(f'{octet:08b}' for octet in octets),
            
            # Formato decimal parcial
            'partial_decimal': f"{octets[0]}.{octets[1]}.{(octets[2] << 8) + octets[3]}",
            
            # Notación DWORD
            'dword': str(int(ip_obj)),
            
            # Notación DWORD con overflow
            'dword_overflow': str(int(ip_obj) + (2**32 * 10)),
            
            # Dirección IPv6 mapeada (dos formatos)
            'ipv6_mapped': f'::FFFF:{octets[0]:02X}{octets[1]:02X}:{octets[2]:02X}{octets[3]:02X}',
            'ipv6_mapped_dots': f'::FFFF:{ip}'
        }
        
        return variations
    except Exception as e:
        print(f"{Fore.RED}[!] Error generating IP variations: {str(e)}{Style.RESET_ALL}")
        return {}


class BypassBlaster:
    def __init__(self, url, path="/", proxies=None, threads=5, timeout=7, delay=0,
                 verbose=False, retry=2, cookie=None, follow_redirects=False,
                 custom_headers=None, custom_payloads=None, max_requests=None,
                 burst_mode=False, verify_ssl=True, stop_on_success=False):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            print(f"{Fore.YELLOW}[!] No URL scheme provided. Using https://{Style.RESET_ALL}")

        self.url = url.rstrip("/")
        self.path = path if path.startswith("/") else f"/{path}"
        self.proxies = proxies if proxies else {}
        self.threads = threads
        self.timeout = timeout # Use this timeout
        self.delay = delay
        self.verbose = verbose
        self.retry = retry
        self.cookie = cookie
        self.follow_redirects = follow_redirects
        self.custom_headers = custom_headers or {}
        self.custom_payloads = custom_payloads or []
        self.max_requests = max_requests
        self.burst_mode = burst_mode
        self.verify_ssl = verify_ssl
        self.stop_on_success = stop_on_success

        self.results = []
        self.successful_bypasses = []
        self.waf_detected = set()
        self.captcha_detected = False
        self.captcha_types = set()
        self.start_time = None
        self.end_time = None
        self.request_count = 0 # Correctly represents processed futures
        self.success_count = 0
        self.session = requests.Session() # Create session ONCE
        self.stop_event = Event() # Create event here for main thread access
        
        # Añadir contador de errores SSL
        self.ssl_error_count = 0
        self.ssl_error_threshold = 10  # Threshold to stop the script
        self.last_ssl_error = None  # To store the last SSL error

        self.ip_variations = None
        if proxies:
            # Intentar obtener la IP del proxy si existe
            proxy_url = urlparse(proxies.get('http') or proxies.get('https', ''))
            if proxy_url.hostname:
                try:
                    self.ip_variations = generate_ip_variations(socket.gethostbyname(proxy_url.hostname))
                except:
                    pass

    def print_banner(self):
        # --- (Banner ) ---
        banner = r"""
╔══════════════════════════════════════════════════════════════╗
║   ___                             _  ___        _            ║
║  / _ )__ _____  ___ ____ ___     / |/ (_)__    (_)__ _       ║
║ / _  / // / _ \/ _ `(_-<(_-<    /    / / _ \  / / _ `/       ║
║/____/\_, / .__/\_,_/___/___/   /_/|_/_/_//_/_/ /\_,_/        ║
║     /___/_/                               |___/              ║
║────────────────────────────────────────────────────────────  ║
║        BypassNinja  1.0.2  - HTTP 403 Evasion Tool           ║
║                      by @M4rt1n_0x1337                       ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)

    def print_target_info(self):
        # --- (Target info print remains the same) ---
        parsed_url = urlparse(self.url)
        ip = "Unable to resolve"
        try:
            ip = socket.gethostbyname(parsed_url.netloc)
        except socket.gaierror:
             pass # Keep ip as "Unable to resolve"

        print(f"{Fore.CYAN}[Target Information]{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}URL:{Style.RESET_ALL} {self.url}{self.path}")
        print(f"  {Fore.WHITE}Host:{Style.RESET_ALL} {parsed_url.netloc}")
        print(f"  {Fore.WHITE}IP:{Style.RESET_ALL} {ip}")
        print(f"  {Fore.WHITE}Protocol:{Style.RESET_ALL} {parsed_url.scheme}")
        print(f"  {Fore.WHITE}Threads:{Style.RESET_ALL} {self.threads}")
        print(f"  {Fore.WHITE}Proxy:{Style.RESET_ALL} {self.proxies.get('http', 'None')}")
        print(f"  {Fore.WHITE}SSL Verification:{Style.RESET_ALL} {'Enabled' if self.verify_ssl else 'Disabled'}")
        print(f"  {Fore.WHITE}Stop on Success:{Style.RESET_ALL} {'Enabled' if self.stop_on_success else 'Disabled'}")
        print(f"  {Fore.WHITE}Retries:{Style.RESET_ALL} {self.retry}")
        print(f"  {Fore.WHITE}Timeout:{Style.RESET_ALL} {self.timeout}s")
        print(f"  {Fore.WHITE}Start Time:{Style.RESET_ALL} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()


    def get_random_user_agent(self):
        return random.choice(USER_AGENTS)

    def mutate_path(self, path):
        # --- (Mutate path remains the same) ---
        random_str = str(random.randint(1000, 9999))
        mutations = [mutation.format(path=path, random=random_str) for mutation in PATH_MUTATIONS]
        if self.custom_payloads:
            for payload in self.custom_payloads:
                 # Ensure custom payloads also get formatting if placeholders are used
                 try:
                     mutations.append(payload.format(path=path, random=random_str))
                 except KeyError: # Handle case where format strings are not expected/present
                     mutations.append(payload)
        return mutations

    def detect_waf(self, response):
        # --- (WAF detection remains the same) ---
        detected_wafs = []
        headers_str = str(response.headers).lower()
        content = ""
        try:
             # Limit content check size and handle potential decoding errors
             content = response.text[:10000].lower()
        except Exception:
             pass # Ignore content check if text decoding fails

        for waf_name, signatures in WAF_SIGNATURES.items():
            for signature in signatures:
                sig_lower = signature.lower()
                if sig_lower in headers_str or (content and sig_lower in content):
                    # Check self.waf_detected first to avoid redundant adds to list if already found
                    if waf_name not in self.waf_detected:
                        detected_wafs.append(waf_name)
                    self.waf_detected.add(waf_name) # Add to set regardless
                    break # Only add each WAF name once per response check

        return detected_wafs


    def detect_captcha(self, response):
        # --- (CAPTCHA detection remains the same) ---
        detected_captcha = []
        content = ""
        try:
            content = response.text[:10000].lower()
        except Exception:
            pass

        if not content: return [] # Skip if no content

        for captcha_type, signatures in CAPTCHA_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in content:
                    if captcha_type not in self.captcha_types:
                         detected_captcha.append(captcha_type)
                    self.captcha_detected = True
                    self.captcha_types.add(captcha_type)
                    break
        return detected_captcha


    def check_response_status_text(self, status_code):
        # --- (Status text helper remains the same) ---
        if status_code in [200, 201]: return f"{Fore.GREEN}SUCCESS{Style.RESET_ALL}"
        if status_code in [301, 302, 307, 308]: return f"{Fore.BLUE}REDIRECT{Style.RESET_ALL}"
        if status_code in [401, 403]: return f"{Fore.RED}BLOCKED{Style.RESET_ALL}"
        if status_code == 400: return f"{Fore.RED}BAD REQUEST{Style.RESET_ALL}" # Added 400
        if status_code == 429: return f"{Fore.MAGENTA}RATE LIMITED{Style.RESET_ALL}"
        if status_code == 503: return f"{Fore.YELLOW}SERVICE UNAVAILABLE{Style.RESET_ALL}"
        return f"{Fore.YELLOW}OTHER ({status_code}){Style.RESET_ALL}"


    def generate_headers_with_ip_bypass(self, base_headers):
        """Generate headers with different IP representations."""
        if not self.ip_variations:
            return [base_headers]
        
        headers_variations = []
        ip_headers = {
            'X-Forwarded-For': ['ipv4', 'ipv6_mapped', 'dword'],
            'X-Real-IP': ['ipv4', 'hex', 'octal'],
            'X-Client-IP': ['ipv4', 'partial_decimal'],
            'CF-Connecting-IP': ['ipv4', 'ipv6_mapped_dots']
        }
        
        for header, formats in ip_headers.items():
            for fmt in formats:
                if fmt in self.ip_variations:
                    new_headers = base_headers.copy()
                    new_headers[header] = self.ip_variations[fmt]
                    headers_variations.append(new_headers)
        
        return headers_variations

    def try_request(self, method, url, headers=None, retry_count=0):
        """Performs a single request attempt. Uses self.stop_event internally."""
        if self.stop_event.is_set():
            return None

        req_headers = headers.copy() if headers else {}

        # Generar variaciones de headers con diferentes representaciones de IP
        headers_to_try = self.generate_headers_with_ip_bypass(req_headers)
        
        # Añadir variaciones Unicode al path
        url_variations = [url]
        parsed = urlparse(url)
        path = parsed.path
        
        # Añadir bypass Unicode al path
        for bypass_char in UNICODE_BYPASSES.values():
            new_path = path.replace('/', f'/{bypass_char}')
            new_url = parsed._replace(path=new_path).geturl()
            url_variations.append(new_url)

        for current_headers in headers_to_try:
            for current_url in url_variations:
                if self.stop_event.is_set():
                    return None

                try:
                    # Prepare request details
                    current_headers["User-Agent"] = self.get_random_user_agent()
                    if self.custom_headers:
                        current_headers.update(self.custom_headers)
                    cookies = {}
                    if self.cookie:
                        for cookie_pair in self.cookie.split(';'):
                            if '=' in cookie_pair:
                                key, value = cookie_pair.strip().split('=', 1)
                                cookies[key] = value

                    if self.delay > 0 and not self.burst_mode:
                        if self.stop_event.is_set(): return None
                        time.sleep(self.delay)

                    if self.stop_event.is_set(): return None

                    response = self.session.request(
                        method=method,
                        url=current_url,
                        headers=current_headers,
                        proxies=self.proxies,
                        timeout=self.timeout,
                        allow_redirects=self.follow_redirects,
                        cookies=cookies if cookies else None,
                        verify=self.verify_ssl
                    )

                    status = response.status_code
                    size = len(response.content)
                    is_stop_worthy = status in [200, 201, 301, 302, 307, 308]
                    is_actual_bypass = status in [200, 201, 302]

                    # Detect WAF/Captcha
                    detected_wafs = self.detect_waf(response)
                    detected_captchas = self.detect_captcha(response)

                    result_data = {
                        "method": method,
                        "url": current_url,
                        "headers": current_headers,
                        "status": status,
                        "size": size,
                        "success": is_actual_bypass,
                        "waf": detected_wafs,
                        "captcha": detected_captchas,
                        "response_headers": dict(response.headers),
                        "content_preview": ""
                    }

                    # Get content preview carefully
                    try:
                        if is_actual_bypass:
                            result_data["content_preview"] = response.text[:200]
                        elif is_stop_worthy:
                            result_data["content_preview"] = f"Redirect to: {response.headers.get('Location', 'N/A')}"
                    except Exception:
                        result_data["content_preview"] = "[Error decoding content]"

                    # --- Stop Signal Logic ---
                    if self.stop_on_success and is_stop_worthy:
                        status_text = self.check_response_status_text(status)
                        print(f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} [{method}] {current_url} | Status: {status_text} {status} | Size: {size}")
                        return {"stop_signal": True, "result": result_data}

                    # Normal Printing Logic
                    status_text = self.check_response_status_text(status)
                    if is_actual_bypass:
                        print(f"{Fore.GREEN}[HIT]{Style.RESET_ALL} [{method}] {current_url} | Status: {status_text} {status} | Size: {size}")
                    elif self.verbose:
                        print(f"[{method}] {current_url} | Status: {status_text} {status} | Size: {size}")

                    return {"stop_signal": False, "result": result_data}

                # Error Handling
                except requests.exceptions.Timeout as e:
                    if self.verbose: print(f"{Fore.YELLOW}[TIMEOUT]{Style.RESET_ALL} {method} {current_url} - {str(e)}")
                    if retry_count < self.retry:
                        return self.try_request(method, current_url, current_headers, retry_count + 1)
                    return None
                except requests.exceptions.SSLError as e:
                    error_message = str(e)
                    
                    # Check if it's the same error as before
                    if self.last_ssl_error == error_message:
                        self.ssl_error_count += 1
                    else:
                        # If it's a different error, reset the counter
                        self.ssl_error_count = 1
                        self.last_ssl_error = error_message
                    
                    if self.verify_ssl:
                        print(f"{Fore.YELLOW}[SSL ERROR]{Style.RESET_ALL} {method} {current_url} - {error_message}")
                        
                        # If the SSL error threshold is reached, stop the script
                        if self.ssl_error_count >= self.ssl_error_threshold:
                            print(f"\n{Fore.RED}[!!!] TOO MANY REPEATED SSL ERRORS ({self.ssl_error_count}){Style.RESET_ALL}")
                            print(f"{Fore.RED}[!!!] Stopping the script to prevent further errors.{Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}[TIP]{Style.RESET_ALL} Try running the script with the --no-verify option to ignore SSL verification")
                            self.stop_event.set()  # Signal all threads to stop
                    return None
                except requests.exceptions.RequestException as e:
                    if self.verbose: print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {method} {current_url} - {type(e).__name__}: {str(e)}")
                    if retry_count < self.retry:
                        return self.try_request(method, current_url, current_headers, retry_count + 1)
                    return None
                except Exception as e:
                    print(f"{Fore.RED}[UNEXPECTED WORKER ERROR]{Style.RESET_ALL} {method} {current_url} - {type(e).__name__}: {str(e)}")
                    traceback.print_exc()
                    return None


    def run(self):
        self.print_banner()
        self.print_target_info()

        print(f"{Fore.CYAN}=== Starting bypass attempts on {self.url}{self.path} ==={Style.RESET_ALL}")

        self.start_time = time.time()

        # --- Initial Probe ---
        print(f"{Fore.YELLOW}[+] Performing initial probe...{Style.RESET_ALL}")
        probe_success = False
        try:
            probe_response = self.session.get(
                urljoin(self.url, self.path),
                headers={"User-Agent": self.get_random_user_agent()},
                proxies=self.proxies,
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_ssl
            )
            probe_success = True # Mark as successful if request completes
            if probe_response.status_code in [301, 302, 307, 308] and 'Location' in probe_response.headers:
                redirect_url = probe_response.headers['Location']
                print(f"{Fore.YELLOW}[!] Initial probe resulted in redirect: {probe_response.status_code} -> {redirect_url}{Style.RESET_ALL}")
            wafs = self.detect_waf(probe_response) # Use instance method
            if wafs:
                print(f"{Fore.YELLOW}[!] Detected WAF/Security Service: {', '.join(wafs)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] No common WAF detected or signature unknown{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[+] Baseline response: Status {probe_response.status_code}, Size {len(probe_response.content)}{Style.RESET_ALL}")

        except requests.exceptions.SSLError as e:
            print(f"{Fore.RED}[!] SSL Error during initial probe: {str(e)}{Style.RESET_ALL}")
            if self.verify_ssl: print(f"{Fore.YELLOW}[TIP]{Style.RESET_ALL} Try running with --no-verify")
        except requests.exceptions.Timeout:
             print(f"{Fore.RED}[!] Timeout during initial probe.{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Failed to perform initial probe: {type(e).__name__}: {str(e)}{Style.RESET_ALL}")
        print() # Newline after probe info or error


        # --- Prepare Test Cases with Validation ---
        mutated_paths = self.mutate_path(self.path)
        methods_to_try = HTTP_METHODS if not self.burst_mode else ["GET", "POST"]
        test_cases = []
        unique_test_combos = set()
        base_netloc = urlparse(self.url).netloc  # Obtener el nombre de host esperado

        print(f"{Fore.CYAN}[+] Generating and validating test cases...{Style.RESET_ALL}")
        for method in methods_to_try:
            for path_mutation in mutated_paths:
                # --- URL VALIDATION ---
                try:
                    full_url = urljoin(self.url, path_mutation)
                    parsed_full_url = urlparse(full_url)
                    # Verificar si el nombre de host es válido y coincide con el original
                    if not parsed_full_url.netloc or parsed_full_url.netloc != base_netloc:
                        if self.verbose: print(f"{Fore.YELLOW}[SKIP INVALID URL]{Style.RESET_ALL} Mutation '{path_mutation}' generated invalid host: {parsed_full_url.netloc}")
                        continue  # Saltar esta mutación
                except ValueError as e:  # Capturar errores potenciales durante urljoin/urlparse
                    if self.verbose: print(f"{Fore.RED}[URL GEN ERROR]{Style.RESET_ALL} Mutation '{path_mutation}' failed: {e}")
                    continue  # Saltar esta mutación

                # --- Test Case Addition (Base and Headers) ---
                base_headers_tuple = tuple()
                combo = (method, full_url, base_headers_tuple)
                if combo not in unique_test_combos:
                    test_cases.append((method, full_url, {}))
                    unique_test_combos.add(combo)

                # Header cases
                for header_template in HEADERS_BYPASS:
                    try:
                        headers = {k: v.format(path=self.path, random=str(random.randint(1000, 9999)))
                                   if isinstance(v, str) and ("{path}" in v or "{random}" in v) else v
                                   for k, v in header_template.items()}
                        headers_tuple = tuple(sorted(headers.items()))
                        combo = (method, full_url, headers_tuple)
                        if combo not in unique_test_combos:
                            test_cases.append((method, full_url, headers))
                            unique_test_combos.add(combo)
                    except KeyError as e:  # Error al formatear el valor del encabezado
                        if self.verbose: print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} Header formatting error ({e}): {header_template}")


        total_combinations = len(test_cases) # This is the actual number submitted

        if total_combinations == 0:
             print(f"{Fore.RED}[!] No test cases generated. Check path mutations and methods.{Style.RESET_ALL}")
             return # Exit run method

        # Apply max_requests limit if set
        if self.max_requests is not None and self.max_requests < total_combinations:
            print(f"{Fore.YELLOW}[!] Limiting requests to {self.max_requests} (randomly selected from {total_combinations}){Style.RESET_ALL}")
            random.shuffle(test_cases)
            test_cases = test_cases[:self.max_requests]
            total_combinations = len(test_cases) # Update total_combinations to the limited number

        print(f"{Fore.CYAN}[+] Actual combinations to test: {total_combinations}{Style.RESET_ALL}")


        # --- Execute Requests using as_completed ---
        processed_requests = 0 # Renamed from self.request_count to avoid confusion
        submitted_requests = 0
        futures = set()
        first_success_result = None # Store the result that triggered the stop
        stop_triggered = False # Flag for main loop

        print(f"{Fore.CYAN}[+] Starting bypass attempts...{Style.RESET_ALL}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit initial batch or all tasks
            for method, url, headers in test_cases:
                 # Check stop event *before* submitting more tasks if stop_on_success is True
                 if self.stop_event.is_set():
                      break
                 future = executor.submit(self.try_request, method, url, headers, 0)
                 futures.add(future)
                 submitted_requests += 1

            print(f"{Fore.CYAN}[+] {submitted_requests} tasks submitted. Processing results as they complete...{Style.RESET_ALL}")

            # Process results using as_completed
            for future in as_completed(futures):
                processed_requests += 1
                if stop_triggered:  # Saltar el procesamiento si ya se detuvo
                    try: future.result()
                    except Exception: pass
                    continue

                try:
                    task_output = future.result()
                    if task_output:
                        result_data = task_output.get("result")
                        stop_signal = task_output.get("stop_signal", False)

                        if self.stop_on_success and stop_signal:
                            if not stop_triggered:
                                print(f"\n{Fore.YELLOW}[!!!] STOP SIGNAL RECEIVED! (Status: {result_data.get('status', 'N/A')}). Signaling threads...{Style.RESET_ALL}")
                                self.stop_event.set()  # SET THE EVENT!
                                first_success_result = result_data  # Store the triggering result
                                stop_triggered = True  # Set flag for subsequent iterations

                        # --- Handle Normal Success (2xx) ---
                        elif result_data and result_data['success']:
                            self.successful_bypasses.append(result_data)

                except Exception as exc:
                    print(f'{Fore.RED}[!] Main loop error processing future result: {exc}{Style.RESET_ALL}')
                    traceback.print_exc()

                # --- Progress Update ---
                if processed_requests % 100 == 0 or processed_requests == total_combinations:
                      if total_combinations > 0:
                           progress = (processed_requests / total_combinations) * 100
                           status_line = f"\r{Fore.CYAN}[+] Progress: {progress:.1f}% ({processed_requests}/{total_combinations}){Style.RESET_ALL}"
                           sys.stdout.write(status_line.ljust(80)) # Pad to overwrite previous line
                           sys.stdout.flush()

        # --- End Execution ---
        print() # Newline after progress indicator

        # Finalize results
        self.request_count = processed_requests # Update instance count

        # If we stopped early via stop_on_success, ensure the triggering result is added if it was a 2xx bypass
        if first_success_result and first_success_result['success']:
             is_already_added = any(
                 b['url'] == first_success_result['url'] and b['method'] == first_success_result['method']
                 for b in self.successful_bypasses
             )
             if not is_already_added:
                 self.successful_bypasses.append(first_success_result)

        self.success_count = len(self.successful_bypasses) # Final count
        self.end_time = time.time()
        self.print_summary() # Call summary regardless of stopping


    def print_summary(self):
        # --- (Summary print remains largely the same) ---
        elapsed_time = self.end_time - self.start_time if self.end_time and self.start_time else 0

        print(f"\n{Fore.CYAN}=== BypassBlaster Summary ==={Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Target:{Style.RESET_ALL} {self.url}{self.path}")
        print(f"  {Fore.WHITE}Requests Processed:{Style.RESET_ALL} {self.request_count}") # Count of completed futures
        print(f"  {Fore.WHITE}Successful Bypasses (2xx):{Style.RESET_ALL} {self.success_count}")
        if elapsed_time > 0:
            req_per_sec = self.request_count / elapsed_time
            print(f"  {Fore.WHITE}Time Elapsed:{Style.RESET_ALL} {elapsed_time:.2f} seconds ({req_per_sec:.2f} req/sec)")
        else:
            print(f"  {Fore.WHITE}Time Elapsed:{Style.RESET_ALL} < 0.01 seconds")

        if self.waf_detected: print(f"  {Fore.WHITE}WAF Detected:{Style.RESET_ALL} {', '.join(sorted(list(self.waf_detected)))}")
        else: print(f"  {Fore.WHITE}WAF Detected:{Style.RESET_ALL} None detected or unknown")
        if self.captcha_detected: print(f"  {Fore.WHITE}CAPTCHA Detected:{Style.RESET_ALL} {', '.join(sorted(list(self.captcha_types)))}")

        if self.successful_bypasses:
            print(f"\n{Fore.GREEN}=== Successful Bypasses (Status 2xx) ==={Style.RESET_ALL}")
            sorted_bypasses = sorted(self.successful_bypasses, key=lambda x: (x['url'], x['method']))
            for i, bypass in enumerate(sorted_bypasses[:10], 1):
                print(f"  {i}. [{bypass['method']}] {bypass['url']}")
                print(f"     Status: {bypass['status']}, Size: {bypass['size']}")
                # Show relevant headers used for this specific successful request
                relevant_headers = {k: v for k, v in bypass['headers'].items() if k.lower() not in ['user-agent', 'accept', 'accept-encoding', 'connection', 'content-length']}
                if relevant_headers: print(f"     Request Headers: {json.dumps(relevant_headers)}")
                if bypass['waf']: print(f"     WAF Notes: {', '.join(bypass['waf'])}")
                # Add content preview if available
                if bypass.get('content_preview'): print(f"     Content Preview: {bypass['content_preview'][:100]}...") # Limit length

            if len(sorted_bypasses) > 10: print(f"  ... and {len(sorted_bypasses) - 10} more.")
        elif self.stop_on_success and first_success_result: # Check if stopped for non-2xx
             print(f"\n{Fore.BLUE}=== Stopped on First Success/Redirect ==={Style.RESET_ALL}")
             print(f"  - [{first_success_result['method']}] {first_success_result['url']}")
             print(f"    Status: {first_success_result['status']}, Size: {first_success_result['size']}")
             if first_success_result.get('content_preview'): print(f"    Preview: {first_success_result['content_preview'][:100]}...")
        else:
             print(f"\n{Fore.RED}No successful bypasses (Status 2xx) found.{Style.RESET_ALL}")

        # Suggestions
        if self.success_count == 0 and not (self.stop_on_success and first_success_result):
             print(f"\n{Fore.YELLOW}[!] Suggestions for improving results:{Style.RESET_ALL}")
             print(f"  - Target might require specific cookies: {Fore.CYAN}--cookie \"name=value;...\"{Style.RESET_ALL}")
             print(f"  - Try different/custom headers: {Fore.CYAN}--headers '{{\"Header\": \"Value\"}}'{Style.RESET_ALL}")
             print(f"  - Try custom path payloads: {Fore.CYAN}--payloads <payload_file>{Style.RESET_ALL}")
             print(f"  - If redirects occur, consider targeting the final URL or use {Fore.CYAN}--follow-redirects{Style.RESET_ALL}")
             print(f"  - Adjust timeout/retries: {Fore.CYAN}--timeout 15 --retry 2{Style.RESET_ALL}")
             print(f"  - Use a proxy: {Fore.CYAN}--proxy http://...{Style.RESET_ALL}")
             print(f"  - Disable SSL verification if needed: {Fore.CYAN}--no-verify{Style.RESET_ALL}")
             print(f"  - Check verbose output for errors: {Fore.CYAN}-v{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")


    def save_results(self, output_file):
         # --- (Save results remains largely the same) ---
        output = {
            "target": f"{self.url}{self.path}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_requests_processed": self.request_count,
                "successful_bypasses_2xx": self.success_count,
                "time_elapsed_seconds": self.end_time - self.start_time if self.end_time and self.start_time else 0,
                "waf_detected": sorted(list(self.waf_detected)),
                "captcha_detected": sorted(list(self.captcha_types)) if self.captcha_detected else []
            },
            "successful_bypasses": [ # Only saves 2xx results
                {
                    "method": bypass["method"],
                    "url": bypass["url"],
                    "status": bypass["status"],
                    "size": bypass["size"],
                    "request_headers": {k: v for k, v in bypass["headers"].items() if k.lower() != "user-agent"}, # Exclude UA
                    "response_headers": bypass["response_headers"],
                    "waf_detected": bypass["waf"],
                    "captcha_detected": bypass["captcha"],
                    "content_preview": bypass.get("content_preview", "") # Include preview
                } for bypass in sorted(self.successful_bypasses, key=lambda x: (x['url'], x['method']))
            ]
        }
        # Add the first success if stopped early and it wasn't a 2xx already saved
        if self.stop_on_success and first_success_result and not first_success_result['success']:
             output["stopped_on_redirect"] = {
                  "method": first_success_result["method"],
                  "url": first_success_result["url"],
                  "status": first_success_result["status"],
                  "size": first_success_result["size"],
                  "request_headers": {k: v for k, v in first_success_result["headers"].items() if k.lower() != "user-agent"},
                  "response_headers": first_success_result["response_headers"],
                   "content_preview": first_success_result.get("content_preview", "")
             }

        try:
            with open(output_file, 'w') as f:
                json.dump(output, f, indent=4)
            print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {str(e)}{Style.RESET_ALL}")


# Store first_success_result globally or pass it around if needed outside run()
first_success_result = None

def update_script():
    """Update the script by pulling the latest changes from the repository."""
    try:
        # Ejecutar el comando git pull para actualizar el repositorio
        result = subprocess.run(['git', 'pull'], check=True, capture_output=True, text=True)
        print(result.stdout)
        print("The script has been updated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error updating the script: {e.stderr}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description=f"BypassNinja v{VERSION} - HTTP Evasion Tool")

    # --- (Arguments remain the same) ---
    parser.add_argument("url", nargs='?', help="Target URL (e.g. https://example.com)")
    parser.add_argument("-p", "--path", default="/", help="Path to test (default: /)")
    parser.add_argument("-o", "--output", help="Output file for results (JSON format)")
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080 or socks5h://127.0.0.1:1080)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (float, default: 10.0)")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests per thread in seconds (default: 0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show all non-successful attempts)")
    parser.add_argument("-r", "--retry", type=int, default=1, help="Number of retries for failed requests (default: 1)")
    parser.add_argument("-c", "--cookie", help="Cookies string (e.g. 'name1=value1; name2=value2') or file path containing cookies")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects (may impact bypass detection)")
    parser.add_argument("--headers", help="Custom headers as JSON string ('{\"H\": \"V\"}') or path to a JSON file")
    parser.add_argument("--payloads", help="File containing custom path mutation payloads (one per line)")
    parser.add_argument("--max-requests", type=int, help="Maximum number of requests to make (randomly selected)")
    parser.add_argument("--burst", action="store_true", help="Burst mode (uses only GET/POST methods)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--stop-on-success", action="store_true", help="Stop after the first success (2xx) or redirect (3xx)")
    parser.add_argument("--update", "-u", action="store_true", help="Update the script from the repository")

    args = parser.parse_args()

    # Check if the update flag is set
    if args.update:
        update_script()
        sys.exit(0)

    # Check if URL is provided when not updating
    if not args.url:
        parser.error("the following arguments are required: url")

    # --- Handle Proxy ---
    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    # --- Handle Custom Headers ---
    custom_headers = {}
    if args.headers:
        if args.headers.startswith('{'): # Assume JSON string
             try: custom_headers = json.loads(args.headers)
             except json.JSONDecodeError:
                  print(f"{Fore.RED}[!] Invalid JSON in --headers argument.{Style.RESET_ALL}"); sys.exit(1)
        else: # Assume file path
             try:
                  with open(args.headers, 'r') as f: custom_headers = json.load(f)
             except FileNotFoundError: print(f"{Fore.RED}[!] Headers file not found: {args.headers}{Style.RESET_ALL}"); sys.exit(1)
             except json.JSONDecodeError: print(f"{Fore.RED}[!] Invalid JSON in headers file: {args.headers}{Style.RESET_ALL}"); sys.exit(1)
             except Exception as e: print(f"{Fore.RED}[!] Error reading headers file: {e}{Style.RESET_ALL}"); sys.exit(1)
        if not isinstance(custom_headers, dict):
             print(f"{Fore.RED}[!] Custom headers must be a JSON object (dictionary).{Style.RESET_ALL}"); sys.exit(1)

     # --- Handle Cookies ---
    cookie_input = args.cookie
    if cookie_input and not ('=' in cookie_input and ';' in cookie_input) and not '=' in cookie_input:
        # If it doesn't look like a cookie string, assume it's a file path
        try:
            with open(cookie_input, 'r') as f:
                cookie_input = f.read().strip()
            print(f"{Fore.CYAN}[+] Loaded cookies from file: {args.cookie}{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Cookie file not found: {args.cookie}{Style.RESET_ALL}")
            cookie_input = None # Reset to none if file not found
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading cookie file: {e}{Style.RESET_ALL}")
            cookie_input = None


    # --- Handle Custom Payloads ---
    custom_payloads = []
    if args.payloads:
        try:
            with open(args.payloads, 'r') as f:
                custom_payloads = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            print(f"{Fore.CYAN}[+] Loaded {len(custom_payloads)} custom payloads from {args.payloads}{Style.RESET_ALL}")
        except FileNotFoundError: print(f"{Fore.RED}[!] Payloads file not found: {args.payloads}{Style.RESET_ALL}"); sys.exit(1)
        except Exception as e: print(f"{Fore.RED}[!] Error reading payloads file: {e}{Style.RESET_ALL}"); sys.exit(1)


    blaster = None 
    try:
        blaster = BypassBlaster(
            url=args.url,
            path=args.path,
            proxies=proxies,
            threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
            verbose=args.verbose,
            retry=args.retry,
            cookie=cookie_input, # Use processed cookie input
            follow_redirects=args.follow_redirects,
            custom_headers=custom_headers,
            custom_payloads=custom_payloads,
            max_requests=args.max_requests,
            burst_mode=args.burst,
            verify_ssl=not args.no_verify,
            stop_on_success=args.stop_on_success
        )

        blaster.run() # stop_event is now self.stop_event within blaster

        # Save results should happen *after* run() completes naturally or stops
        if args.output and blaster: # Check if blaster object exists
             blaster.save_results(args.output)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Execution interrupted by user. Signaling threads to stop...{Style.RESET_ALL}")
        if blaster and hasattr(blaster, 'stop_event'):
            blaster.stop_event.set() # Signal worker threads
            print(f"{Fore.YELLOW}[!] Stop event set. Allowing threads to finish current request...{Style.RESET_ALL}")
            # Optional: Add a small delay to allow threads to potentially react before force exit,
            # but sys.exit(0) should eventually terminate anyway.
            # time.sleep(1)
        else:
             print(f"{Fore.YELLOW}[!] Blaster object not fully initialized, cannot signal threads gracefully.{Style.RESET_ALL}")
        sys.exit(130) # Standard exit code for Ctrl+C
    except Exception as e:
        print(f"\n{Fore.RED}[!] An unexpected error occurred in main: {str(e)}{Style.RESET_ALL}")
        traceback.print_exc()
        # Try to signal threads even on unexpected error if possible
        if blaster and hasattr(blaster, 'stop_event'):
             blaster.stop_event.set()
        sys.exit(1)


if __name__ == "__main__":
    # Assign the global variable here AFTER the class definition
    first_success_result = None
    main()
