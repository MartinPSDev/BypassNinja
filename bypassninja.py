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
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
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

        self.results = [] # Can store all results if needed later
        self.successful_bypasses = [] # Store only actual successful bypasses (2xx)
        self.waf_detected = set()
        self.captcha_detected = False
        self.captcha_types = set()
        self.start_time = None
        self.end_time = None
        self.request_count = 0 # Total requests attempted
        self.success_count = 0 # Count of successful bypasses (2xx) added to list
        self.session = requests.Session()

    def print_banner(self):
        # --- (Banner code remains the same) ---
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
        # --- (Target info print remains the same) ---
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
        print(f"  {Fore.WHITE}Stop on Success:{Style.RESET_ALL} {'Enabled' if self.stop_on_success else 'Disabled'}") # Added this
        print(f"  {Fore.WHITE}Start Time:{Style.RESET_ALL} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()


    def get_random_user_agent(self):
        return random.choice(USER_AGENTS)

    def mutate_path(self, path):
        # --- (Mutate path remains the same) ---
        random_str = str(random.randint(1000, 9999))
        mutations = [mutation.format(path=path, random=random_str) for mutation in PATH_MUTATIONS]

        # Add custom payloads if provided
        if self.custom_payloads:
            for payload in self.custom_payloads:
                mutations.append(payload.format(path=path, random=random_str))

        return mutations

    def detect_waf(self, response):
        # --- (WAF detection remains the same) ---
        detected_wafs = []

        # Check headers for WAF signatures
        headers_str = str(response.headers).lower()
        # Limit content check size for performance
        content = response.text[:10000].lower() if response.text else ""

        for waf_name, signatures in WAF_SIGNATURES.items():
            for signature in signatures:
                sig_lower = signature.lower()
                if sig_lower in headers_str or sig_lower in content:
                    detected_wafs.append(waf_name)
                    self.waf_detected.add(waf_name)
                    break # Only add each WAF name once per response

        return detected_wafs

    def detect_captcha(self, response):
        # --- (CAPTCHA detection remains the same) ---
        content = response.text[:10000].lower() if response.text else "" # Limit check size
        detected_captcha = []

        for captcha_type, signatures in CAPTCHA_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in content:
                    detected_captcha.append(captcha_type)
                    self.captcha_detected = True
                    self.captcha_types.add(captcha_type)
                    break

        return detected_captcha

    def check_response_status_text(self, status_code):
        """Helper to get colored status text for printing."""
        if status_code in [200, 201]:
            return f"{Fore.GREEN}SUCCESS{Style.RESET_ALL}"
        elif status_code in [301, 302, 307, 308]:
            return f"{Fore.BLUE}REDIRECT{Style.RESET_ALL}"
        elif status_code in [401, 403]:
            return f"{Fore.RED}BLOCKED{Style.RESET_ALL}"
        elif status_code == 429:
            return f"{Fore.MAGENTA}RATE LIMITED{Style.RESET_ALL}"
        elif status_code == 503:
            return f"{Fore.YELLOW}SERVICE UNAVAILABLE{Style.RESET_ALL}"
        else:
            return f"{Fore.YELLOW}OTHER ({status_code}){Style.RESET_ALL}"

    def try_request(self, method, url, headers=None, retry_count=0, stop_event=None):
        """Performs a single request attempt."""
        if stop_event and stop_event.is_set():
            return None

        req_headers = headers.copy() if headers else {}

        try:
            local_session = requests.Session()
            req_headers["User-Agent"] = self.get_random_user_agent()
            if self.custom_headers:
                req_headers.update(self.custom_headers)
            cookies = {}
            if self.cookie:
                for cookie_pair in self.cookie.split(';'):
                    if '=' in cookie_pair:
                        key, value = cookie_pair.strip().split('=', 1)
                        cookies[key] = value

            response = local_session.request(
                method=method,
                url=url,
                headers=req_headers,
                proxies=self.proxies,
                timeout=2,
                allow_redirects=self.follow_redirects,
                cookies=cookies if cookies else None,
                verify=self.verify_ssl
            )

            status = response.status_code
            is_stop_worthy_success = status in [200, 201, 301, 302, 307, 308]

            if self.stop_on_success and is_stop_worthy_success:
                return {"stop_signal": True, "result": {"status": status, "url": url}}

            return {"stop_signal": False, "result": {"status": status, "url": url}}

        except requests.exceptions.RequestException as e:
            return None

    def run(self):
        self.print_banner()
        self.print_target_info()

        print(f"{Fore.CYAN}=== Starting bypass attempts on {self.url}{self.path} ==={Style.RESET_ALL}")

        self.start_time = time.time()
        mutated_paths = self.mutate_path(self.path)

        # --- Initial Probe ---
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
            if probe_response.status_code in [301, 302, 307, 308] and 'Location' in probe_response.headers:
                redirect_url = probe_response.headers['Location']
                print(f"{Fore.YELLOW}[!] Initial probe resulted in redirect: {probe_response.status_code} -> {redirect_url}{Style.RESET_ALL}")
            wafs = self.detect_waf(probe_response)
            if wafs:
                print(f"{Fore.YELLOW}[!] Detected WAF/Security Service: {', '.join(wafs)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] No common WAF detected or signature unknown{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[+] Baseline response: Status {probe_response.status_code}, Size {len(probe_response.content)}{Style.RESET_ALL}")
            print()
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Failed to perform initial probe: {str(e)}{Style.RESET_ALL}")
            print()

        # --- Prepare Test Cases ---
        methods_to_try = HTTP_METHODS if not self.burst_mode else ["GET", "POST"]
        test_cases = []
        for method in methods_to_try:
            for path_mutation in mutated_paths:
                full_url = urljoin(self.url, path_mutation)
                test_cases.append((method, full_url, {}))
                for header_template in HEADERS_BYPASS:
                    headers = {k: v.format(path=self.path, random=str(random.randint(1000, 9999)))
                              if isinstance(v, str) and ("{path}" in v or "{random}" in v) else v
                              for k, v in header_template.items()}
                    test_cases.append((method, full_url, headers))

        total_combinations = len(test_cases)
        if self.max_requests is not None and self.max_requests < total_combinations:
            random.shuffle(test_cases)
            test_cases = test_cases[:self.max_requests]
            total_combinations = self.max_requests
        print(f"{Fore.CYAN}[+] Total combinations to test: {total_combinations}{Style.RESET_ALL}")

        # --- Execute Requests ---
        stop_event = Event()
        processed_requests = 0
        futures = []

        print(f"{Fore.CYAN}[+] Starting bypass attempts...{Style.RESET_ALL}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Enviar tareas en lotes pequeños para control
            batch_size = self.threads * 2  # Procesar el doble de hilos como lote inicial
            remaining_cases = test_cases.copy()

            while remaining_cases and not stop_event.is_set():
                current_batch = remaining_cases[:batch_size]
                remaining_cases = remaining_cases[batch_size:]

                # Enviar lote actual
                futures = [executor.submit(self.try_request, method, url, headers, 0, stop_event)
                           for method, url, headers in current_batch]

                # Procesar resultados con un timeout para verificar stop_event periódicamente
                while futures and not stop_event.is_set():
                    done, not_done = wait(futures, timeout=1, return_when=FIRST_COMPLETED)
                    for future in done:
                        processed_requests += 1
                        task_output = future.result()
                        if task_output:
                            result_data = task_output.get("result")
                            stop_signal = task_output.get("stop_signal", False)

                            if self.stop_on_success and stop_signal:
                                print(f"{Fore.YELLOW}[!] Stopping: Successful response found (Status {result_data.get('status')}).{Style.RESET_ALL}")
                                stop_event.set()  # Activar el evento de parada
                                if result_data.get('success', False):
                                    self.successful_bypasses.append(result_data)
                                break  # Salir del bucle de resultados
                            elif result_data and 'success' in result_data and result_data['success']:
                                self.successful_bypasses.append(result_data)

                    # Reporte de progreso
                    if processed_requests % 100 == 0 and not self.verbose:
                        progress = (processed_requests / total_combinations) * 100
                        print(f"{Fore.CYAN}[+] Progress: {progress:.1f}% ({processed_requests}/{total_combinations}){Style.RESET_ALL}")

                futures = list(not_done)  # Mantener las tareas pendientes

            # Verificar stop_event al final del bucle
            if stop_event.is_set() or processed_requests >= total_combinations:
                return  # Salir del método si se ha activado stop_event o se han procesado todas las solicitudes

        self.request_count = processed_requests
        self.success_count = len(self.successful_bypasses)
        self.end_time = time.time()
        self.print_summary()


    def print_summary(self):
        # --- (Summary print remains largely the same, ensure counts are correct) ---
        elapsed_time = self.end_time - self.start_time if self.end_time and self.start_time else 0

        print(f"\n{Fore.CYAN}=== BypassBlaster Summary ==={Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Target:{Style.RESET_ALL} {self.url}{self.path}")
        print(f"  {Fore.WHITE}Requests Processed:{Style.RESET_ALL} {self.request_count}") # Changed label slightly
        print(f"  {Fore.WHITE}Successful Bypasses (2xx):{Style.RESET_ALL} {self.success_count}") # Clarified label
        if elapsed_time > 0:
            print(f"  {Fore.WHITE}Time Elapsed:{Style.RESET_ALL} {elapsed_time:.2f} seconds")
            print(f"  {Fore.WHITE}Requests/sec:{Style.RESET_ALL} {self.request_count / elapsed_time:.2f}")
        else:
            print(f"  {Fore.WHITE}Time Elapsed:{Style.RESET_ALL} < 0.01 seconds")


        if self.waf_detected:
            print(f"  {Fore.WHITE}WAF/Security Services Detected:{Style.RESET_ALL} {', '.join(sorted(list(self.waf_detected)))}")
        else:
            print(f"  {Fore.WHITE}WAF/Security Services:{Style.RESET_ALL} None detected or unknown")

        if self.captcha_detected:
            print(f"  {Fore.WHITE}CAPTCHA Types Detected:{Style.RESET_ALL} {', '.join(sorted(list(self.captcha_types)))}")

        if self.successful_bypasses:
            print(f"\n{Fore.GREEN}=== Successful Bypasses (Status 2xx) ==={Style.RESET_ALL}") # Clarified title
            # Sort results for consistency? Maybe by URL then method?
            sorted_bypasses = sorted(self.successful_bypasses, key=lambda x: (x['url'], x['method']))
            for i, bypass in enumerate(sorted_bypasses[:10], 1): # Show top 10
                print(f"  {i}. [{bypass['method']}] {bypass['url']}")
                print(f"     Status: {bypass['status']}, Size: {bypass['size']}")
                # Only show headers if they were non-empty and potentially relevant
                relevant_headers = {k: v for k, v in bypass['headers'].items() if k.lower() not in ['user-agent', 'accept', 'accept-encoding', 'connection']}
                if relevant_headers:
                     print(f"     Headers: {json.dumps(relevant_headers)}")
                if bypass['waf']:
                    print(f"     WAF Notes: {', '.join(bypass['waf'])}") # Indicate these were still detected

            if len(sorted_bypasses) > 10:
                print(f"  ... and {len(sorted_bypasses) - 10} more (see output file for complete results)")
        else:
            print(f"\n{Fore.RED}No successful bypasses (Status 2xx) found.{Style.RESET_ALL}") # Clarified message

        # Suggestions remain the same
        if self.success_count == 0:
             print(f"\n{Fore.YELLOW}[!] Suggestions for improving results:{Style.RESET_ALL}")
             print(f"  - Target might require specific cookies: {Fore.CYAN}--cookie \"name=value;...\"{Style.RESET_ALL}")
             print(f"  - Try different/custom headers: {Fore.CYAN}--headers '{{\"Header\": \"Value\"}}'{Style.RESET_ALL}")
             print(f"  - Try custom path payloads: {Fore.CYAN}--payloads '[\"{{path}}/admin\"]'{Style.RESET_ALL}")
             print(f"  - If redirects occur, consider targeting the final URL or use {Fore.CYAN}--follow-redirects{Style.RESET_ALL}")
             print(f"  - Increase timeout if network is slow: {Fore.CYAN}--timeout 15{Style.RESET_ALL}")
             print(f"  - Use a proxy, maybe residential: {Fore.CYAN}--proxy http://...{Style.RESET_ALL}")
             print(f"  - Disable SSL verification if needed: {Fore.CYAN}--no-verify{Style.RESET_ALL}")
             print(f"  - The resource might genuinely be forbidden or require authentication.")

        print("\nComplete results are available in the output file if specified.")


    def save_results(self, output_file):
         # --- (Save results remains the same, ensure it uses self.successful_bypasses) ---
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
                    "content_preview": bypass["content_preview"]
                } for bypass in sorted(self.successful_bypasses, key=lambda x: (x['url'], x['method'])) # Sort output
            ]
        }

        try:
            with open(output_file, 'w') as f:
                json.dump(output, f, indent=4)
            print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {str(e)}{Style.RESET_ALL}")


def main():
    # --- (main function remains the same - parsing args, creating instance, running) ---
    parser = argparse.ArgumentParser(description=f"BypassBlaster v{VERSION} - HTTP 403 Evasion Tool")

    # Required arguments
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")

    # Optional arguments
    parser.add_argument("-p", "--path", default="/", help="Path to test (default: /)")
    parser.add_argument("-o", "--output", help="Output file for results (JSON format)")
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:1080)") # Added socks5 example
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)") # Increased default
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests per thread in seconds (default: 0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show all non-successful attempts)")
    parser.add_argument("-r", "--retry", type=int, default=1, help="Number of retries for failed requests (default: 1)") # Reduced default
    parser.add_argument("-c", "--cookie", help="Cookies to include with requests (format: 'name1=value1; name2=value2')")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects (may impact bypass detection)")
    parser.add_argument("--headers", help="Custom headers in JSON format (e.g. '{\"X-Custom-Header\": \"value\"}')")
    parser.add_argument("--payloads", help="File containing custom path mutation payloads (one per line, use {path} and {random})") # Changed to file input
    parser.add_argument("--max-requests", type=int, help="Maximum number of requests to make (randomly selected)")
    parser.add_argument("--burst", action="store_true", help="Burst mode (uses only GET/POST methods, less comprehensive)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--stop-on-success", action="store_true", help="Stop after the first success (2xx) or redirect (3xx) response")

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
            if not isinstance(custom_headers, dict):
                 print(f"{Fore.RED}[!] Custom headers must be a valid JSON object (dictionary).{Style.RESET_ALL}")
                 sys.exit(1)
        except json.JSONDecodeError:
            print(f"{Fore.RED}[!] Error parsing custom headers. Must be valid JSON.{Style.RESET_ALL}")
            sys.exit(1)

    # Handle custom payloads from file
    custom_payloads = []
    if args.payloads:
        try:
            with open(args.payloads, 'r') as f:
                # Read lines, strip whitespace, ignore empty lines/comments
                custom_payloads = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            print(f"{Fore.CYAN}[+] Loaded {len(custom_payloads)} custom payloads from {args.payloads}{Style.RESET_ALL}")
        except FileNotFoundError:
             print(f"{Fore.RED}[!] Custom payloads file not found: {args.payloads}{Style.RESET_ALL}")
             sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading custom payloads file: {e}{Style.RESET_ALL}")
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
            custom_payloads=custom_payloads, # Pass loaded payloads
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
        # Consider adding cleanup here if needed (e.g., closing sessions explicitly)
        sys.exit(0)
    except Exception as e:
        import traceback
        print(f"\n{Fore.RED}[!] An unexpected error occurred: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.RED}Traceback:{Style.RESET_ALL}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()