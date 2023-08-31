from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import socket
import json
import re
import threading
import queue

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
GRAY = "\033[90m"
WHITE = "\033[97m"

def recv_data(sock, q):
    while True:
        chunks = []
        try:
            chunk = sock.recv(2048)
            if chunk:
                chunks.append(chunk)
            else:
                break
        except socket.timeout:
            print(f"{RED}[!]{RESET} {WHITE}Timed out waiting for more data{RESET}")

        data_bytes = b''.join(chunks)
        data_str = data_bytes.decode('utf-8')

        try:
            match = re.search(r'\{.*\}', data_str)
            if match:
                json_str = match.group(0)
                json_data = json.loads(json_str)
                q.put(json_data)
        except json.JSONDecodeError as e:
            print(f"{RED}[!]{RESET} {WHITE}Failed to decode JSON: {e}{RESET}")

def send_data(sock, data_to_send):
    sock.sendall(data_to_send)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('socket.cryptohack.org', 13371))
s.settimeout(5)

json_queue = queue.Queue()

recv_thread = threading.Thread(target=recv_data, args=(s, json_queue))
recv_thread.daemon = True
recv_thread.start()

while True:
    try:
        print(f"\n{YELLOW}[i]{RESET} {WHITE}Connecting to cryptohack...{RESET}\n")
        received_json = json_queue.get(timeout=10)
        print(f"{BLUE}[+]{RESET} {WHITE}Received JSON: {received_json}{RESET}")

        p = received_json.get("p", "Key not found")
        g = received_json.get("g", "Key not found")
        A = received_json.get("A", "Key not found")

        Prim = int(p, 16)
        A_int = int(A, 16)
        Base = int(g, 16)

        exp = input(f"\n{BLUE}[+]{RESET}{WHITE} Give me a value for your exponent in hexadecimal (0x):\n|> {RESET}")
        expd = int(exp, 16)

        mia = pow(Base, expd, Prim)

        alice_data = {
            "p": p,
            "g": g,
            "A": hex(mia)
        }

        alice_json_str = json.dumps(alice_data)
        alice_json_bytes = alice_json_str.encode('utf-8')

        send_data(s, alice_json_bytes)

        try:
            received_json = json_queue.get(timeout=10)
            print(f"\n{BLUE}[+]{RESET}{WHITE} Received JSON: {received_json}{RESET}\n")
        except queue.Empty:
            print(f"{RED}[!]{RESET}{WHITE} No JSON object received within 10 seconds.{RESET}")

        B = received_json.get("B", "Key not found")
        B_num = int(B, 16)

        mib=pow(Base,expd,Prim)

        alice = {
            "B": hex(mib)
        }
        
        alice_str = json.dumps(alice)
        alice_bytes = alice_str.encode('utf-8')

        send_data(s,alice_bytes)

        try:
            received_json = json_queue.get(timeout=10)
            print(f"{BLUE}[+]{RESET}{WHITE} Received JSON: {received_json}{RESET}\n")
        except queue.Empty:
            print(f"{RED}[!]{RESET}{WHITE} No JSON object received within 10 seconds.{RESET}")

        shared_secret = pow(A_int, expd, Prim)

        iv = received_json.get("iv", "Key not found")
        ciphertext = received_json.get("encrypted_flag", "Key not found")

        print(f"{BLUE}[+]{RESET}{WHITE} Decrypting AES...{RESET}\n")
        
        # Derive AES key from shared secret
        sha1 = hashlib.sha1()
        sha1.update(str(shared_secret).encode('ascii'))
        key = sha1.digest()[:16]
        # Decrypt flag
        ciphertext = bytes.fromhex(ciphertext)
        iv = bytes.fromhex(iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)

        print(f"{GREEN}[*]{RESET}{WHITE} The flag is{plaintext.decode('ascii')}{RESET}")
        break
    except:
        pass
