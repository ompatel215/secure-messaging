import requests
import base64
from crypto_utils import SecurityManager

def run_client():
    server_url = "http://127.0.0.1:5000"
    sec_manager = SecurityManager()

    print("[-] Connecting to server to fetch Public Key...")
    
    # 1. RSA Handshake
    try:
        resp = requests.get(f"{server_url}/get_public_key")
        server_pub_key = resp.json()['public_key'].encode('utf-8')
        sec_manager.load_public_key(server_pub_key)
        print("[-] RSA Public Key received.")
    except Exception as e:
        print(f"[!] Could not connect to server: {e}")
        return

    while True:
        msg_text = input("\nEnter message (or 'exit'): ")
        if msg_text.lower() == 'exit':
            break

        # 2. Generate AES Session Key
        session_key = sec_manager.generate_aes_key()

        # 3. Encrypt Session Key with RSA
        encrypted_session_key = sec_manager.encrypt_session_key(session_key)
        encrypted_session_key_b64 = base64.b64encode(encrypted_session_key).decode('utf-8')

        # 4. Prepare Payload & Serialize
        payload = {"sender": "Student_Client", "message": msg_text}

        # 5. Encrypt Payload with AES
        encrypted_msg = sec_manager.encrypt_message(payload, session_key)

        # 6. Generate HMAC for Integrity
        hmac_sig = sec_manager.generate_hmac(encrypted_msg, session_key)

        # 7. Send Packet
        packet = {
            "encrypted_aes_key": encrypted_session_key_b64,
            "encrypted_data": encrypted_msg,
            "hmac": hmac_sig
        }

        try:
            r = requests.post(f"{server_url}/secure_message", json=packet)
            print(f"Server Reply: {r.json()}")
        except Exception as e:
            print(f"Send failed: {e}")

if __name__ == "__main__":
    run_client()