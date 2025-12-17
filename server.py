from flask import Flask, request, jsonify
from crypto_utils import SecurityManager
from ai_engine import AnomalyDetector
import base64

app = Flask(__name__)
sec_manager = SecurityManager()
ai_engine = AnomalyDetector()

# Initialize RSA Keys on startup
public_key_pem = sec_manager.generate_rsa_keys()
print(f"[*] Server Started. RSA Public Key Ready.")

@app.route('/get_public_key', methods=['GET'])
def get_key():
    """Endpoint for clients to fetch RSA Public Key"""
    return jsonify({"public_key": public_key_pem.decode('utf-8')})

@app.route('/secure_message', methods=['POST'])
def receive_message():
    try:
        data = request.json
        enc_aes_key_b64 = data.get('encrypted_aes_key')
        encrypted_msg = data.get('encrypted_data')
        hmac_signature = data.get('hmac')

        # 1. Decrypt AES Key using RSA Private Key
        aes_key = sec_manager.decrypt_session_key(base64.b64decode(enc_aes_key_b64))

        # 2. Verify Integrity (HMAC)
        if not sec_manager.verify_hmac(encrypted_msg, hmac_signature, aes_key):
            return jsonify({"status": "error", "message": "Integrity Check Failed! Message Tampered."}), 401

        # 3. Decrypt Message Content
        payload = sec_manager.decrypt_message(encrypted_msg, aes_key)
        user_message = payload.get('message')
        sender = payload.get('sender')

        # 4. AI Anomaly Detection
        is_bad, reason = ai_engine.is_anomalous(user_message)
        
        print(f"\n[NEW MESSAGE]")
        print(f"From: {sender}")
        print(f"Content: {user_message}")
        print(f"Integrity: Verified")
        print(f"AI Scan: {'ANOMALY DETECTED (' + reason + ')' if is_bad else 'Clean'}")

        response_status = "Flagged by AI" if is_bad else "Received"

        return jsonify({
            "status": "success", 
            "response": response_status,
            "ai_analysis": reason
        })

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)