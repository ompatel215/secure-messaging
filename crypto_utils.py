import os
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac

class SecurityManager:
    def __init__(self):
        self.rsa_private_key = None
        self.rsa_public_key = None

    def generate_rsa_keys(self):
        """Generates RSA Keypair (Server side)"""
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        return self.get_public_key_pem()

    def get_public_key_pem(self):
        """Export Public Key to PEM format"""
        return self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_public_key(self, pem_data):
        """Load Public Key from PEM (Client side)"""
        self.rsa_public_key = serialization.load_pem_public_key(pem_data)

    def encrypt_session_key(self, aes_key):
        """Encrypt AES key using RSA Public Key"""
        return self.rsa_public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_session_key(self, encrypted_aes_key):
        """Decrypt AES key using RSA Private Key"""
        return self.rsa_private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def generate_aes_key(self):
        return os.urandom(32)  # 256-bit key

    def encrypt_message(self, message_dict, aes_key):
        """Encrypts JSON payload using AES-CBC"""
        # 1. Serialize to JSON
        json_data = json.dumps(message_dict).encode('utf-8')
        
        # 2. Pad data (AES requires block size multiples)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(json_data) + padder.finalize()
        
        # 3. Encrypt
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + Ciphertext encoded
        return base64.b64encode(iv + ct).decode('utf-8')

    def decrypt_message(self, encrypted_b64, aes_key):
        """Decrypts JSON payload"""
        encrypted_data = base64.b64decode(encrypted_b64)
        iv = encrypted_data[:16]
        ct = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        json_data = unpadder.update(padded_data) + unpadder.finalize()
        
        return json.loads(json_data.decode('utf-8'))

    def generate_hmac(self, encrypted_b64, aes_key):
        """Signs the encrypted message"""
        h = hmac.HMAC(aes_key, hashes.SHA256())
        h.update(encrypted_b64.encode('utf-8'))
        return base64.b64encode(h.finalize()).decode('utf-8')

    def verify_hmac(self, encrypted_b64, provided_hmac, aes_key):
        """Verifies integrity"""
        h = hmac.HMAC(aes_key, hashes.SHA256())
        h.update(encrypted_b64.encode('utf-8'))
        try:
            h.verify(base64.b64decode(provided_hmac))
            return True
        except:
            return False