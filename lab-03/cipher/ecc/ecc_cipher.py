from ecdsa import SigningKey, VerifyingKey, SECP256k1
import os

class ECCCipher:
    def __init__(self):
        os.makedirs('cipher/ecc/keys', exist_ok=True)

    def generate_keys(self):
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.get_verifying_key()
        
        with open('cipher/ecc/keys/privateKey.pem', 'wb') as p:
            p.write(private_key.to_pem())
            
        with open('cipher/ecc/keys/publicKey.pem', 'wb') as p:
            p.write(public_key.to_pem())

    def load_keys(self):
        with open('cipher/ecc/keys/privateKey.pem', 'rb') as p:
            private_key = SigningKey.from_pem(p.read())
            
        with open('cipher/ecc/keys/publicKey.pem', 'rb') as p:
            public_key = VerifyingKey.from_pem(p.read())
            
        return private_key, public_key

    def sign(self, message, private_key):
        message_bytes = message.encode('utf8')
        
        signature = private_key.sign(message_bytes)
        return signature

    def verify(self, message, signature, public_key):
        message_bytes = message.encode('utf8')
        try:

            is_verified = public_key.verify(signature, message_bytes)
            return is_verified
        except Exception:
            return False