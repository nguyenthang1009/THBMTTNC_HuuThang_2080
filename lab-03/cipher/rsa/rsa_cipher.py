import rsa

class RSACipher:
    def __init__(self):
        pass

    def generate_keys(self):
        (public_key, private_key) = rsa.newkeys(1024)
        
        with open('cipher/rsa/keys/publicKey.pem', 'wb') as p:
            p.write(public_key.save_pkcs1('PEM'))
            
        with open('cipher/rsa/keys/privateKey.pem', 'wb') as p:
            p.write(private_key.save_pkcs1('PEM'))

    def load_keys(self):
        with open('cipher/rsa/keys/publicKey.pem', 'rb') as p:
            public_key = rsa.PublicKey.load_pkcs1(p.read())
            

        with open('cipher/rsa/keys/privateKey.pem', 'rb') as p:
            private_key = rsa.PrivateKey.load_pkcs1(p.read())
            
        return private_key, public_key

    def encrypt(self, message, key):
        message_bytes = message.encode('utf8')
        encrypted_message = rsa.encrypt(message_bytes, key)
        return encrypted_message

    def decrypt(self, ciphertext, key):
        decrypted_bytes = rsa.decrypt(ciphertext, key)
        return decrypted_bytes.decode('utf8')

    def sign(self, message, private_key):
        message_bytes = message.encode('utf8')
        signature = rsa.sign(message_bytes, private_key, 'SHA-256')
        return signature

    def verify(self, message, signature, public_key):
        message_bytes = message.encode('utf8')
        try:
            rsa.verify(message_bytes, signature, public_key)
            return True
        except rsa.VerificationError:
            return False