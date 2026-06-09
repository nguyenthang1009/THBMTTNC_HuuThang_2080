from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
server_socket.bind(('localhost', 12345))
server_socket.listen(5)

print("[*] Server đang chạy")

server_key = RSA.generate(2048)

clients = []

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext

def decrypt_message(key, encrypted_message):
    if len(encrypted_message) < AES.block_size:
        raise ValueError("Dữ liệu nhận được quá ngắn, không chứa đủ IV.")
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode('utf-8')

def handle_client(client_socket, client_address):
    print(f"[+] Kết nối mới từ: {client_address}")
    aes_key = None

    try:
        client_socket.send(server_key.publickey().export_key(format='PEM'))

        client_key_bytes = client_socket.recv(2048)
        if not client_key_bytes:
            return
        client_received_key = RSA.import_key(client_key_bytes)

        aes_key = get_random_bytes(16)

        cipher_rsa = PKCS1_OAEP.new(client_received_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        client_socket.send(encrypted_aes_key)

        clients.append((client_socket, aes_key))

        while True:
            encrypted_message = client_socket.recv(1024)
            
            if not encrypted_message:
                print(f"[-] Client {client_address} đã chủ động ngắt kết nối.")
                break

            try:
                decrypted_message = decrypt_message(aes_key, encrypted_message)
            except Exception as e:
                print(f"[!] Lỗi giải mã tin nhắn từ {client_address}: {e}")
                break

            print(f"[{client_address}]: {decrypted_message}")

            if decrypted_message.strip().lower() == "exit":
                break

            for client, key in clients.copy():
                if client != client_socket:
                    try:
                        encrypted = encrypt_message(key, decrypted_message)
                        client.send(encrypted)
                    except Exception:
                        pass

    except Exception as e:
        print(f"[!] Có lỗi xảy ra với client {client_address}: {e}")
        
    finally:
        if aes_key and (client_socket, aes_key) in clients:
            clients.remove((client_socket, aes_key))
        client_socket.close()
        print(f"[-] Kết nối với {client_address} đã được đóng an toàn.")

try:
    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.daemon = True 
        client_thread.start()
except KeyboardInterrupt:
    print("\n[!] Server đang tắt...")
finally:
    server_socket.close()