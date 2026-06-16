from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import socket
import threading
import sys

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client_socket.connect(('localhost', 12345))
    print("[+] Kết nối tới Server thành công.")
except Exception as e:
    print(f"[!] Không thể kết nối tới Server: {e}")
    sys.exit()

print("[*] Đang khởi tạo khóa RSA...")
client_key = RSA.generate(2048)

server_public_key = RSA.import_key(client_socket.recv(2048))

client_socket.send(client_key.publickey().export_key(format='PEM'))

encrypted_aes_key = client_socket.recv(2048)

cipher_rsa = PKCS1_OAEP.new(client_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)
print("[+] Đã bắt tay mã hóa thành công. Bạn có thể trò chuyện chat.")

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext

def decrypt_message(key, encrypted_message):
    if len(encrypted_message) < AES.block_size:
        raise ValueError("Dữ liệu nhận được quá ngắn.")
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode('utf-8')

def receive_messages():
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            
            if not encrypted_message:
                print("\n[-] Mất kết nối tới Server (Server đã tắt).")
                break
                
            decrypted_message = decrypt_message(aes_key, encrypted_message)
            print(f"\n[Tin nhắn mới]: {decrypted_message}")
            print("Enter message ('exit' to quit): ", end="", flush=True) 
            
        except (ConnectionAbortedError, ConnectionResetError, OSError):
            break
        except Exception as e:
            print(f"\n[!] Lỗi nhận/giải mã tin nhắn: {e}")
            break

receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True 
receive_thread.start()

while True:
    try:
        message = input("Enter message ('exit' to quit): ")
        if not message.strip():
            continue
            
        encrypted_message = encrypt_message(aes_key, message)
        client_socket.send(encrypted_message)
        
        if message.strip().lower() == "exit":
            print("[*] Đang đóng kết nối...")
            break
    except (KeyboardInterrupt, EOFError):
        break

client_socket.close()
print("[+] Đã thoát chương trình.")