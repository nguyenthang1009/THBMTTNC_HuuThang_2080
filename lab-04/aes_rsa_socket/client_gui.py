import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-RSA Secure Chat Client")
        self.root.geometry("500x450")

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_key = RSA.generate(2048)
        self.aes_key = None
        
        self.chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', height=18)
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.entry_frame = tk.Frame(root)
        self.entry_frame.pack(padx=10, pady=5, fill=tk.X)

        self.msg_entry = tk.Entry(self.entry_frame)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)
        self.msg_entry.bind("<Return>", lambda event: self.send_message())

        self.send_button = tk.Button(self.entry_frame, text="Gửi", command=self.send_message, width=10)
        self.send_button.pack(side=tk.RIGHT, padx=5)

        self.connect_to_server()

    def log(self, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def encrypt_message(self, key, message):
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
        return cipher.iv + ciphertext

    def decrypt_message(self, key, encrypted_message):
        iv = encrypted_message[:AES.block_size]
        ciphertext = encrypted_message[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

    def connect_to_server(self):
        try:
            self.client_socket.connect(('localhost', 12345))
            self.log("[Hệ thống] Đang thiết lập kênh mã hóa tin nhắn...")

            server_public_key = RSA.import_key(self.client_socket.recv(2048))
            self.client_socket.send(self.client_key.publickey().export_key(format='PEM'))
            encrypted_aes_key = self.client_socket.recv(2048)
            cipher_rsa = PKCS1_OAEP.new(self.client_key)
            self.aes_key = cipher_rsa.decrypt(encrypted_aes_key)

            self.log("[Hệ thống] Kết nối thành công! Kênh chat đã được bảo mật.")

            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể kết nối đến server: {e}")
            self.root.destroy()

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if not encrypted_message:
                    break
                decrypted_message = self.decrypt_message(self.aes_key, encrypted_message)
                self.log(f"Đối phương: {decrypted_message}")
            except:
                break
        self.log("[Hệ thống] Mất kết nối tới server.")

    def send_message(self):
        message = self.msg_entry.get().strip()
        if not message:
            return
        
        self.msg_entry.delete(0, tk.END)
        self.log(f"Bạn: {message}")

        try:
            encrypted_message = self.encrypt_message(self.aes_key, message)
            self.client_socket.send(encrypted_message)
        except Exception as e:
            self.log(f"[Lỗi gửi tin]: {e}")

        if message == "exit":
            self.client_socket.close()
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()