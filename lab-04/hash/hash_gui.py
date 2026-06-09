import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
from Crypto.Hash import SHA3_256

def left_rotate(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

def manual_md5(message):
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    original_length = len(message)
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += original_length.to_bytes(8, 'little')

    for i in range(0, len(message), 64):
        block = message[i:i+64]
        words = [int.from_bytes(block[j:j+4], 'little') for j in range(0, 64, 4)]
        a0, b0, c0, d0 = a, b, c, d

        for j in range(64):
            if j < 16:
                f = (b & c) | ((~b) & d)
                g = j
            elif j < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * j + 1) % 16
            elif j < 48:
                f = b ^ c ^ d
                g = (3 * j + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * j) % 16

            temp = d
            d = c
            c = b
            b = (b + left_rotate((a + f + 0x5A827999 + words[g]) & 0xFFFFFFFF, 3)) & 0xFFFFFFFF
            a = temp

        a = (a + a0) & 0xFFFFFFFF
        b = (b + b0) & 0xFFFFFFFF
        c = (c + c0) & 0xFFFFFFFF
        d = (d + d0) & 0xFFFFFFFF

    return '{:08x}{:08x}{:08x}{:08x}'.format(a, b, c, d)


class HashUtilityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Công cụ tính toán Hàm Băm")
        self.root.geometry("550x280")

        tk.Label(root, text="Nhập chuỗi văn bản cần băm:").pack(anchor="w", padx=15, pady=(15, 2))
        self.txt_input = tk.Entry(root, width=60)
        self.txt_input.pack(fill="x", padx=15, pady=5)
        
        tk.Label(root, text="Chọn thuật toán băm:").pack(anchor="w", padx=15, pady=(10, 2))
        self.algo_combo = ttk.Combobox(root, values=[
            "MD5 (Cài đặt thủ công)", 
            "MD5 (Thư viện)", 
            "SHA-256", 
            "SHA-3 (256)", 
            "BLAKE2 (b)"
        ], state="readonly", width=30)
        self.algo_combo.pack(anchor="w", padx=15, pady=5)
        self.algo_combo.current(0)

        self.btn_hash = tk.Button(root, text="Thực hiện Băm", command=self.process_hash, bg="#4CAF50", fg="white")
        self.btn_hash.pack(anchor="w", padx=15, pady=10)

        tk.Label(root, text="Kết quả mã băm (Hex):").pack(anchor="w", padx=15, pady=(10, 2))
        self.txt_output = tk.Entry(root, width=60, fg="blue")
        self.txt_output.pack(fill="x", padx=15, pady=5)

    def process_hash(self):
        input_data = self.txt_input.get()
        if not input_data:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập chuỗi văn bản dữ liệu đầu vào.")
            return

        algo = self.algo_combo.get()
        data_bytes = input_data.encode('utf-8')
        result = ""

        if algo == "MD5 (Cài đặt thủ công)":
            result = manual_md5(data_bytes)
        elif algo == "MD5 (Thư viện)":
            result = hashlib.md5(data_bytes).hexdigest()
        elif algo == "SHA-256":
            result = hashlib.sha256(data_bytes).hexdigest()
        elif algo == "SHA-3 (256)":
            sha3 = SHA3_256.new(data_bytes)
            result = sha3.hexdigest()
        elif algo == "BLAKE2 (b)":
            result = hashlib.blake2b(data_bytes).hexdigest()

        self.txt_output.delete(0, tk.END)
        self.txt_output.insert(0, result)

if __name__ == "__main__":
    root = tk.Tk()
    app = HashUtilityGUI(root)
    root.mainloop()