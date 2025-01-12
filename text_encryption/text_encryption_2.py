import tkinter as tk
from tkinter import messagebox, scrolledtext
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class TextEncryption:
    def __init__(self):
        self.aes_key = get_random_bytes(16)
        self.des_key = get_random_bytes(8)
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

    # AES Methods
    def aes_encrypt(self, plaintext):
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return cipher.iv, ciphertext

    def aes_decrypt(self, iv, ciphertext):
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode()

    # DES Methods
    def des_encrypt(self, plaintext):
        cipher = DES.new(self.des_key, DES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), DES.block_size))
        return cipher.iv, ciphertext

    def des_decrypt(self, iv, ciphertext):
        cipher = DES.new(self.des_key, DES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
        return plaintext.decode()

    # RSA Methods
    def rsa_encrypt(self, plaintext):
        ciphertext = self.rsa_public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return ciphertext

    def rsa_decrypt(self, ciphertext):
        plaintext = self.rsa_private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext.decode()


class EncryptionApp:
    def __init__(self, root):
        self.encryption = TextEncryption()
        self.root = root
        self.root.title("Text Encryption GUI")

        # Input text
        self.input_label = tk.Label(root, text="Input Text:")
        self.input_label.pack()
        self.input_text = scrolledtext.ScrolledText(root, width=40, height=5)
        self.input_text.pack()

        # Encrypted text
        self.output_label = tk.Label(root, text="Encrypted/Decrypted Text:")
        self.output_label.pack()
        self.output_text = scrolledtext.ScrolledText(root, width=40, height=5)
        self.output_text.pack()

        # Buttons
        self.aes_encrypt_button = tk.Button(
            root, text="Encrypt with AES", command=self.aes_encrypt
        )
        self.aes_encrypt_button.pack()

        self.aes_decrypt_button = tk.Button(
            root, text="Decrypt with AES", command=self.aes_decrypt
        )
        self.aes_decrypt_button.pack()

        self.des_encrypt_button = tk.Button(
            root, text="Encrypt with DES", command=self.des_encrypt
        )
        self.des_encrypt_button.pack()

        self.des_decrypt_button = tk.Button(
            root, text="Decrypt with DES", command=self.des_decrypt
        )
        self.des_decrypt_button.pack()

        self.rsa_encrypt_button = tk.Button(
            root, text="Encrypt with RSA", command=self.rsa_encrypt
        )
        self.rsa_encrypt_button.pack()

        self.rsa_decrypt_button = tk.Button(
            root, text="Decrypt with RSA", command=self.rsa_decrypt
        )
        self.rsa_decrypt_button.pack()

        # Store encryption data
        self.aes_data = None
        self.des_data = None
        self.rsa_data = None

    def aes_encrypt(self):
        plaintext = self.input_text.get("1.0", tk.END).strip()
        if plaintext:
            iv, ciphertext = self.encryption.aes_encrypt(plaintext)
            self.aes_data = (iv, ciphertext)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, ciphertext)
        else:
            messagebox.showwarning("Input Error", "Please enter text to encrypt.")

    def aes_decrypt(self):
        if self.aes_data:
            iv, ciphertext = self.aes_data
            decrypted_text = self.encryption.aes_decrypt(iv, ciphertext)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted_text)
        else:
            messagebox.showwarning("Decryption Error", "No AES data to decrypt.")

    def des_encrypt(self):
        plaintext = self.input_text.get("1.0", tk.END).strip()
        if plaintext:
            iv, ciphertext = self.encryption.des_encrypt(plaintext)
            self.des_data = (iv, ciphertext)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, ciphertext)
        else:
            messagebox.showwarning("Input Error", "Please enter text to encrypt.")

    def des_decrypt(self):
        if self.des_data:
            iv, ciphertext = self.des_data
            decrypted_text = self.encryption.des_decrypt(iv, ciphertext)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted_text)
        else:
            messagebox.showwarning("Decryption Error", "No DES data to decrypt.")

    def rsa_encrypt(self):
        plaintext = self.input_text.get("1.0", tk.END).strip()
        if plaintext:
            ciphertext = self.encryption.rsa_encrypt(plaintext)
            self.rsa_data = ciphertext
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, ciphertext)
        else:
            messagebox.showwarning("Input Error", "Please enter text to encrypt.")

    def rsa_decrypt(self):
        if self.rsa_data:
            decrypted_text = self.encryption.rsa_decrypt(self.rsa_data)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted_text)
        else:
            messagebox.showwarning("Decryption Error", "No RSA data to decrypt.")


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
