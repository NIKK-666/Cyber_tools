from tkinter import Tk, Label, Button, filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import os


class ImageEncryptionToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption Tool")
        self.key = get_random_bytes(16)  # AES key (16 bytes)

        # GUI Components
        self.label = Label(root, text="Image Encryption Tool", font=("Arial", 16))
        self.label.pack(pady=10)

        self.encrypt_button = Button(
            root, text="Encrypt Image", command=self.encrypt_image_gui, width=20
        )
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = Button(
            root, text="Decrypt Image", command=self.decrypt_image_gui, width=20
        )
        self.decrypt_button.pack(pady=5)

        self.exit_button = Button(root, text="Exit", command=root.quit, width=20)
        self.exit_button.pack(pady=20)

    def encrypt_image(self, input_path, output_path):
        try:
            # Read the image data
            with open(input_path, "rb") as file:
                image_data = file.read()

            # Encrypt the image data
            cipher = AES.new(self.key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(image_data, AES.block_size))

            # Save the IV and ciphertext
            with open(output_path, "wb") as file:
                file.write(cipher.iv + ciphertext)

            messagebox.showinfo("Success", f"Image encrypted and saved to: {output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_image(self, input_path, output_path):
        try:
            # Read the encrypted data
            with open(input_path, "rb") as file:
                iv = file.read(16)  # AES block size is 16 bytes
                ciphertext = file.read()

            # Decrypt the image data
            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

            # Save the decrypted image
            with open(output_path, "wb") as file:
                file.write(plaintext)

            messagebox.showinfo("Success", f"Image decrypted and saved to: {output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def encrypt_image_gui(self):
        input_path = filedialog.askopenfilename(
            title="Select Image to Encrypt",
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")],
        )
        if not input_path:
            return

        output_path = filedialog.asksaveasfilename(
            title="Save Encrypted Image",
            defaultextension=".aes",
            filetypes=[("Encrypted Files", "*.aes")],
        )
        if not output_path:
            return

        self.encrypt_image(input_path, output_path)

    def decrypt_image_gui(self):
        input_path = filedialog.askopenfilename(
            title="Select Encrypted File to Decrypt", filetypes=[("Encrypted Files", "*.aes")]
        )
        if not input_path:
            return

        output_path = filedialog.asksaveasfilename(
            title="Save Decrypted Image",
            defaultextension=".jpg",
            filetypes=[("Image Files", "*.jpg;*.png;*.jpeg;*.bmp")],
        )
        if not output_path:
            return

        self.decrypt_image(input_path, output_path)


if __name__ == "__main__":
    root = Tk()
    app = ImageEncryptionToolGUI(root)
    root.geometry("400x300")
    root.mainloop()
