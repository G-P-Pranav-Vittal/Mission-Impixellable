from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from PIL import Image
import tkinter as tk
from tkinter import filedialog, messagebox

import secrets
import struct



class AESEngine:
    @staticmethod
    def encrypt(data):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        aes = AESGCM(key)

        encrypted = aes.encrypt(nonce, data, None)
        ciphertext = encrypted[:-16]
        tag = encrypted[-16:]

        return key, nonce, ciphertext, tag

    @staticmethod
    def decrypt(key, nonce, ciphertext, tag):
        aes = AESGCM(key)
        return aes.decrypt(nonce, ciphertext + tag, None)

class RSAEngine:
    @staticmethod
    def generate_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_pem, private_pem

    @staticmethod
    def encrypt_aes_key(public_pem: bytes, aes_key: bytes):
        public_key = serialization.load_pem_public_key(public_pem)
        return public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_aes_key(private_pem: bytes, encrypted_key: bytes):
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


class PayloadManager:
    @staticmethod
    def pack(wrapped_key, nonce, tag, ciphertext):
        header = struct.pack(">I", len(wrapped_key))
        return header + wrapped_key + nonce + tag + ciphertext

    @staticmethod
    def unpack(payload):
        key_len = struct.unpack(">I", payload[:4])[0]
        offset = 4

        wrapped_key = payload[offset:offset + key_len]
        offset += key_len

        nonce = payload[offset:offset + 12]
        offset += 12

        tag = payload[offset:offset + 16]
        offset += 16

        ciphertext = payload[offset:]
        return wrapped_key, nonce, tag, ciphertext


class LSBStego:
    @staticmethod
    def embed(cover_path, output_path, payload: bytes):
        image = Image.open(cover_path).convert("RGB")
        pixels = image.load()
        w, h = image.size

        capacity = (w * h * 3) // 8
        if len(payload) > capacity:
            raise ValueError("Payload too large for image")

        payload = len(payload).to_bytes(4, "big") + payload
        bits = "".join(f"{b:08b}" for b in payload)
        idx = 0

        for y in range(h):
            for x in range(w):
                r, g, b = pixels[x, y]
                if idx < len(bits):
                    r = (r & ~1) | int(bits[idx]); idx += 1
                if idx < len(bits):
                    g = (g & ~1) | int(bits[idx]); idx += 1
                if idx < len(bits):
                    b = (b & ~1) | int(bits[idx]); idx += 1
                pixels[x, y] = (r, g, b)

                if idx >= len(bits):
                    image.save(output_path, "PNG")
                    return

    @staticmethod
    def extract(stego_path):
        image = Image.open(stego_path).convert("RGB")
        pixels = iter(image.getdata())  # Create an iterator for pixels
        
    
        header_bits = []
        while len(header_bits) < 32:
            try:
                r, g, b = next(pixels)
            except StopIteration:
                break 
            
            header_bits.append(str(r & 1))
            if len(header_bits) < 32: header_bits.append(str(g & 1))
            if len(header_bits) < 32: header_bits.append(str(b & 1))

        if len(header_bits) < 32:
             raise ValueError("Image does not contain a valid header.")

        
        header_str = "".join(header_bits)
        payload_length = int(header_str, 2)
        total_bits_needed = payload_length * 8
        body_bits = []
        pixels = image.getdata()
        total_bits_to_read = 32 + (payload_length * 8)
        extracted_bits = []
        count = 0
        
        for r, g, b in pixels:
            # Red
            extracted_bits.append(str(r & 1))
            count += 1
            if count >= total_bits_to_read: break
            
            # Green
            extracted_bits.append(str(g & 1))
            count += 1
            if count >= total_bits_to_read: break
            
            # Blue
            extracted_bits.append(str(b & 1))
            count += 1
            if count >= total_bits_to_read: break
            
        # Convert bits to bytes
        all_bits = "".join(extracted_bits)
        data_bits = all_bits[32:] # Skip the first 32 bits (header)
        
        data = bytearray()
        for i in range(0, len(data_bits), 8):
            byte_val = data_bits[i:i+8]
            if len(byte_val) == 8:
                data.append(int(byte_val, 2))
                
        return bytes(data)

def encode(cover_image_path, output_image_path, message: str, public_key_pem: bytes):
    data = message.encode("utf-8")
    aes_key, nonce, ciphertext, tag = AESEngine.encrypt(data)
    wrapped_key = RSAEngine.encrypt_aes_key(public_key_pem, aes_key)
    payload = PayloadManager.pack(wrapped_key, nonce, tag, ciphertext)
    LSBStego.embed(cover_image_path, output_image_path, payload)


def decode(stego_image_path, private_key_pem: bytes):
    payload = LSBStego.extract(stego_image_path)
    wrapped_key, nonce, tag, ciphertext = PayloadManager.unpack(payload)
    aes_key = RSAEngine.decrypt_aes_key(private_key_pem, wrapped_key)
    plaintext = AESEngine.decrypt(aes_key, nonce, ciphertext, tag)
    return plaintext.decode("utf-8")


def show_decoded_message(message: str):
    win = tk.Toplevel()
    win.title("Decoded Message")
    win.geometry("700x500")

    text = tk.Text(win, wrap="word", font=("Arial", 11))
    text.pack(side="left", fill="both", expand=True)

    scrollbar = tk.Scrollbar(win, command=text.yview)
    scrollbar.pack(side="right", fill="y")

    text.configure(yscrollcommand=scrollbar.set)
    text.insert("1.0", message)
    text.config(state="disabled")


def generate_rsa_keys_gui():
    pub_pem, priv_pem = RSAEngine.generate_keys()

    pub_path = filedialog.asksaveasfilename(
        title="Save Public Key",
        defaultextension=".pem",
        filetypes=[("PEM files", "*.pem")]
    )
    if not pub_path:
        return

    priv_path = filedialog.asksaveasfilename(
        title="Save Private Key",
        defaultextension=".pem",
        filetypes=[("PEM files", "*.pem")]
    )
    if not priv_path:
        return

    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    with open(priv_path, "wb") as f:
        f.write(priv_pem)

    messagebox.showinfo("Success", "RSA key pair generated successfully")


def start_gui():
    root = tk.Tk()
    root.title("Steganography Tool")
    root.geometry("500x400")

    tk.Label(root, text="LSB Steganography with Hybrid Crypto",
             font=("Arial", 14, "bold")).pack(pady=10)

    tk.Button(root, text="Encode", width=20, command=open_encode_window).pack(pady=10)
    tk.Button(root, text="Decode", width=20, command=open_decode_window).pack(pady=10)

    root.mainloop()


def browse_file(entry):
    path = filedialog.askopenfilename()
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)


def open_encode_window():
    win = tk.Toplevel()
    win.title("Encode")
    win.geometry("500x420")

    tk.Label(win, text="Cover Image").pack()
    cover_entry = tk.Entry(win, width=50)
    cover_entry.pack()
    tk.Button(win, text="Browse", command=lambda: browse_file(cover_entry)).pack()

    tk.Label(win, text="Message").pack()
    message_entry = tk.Text(win, height=5, width=50)
    message_entry.pack()

    tk.Label(win, text="Public Key (.pem)").pack()
    pub_entry = tk.Entry(win, width=50)
    pub_entry.pack()
    tk.Button(win, text="Browse", command=lambda: browse_file(pub_entry)).pack()

    tk.Button(win, text="Generate RSA Key Pair",
              command=generate_rsa_keys_gui).pack(pady=5)

    tk.Button(
        win, text="Encode",
        command=lambda: encode_action(
            cover_entry.get(),
            message_entry.get("1.0", tk.END).strip(),
            pub_entry.get()
        )
    ).pack(pady=10)


def encode_action(cover_path, message, public_key_path):
    if not cover_path or not message or not public_key_path:
        messagebox.showerror("Error", "All fields are required")
        return

    output_path = filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG files", "*.png")]
    )
    if not output_path:
        return

    try:
        with open(public_key_path, "rb") as f:
            public_key_pem = f.read()

        encode(cover_path, output_path, message, public_key_pem)
        messagebox.showinfo("Success", "Message embedded successfully")

    except Exception as e:
        messagebox.showerror("Error", str(e))


def open_decode_window():
    win = tk.Toplevel()
    win.title("Decode")
    win.geometry("500x300")

    tk.Label(win, text="Stego Image").pack()
    image_entry = tk.Entry(win, width=50)
    image_entry.pack()
    tk.Button(win, text="Browse", command=lambda: browse_file(image_entry)).pack()

    tk.Label(win, text="Private Key (.pem)").pack()
    priv_entry = tk.Entry(win, width=50)
    priv_entry.pack()
    tk.Button(win, text="Browse", command=lambda: browse_file(priv_entry)).pack()

    tk.Button(
        win, text="Decode",
        command=lambda: decode_action(
            image_entry.get(),
            priv_entry.get()
        )
    ).pack(pady=10)


def decode_action(image_path, private_key_path):
    if not image_path or not private_key_path:
        messagebox.showerror("Error", "All fields are required")
        return

    try:
        with open(private_key_path, "rb") as f:
            private_key_pem = f.read()

        message = decode(image_path, private_key_pem)
        show_decoded_message(message)

    except Exception as e:
        messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    start_gui()
