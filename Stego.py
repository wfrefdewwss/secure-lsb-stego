#!/usr/bin/env python3
"""
Fast Secure Steganography with AES & Randomized Positions
- Optimized for large images (no memory crashes)
- Non-blocking GUI (no freezes)
- Key: 44-character base64 Fernet key
"""
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from PIL import Image
import hashlib
import random
import threading
import queue
from cryptography.fernet import Fernet

# ---------- crypto ----------
def derive_seed(key: bytes) -> int:
    """Deterministically derive integer seed from key"""
    return int.from_bytes(hashlib.sha256(key).digest(), 'big')

def generate_key() -> bytes:
    """Generate a new Fernet key (44 chars base64)"""
    return Fernet.generate_key()

# ---------- position generator ----------
def create_position_generator(seed: int, max_pos: int):
    """
    Return a generator that yields unique random positions.
    Memory-efficient: doesn't create a list of all positions.
    """
    rng = random.Random(seed)
    used = set()
    while True:
        pos = rng.randrange(max_pos)
        if pos not in used:
            used.add(pos)
            yield pos

# ---------- bit conversion ----------
def _bytes_to_bits(data: bytes):
    """Convert bytes to list of bits"""
    return [(byte >> i) & 1 for byte in data for i in range(8)]

def _bits_to_bytes(bits):
    """Convert list of bits back to bytes"""
    byte_arr = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= bits[i + j] << j
        byte_arr.append(byte)
    return bytes(byte_arr)

# ---------- core logic ----------
def encode_image(image_path: str, text: str, save_path: str, key: bytes):
    """Hide encrypted text at random locations - optimized"""
    # 1. Encrypt text
    f = Fernet(key)
    ciphertext = f.encrypt(text.encode('utf-8'))
    
    # 2. Payload: 4-byte length + ciphertext
    payload = len(ciphertext).to_bytes(4, 'big') + ciphertext
    bits = _bytes_to_bits(payload)
    
    # 3. Load image
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    width, height = img.size
    max_pos = width * height * 3
    
    # 4. Capacity check
    if len(bits) > max_pos:
        raise ValueError(f"Image too small: need {len(bits)} bits, have {max_pos}")
    
    # 5. Create position generator (memory-efficient)
    seed = derive_seed(key)
    pos_gen = create_position_generator(seed, max_pos)
    
    # 6. Modify pixels in-place (no massive lists)
    pixels = img.load()
    for bit in bits:
        pos = next(pos_gen)
        y = pos // (width * 3)
        x = (pos // 3) % width
        channel = pos % 3
        
        r, g, b = pixels[x, y]
        if channel == 0:
            r = (r & ~1) | bit
        elif channel == 1:
            g = (g & ~1) | bit
        else:
            b = (b & ~1) | bit
        pixels[x, y] = (r, g, b)
    
    # 7. Save
    img.save(save_path, 'PNG')

def decode_image(image_path: str, key: bytes) -> str:
    """Extract & decrypt text - optimized"""
    # 1. Load image
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    width, height = img.size
    max_pos = width * height * 3
    seed = derive_seed(key)
    
    # 2. Create fresh generator
    pos_gen = create_position_generator(seed, max_pos)
    pixels = img.load()
    
    # 3. Read 32-bit length header
    def read_bits(n):
        """Read n bits from image using generator"""
        bits = []
        for _ in range(n):
            pos = next(pos_gen)
            y = pos // (width * 3)
            x = (pos // 3) % width
            channel = pos % 3
            
            r, g, b = pixels[x, y]
            bit = (r, g, b)[channel] & 1
            bits.append(bit)
        return bits
    
    len_bits = read_bits(32)
    ciphertext_len = int.from_bytes(_bits_to_bytes(len_bits), 'big')
    
    total_bits = 32 + ciphertext_len * 8
    if total_bits > max_pos:
        raise ValueError("No hidden message or corrupted data")
    
    # 4. Read remaining bits
    data_bits = read_bits(ciphertext_len * 8)
    ciphertext = _bits_to_bytes(data_bits)
    
    # 5. Decrypt
    f = Fernet(key)
    plaintext = f.decrypt(ciphertext)
    
    return plaintext.decode('utf-8')

# ---------- GUI with threading ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Steganography Tool")
        self.geometry("650x480")
        self.configure(padx=10, pady=10)
        
        self.processing = False
        
        # Key frame
        key_frame = tk.Frame(self)
        key_frame.pack(fill="x", pady=5)
        
        tk.Label(key_frame, text="Key:", font=('Arial', 10, 'bold')).pack(side="left")
        self.key_entry = tk.Entry(key_frame, font=('Courier', 9), fg='blue')
        self.key_entry.pack(side="left", fill="x", expand=True, padx=5)
        tk.Button(key_frame, text="Generate", command=self.generate_key).pack(side="right")
        
        # Text area
        self.txt = scrolledtext.ScrolledText(self, height=15, font=('Arial', 10))
        self.txt.pack(fill="both", expand=True, pady=5)
        
        # Buttons
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill="x", pady=5)
        
        self.encode_btn = tk.Button(btn_frame, text="🔒 Encode", command=self.encode, 
                                   bg='#4CAF50', fg='white')
        self.encode_btn.pack(side="left", padx=5)
        
        self.decode_btn = tk.Button(btn_frame, text="🔓 Decode", command=self.decode,
                                   bg='#2196F3', fg='white')
        self.decode_btn.pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="Clear", command=self.clear_text).pack(side="left", padx=5)
        
        # Status
        self.status = tk.Label(self, text="Ready", relief=tk.SUNKEN, anchor='w')
        self.status.pack(side="bottom", fill="x")
        
        # Threading queue
        self.queue = queue.Queue()
        self.check_queue()
    
    def check_queue(self):
        """Check for messages from worker threads"""
        try:
            msg = self.queue.get_nowait()
            if msg['type'] == 'done':
                self.on_complete(msg['action'], msg['data'])
            elif msg['type'] == 'error':
                self.on_error(msg['exception'])
        except queue.Empty:
            pass
        self.after(100, self.check_queue)
    
    def set_processing(self, processing: bool):
        self.processing = processing
        state = tk.DISABLED if processing else tk.NORMAL
        self.encode_btn.config(state=state)
        self.decode_btn.config(state=state)
        self.key_entry.config(state=state if not processing else tk.DISABLED)
        self.status.config(text="Processing... please wait" if processing else "Ready")
    
    def generate_key(self):
        if self.processing:
            return
        key = generate_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.decode())
        self.status.config(text="✓ Key generated – save it somewhere safe!")
    
    def get_key(self) -> bytes:
        key_str = self.key_entry.get().strip()
        if not key_str:
            raise ValueError("Key required! Generate one or paste it here.")
        return key_str.encode()
    
    def encode(self):
        if self.processing:
            return
        
        try:
            key = self.get_key()
        except ValueError as e:
            messagebox.showwarning("Key", str(e))
            return
        
        image_path = filedialog.askopenfilename(
            title="Select cover image (PNG/BMP)",
            filetypes=[("PNG/BMP", "*.png;*.bmp"), ("All", "*.*")]
        )
        if not image_path:
            return
        
        text = self.txt.get("1.0", tk.END)
        if not text.strip():
            messagebox.showwarning("Input", "No text to hide")
            return
        
        save_path = filedialog.asksaveasfilename(
            title="Save stego image as PNG",
            defaultextension=".png",
            filetypes=[("PNG", "*.png")]
        )
        if not save_path:
            return
        
        self.set_processing(True)
        
        # Run in background thread
        threading.Thread(
            target=self.encode_worker,
            args=(image_path, text, save_path, key),
            daemon=True
        ).start()
    
    def encode_worker(self, image_path: str, text: str, save_path: str, key: bytes):
        try:
            encode_image(image_path, text, save_path, key)
            self.queue.put({'type': 'done', 'action': 'encode', 'data': save_path})
        except Exception as e:
            self.queue.put({'type': 'error', 'exception': e})
    
    def decode(self):
        if self.processing:
            return
        
        try:
            key = self.get_key()
        except ValueError as e:
            messagebox.showwarning("Key", str(e))
            return
        
        image_path = filedialog.askopenfilename(
            title="Select image with hidden text",
            filetypes=[("PNG/BMP", "*.png;*.bmp"), ("All", "*.*")]
        )
        if not image_path:
            return
        
        self.set_processing(True)
        
        threading.Thread(
            target=self.decode_worker,
            args=(image_path, key),
            daemon=True
        ).start()
    
    def decode_worker(self, image_path: str, key: bytes):
        try:
            text = decode_image(image_path, key)
            self.queue.put({'type': 'done', 'action': 'decode', 'data': text})
        except Exception as e:
            self.queue.put({'type': 'error', 'exception': e})
    
    def on_complete(self, action: str, data):
        self.set_processing(False)
        if action == 'encode':
            messagebox.showinfo("Success", 
                f"✓ Text encrypted and hidden!\n\n"
                f"KEY (SAVE THIS):\n{self.key_entry.get()}\n\n"
                f"Image saved to:\n{data}")
        elif action == 'decode':
            self.txt.delete("1.0", tk.END)
            self.txt.insert("1.0", data)
            messagebox.showinfo("Success", "✓ Message decrypted and revealed!")
    
    def on_error(self, exception: Exception):
        self.set_processing(False)
        messagebox.showerror("Error", f"Operation failed:\n\n{exception}")
    
    def clear_text(self):
        if not self.processing:
            self.txt.delete("1.0", tk.END)

if __name__ == "__main__":
    App().mainloop()
