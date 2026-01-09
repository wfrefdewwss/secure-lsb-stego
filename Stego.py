#!/usr/bin/env python3
"""
Fast Secure Steganography with AES & Randomized Positions
- Optimized for large images (no memory crashes)
- Non-blocking GUI (no freezes)
- Two encryption methods: Fernet (default) and AES-256-GCM (more secure)
- No version signatures in encoded data for stealth
- Dark mode by default
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image
import hashlib
import secrets  # Changed from random (imported as requested)
import threading
import queue
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import pyperclip
import platform
import subprocess
import base64
import os

# Requirements: pip install Pillow cryptography pyperclip

# ---------- Deterministic RNG (replaces random.Random) ----------
class DeterministicRNG:
    """Cryptographically secure deterministic RNG using repeated hashing"""
    def __init__(self, seed: int):
        # Convert seed to 32-byte array for consistent hashing
        self.seed = seed.to_bytes(32, 'big', signed=False)
        self.counter = 0
    
    def randrange(self, max_val: int) -> int:
        """Generate deterministic pseudo-random number in range [0, max_val)"""
        if max_val <= 0:
            raise ValueError("max_val must be positive")
        
        # Generate hash from seed + counter for deterministic but unpredictable output
        data = self.seed + self.counter.to_bytes(8, 'big', signed=False)
        hash_val = hashlib.sha256(data).digest()
        num = int.from_bytes(hash_val, 'big')
        result = num % max_val
        self.counter += 1
        return result


# ---------- Theme Manager ----------
class ThemeManager:
    THEMES = {
        'light': {
            'bg': '#fafafa',
            'fg': '#111111',
            'entry_bg': '#ffffff',
            'entry_fg': '#111111',
            'button_bg': '#e8e8e8',
            'button_fg': '#111111',
            'button_hover': '#dcdcdc',
            'accent_encode': '#2e7d32',
            'accent_decode': '#1565c0',
            'border': '#cccccc',
            'status_bg': '#e8e8e8',
            'frame_bg': '#f5f5f5',
        },
        'dark': {
            'bg': '#1e1e1e',
            'fg': '#e0e0e0',
            'entry_bg': '#252525',
            'entry_fg': '#e0e0e0',
            'button_bg': '#2d2d2d',
            'button_fg': '#e0e0e0',
            'button_hover': '#3a3a3a',
            'accent_encode': '#66bb6a',
            'accent_decode': '#42a5f5',
            'border': '#444444',
            'status_bg': '#252525',
            'frame_bg': '#252525',
        }
    }
    
    def __init__(self, root):
        self.root = root
        self.mode = 'dark'  # Default to dark mode
        self._widgets = []
    
    def detect_system_theme(self):
        """Detect system theme preference for Windows, Linux, and macOS"""
        system = platform.system()
        try:
            if system == 'Windows':
                import winreg
                registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
                key = winreg.OpenKey(registry, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                return 'light' if value else 'dark'
                
            elif system == 'Darwin':  # macOS
                result = subprocess.run(['defaults', 'read', '-g', 'AppleInterfaceStyle'], 
                                      capture_output=True, text=True)
                return 'dark' if 'Dark' in result.stdout else 'light'
                
            elif system == 'Linux':
                # Try freedesktop portal (most modern standard)
                result = subprocess.run([
                    'gsettings', 'get', 'org.freedesktop.appearance', 'color-scheme'
                ], capture_output=True, text=True)
                if result.returncode == 0:
                    return 'dark' if 'dark' in result.stdout.lower() else 'light'
                
                # Fallback to GTK theme name
                result = subprocess.run([
                    'gsettings', 'get', 'org.gnome.desktop.interface', 'gtk-theme'
                ], capture_output=True, text=True)
                if result.returncode == 0:
                    theme_name = result.stdout.lower().strip("'")
                    return 'dark' if 'dark' in theme_name else 'light'
        except:
            pass
        return 'light'
    
    def get_theme(self):
        if self.mode == 'system':
            theme_name = self.detect_system_theme()
        else:
            theme_name = self.mode
        return self.THEMES.get(theme_name, self.THEMES['dark']).copy()
    
    def set_mode(self, mode):
        if mode in ['system', 'light', 'dark']:
            self.mode = mode
            self._apply_theme()
    
    def _apply_theme(self):
        theme = self.get_theme()
        self.root.configure(bg=theme['bg'])
        
        for widget, widget_type, accent_type in self._widgets:
            try:
                if widget_type == 'button':
                    bg = theme.get(f'accent_{accent_type}', theme['button_bg']) if accent_type else theme['button_bg']
                    widget.configure(bg=bg, fg=theme['button_fg'], activebackground=bg, activeforeground=theme['button_fg'])
                    widget._theme_bg = bg
                    widget._theme_hover = theme['button_hover']
                elif widget_type == 'entry':
                    widget.configure(bg=theme['entry_bg'], fg=theme['entry_fg'], insertbackground=theme['fg'])
                elif widget_type == 'combobox':
                    widget.configure(style=f'{self.mode}.TCombobox')
                elif widget_type in ['label', 'status']:
                    widget.configure(bg=theme['bg'], fg=theme['fg'])
                elif widget_type == 'text':
                    widget.configure(bg=theme['entry_bg'], fg=theme['entry_fg'], insertbackground=theme['fg'])
                elif widget_type in ['frame', 'labelframe']:
                    widget.configure(bg=theme['frame_bg'] if widget_type == 'frame' else theme['bg'])
                    if widget_type == 'labelframe':
                        widget.configure(fg=theme['fg'])
                elif widget_type == 'status_bar':
                    widget.configure(bg=theme['status_bg'])
            except tk.TclError:
                pass  # Widget destroyed
    
    def register(self, widget, widget_type, accent_type=None):
        self._widgets.append((widget, widget_type, accent_type))
    
    def create_button(self, parent, text, command, accent_type=None, **kwargs):
        btn = tk.Button(parent, text=text, command=command, relief=tk.FLAT, bd=1, font=('Segoe UI', 9), **kwargs)
        btn._theme_bg = None
        btn._theme_hover = None
        btn._is_accent = accent_type is not None
        
        def on_enter(e):
            if not e.widget._is_accent and e.widget._theme_hover:
                e.widget.configure(bg=e.widget._theme_hover)
        
        def on_leave(e):
            if e.widget._theme_bg:
                e.widget.configure(bg=e.widget._theme_bg)
        
        btn.bind('<Enter>', on_enter)
        btn.bind('<Leave>', on_leave)
        
        self.register(btn, 'button', accent_type)
        return btn

# ---------- Encryption Methods ----------
def generate_key(method='fernet') -> bytes:
    """Generate key for selected method"""
    if method == 'fernet':
        return Fernet.generate_key()
    elif method == 'aes256gcm':
        # Generate 32-byte key and encode as base64
        return base64.urlsafe_b64encode(os.urandom(32))
    else:
        raise ValueError(f"Unknown method: {method}")

def encrypt_data(method, key, plaintext):
    """Encrypt data using selected method - no version signatures"""
    if method == 'fernet':
        f = Fernet(key)
        return f.encrypt(plaintext)
    elif method == 'aes256gcm':
        # Decode base64 key to get raw 32-byte key
        raw_key = base64.urlsafe_b64decode(key)
        aesgcm = AESGCM(raw_key)
        nonce = os.urandom(12)  # 96-bit nonce
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        # Prepend nonce (standard practice, not a version signature)
        return nonce + ciphertext
    else:
        raise ValueError(f"Unknown method: {method}")

def decrypt_data(method, key, ciphertext):
    """Decrypt data using selected method"""
    if method == 'fernet':
        f = Fernet(key)
        return f.decrypt(ciphertext)
    elif method == 'aes256gcm':
        raw_key = base64.urlsafe_b64decode(key)
        aesgcm = AESGCM(raw_key)
        nonce = ciphertext[:12]
        actual_ciphertext = ciphertext[12:]
        return aesgcm.decrypt(nonce, actual_ciphertext, None)
    else:
        raise ValueError(f"Unknown method: {method}")

# ---------- crypto ----------
def derive_seed(key: bytes) -> int:
    """Deterministically derive integer seed from key"""
    return int.from_bytes(hashlib.sha256(key).digest(), 'big')

# ---------- position generator ----------
def create_position_generator(seed: int, max_pos: int):
    """
    Return a generator that yields unique random positions.
    Memory-efficient: doesn't create a list of all positions.
    """
    rng = DeterministicRNG(seed)
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
def encode_image(image_path: str, text: str, save_path: str, key: bytes, method: str):
    """Hide encrypted text at random locations - optimized"""
    # Encrypt text using selected method
    ciphertext = encrypt_data(method, key, text.encode('utf-8'))
    
    # Payload: 4-byte length + ciphertext (no version signature)
    payload = len(ciphertext).to_bytes(4, 'big') + ciphertext
    bits = _bytes_to_bits(payload)
    
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    width, height = img.size
    max_pos = width * height * 3
    if len(bits) > max_pos:
        raise ValueError(f"Image too small: need {len(bits)} bits, have {max_pos}")
    
    seed = derive_seed(key)
    pos_gen = create_position_generator(seed, max_pos)
    pixels = img.load()
    
    for bit in bits:
        pos = next(pos_gen)
        y = pos // (width * 3)
        x = (pos // 3) % width
        channel = pos % 3
        
        r, g, b = pixels[x, y]
        if channel == 0: r = (r & ~1) | bit
        elif channel == 1: g = (g & ~1) | bit
        else: b = (b & ~1) | bit
        pixels[x, y] = (r, g, b)
    
    img.save(save_path, 'PNG')

def decode_image(image_path: str, key: bytes, method: str) -> str:
    """Extract & decrypt text - optimized"""
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    width, height = img.size
    max_pos = width * height * 3
    seed = derive_seed(key)
    pos_gen = create_position_generator(seed, max_pos)
    pixels = img.load()
    
    def read_bits(n):
        bits = []
        for _ in range(n):
            pos = next(pos_gen)
            y = pos // (width * 3)
            x = (pos // 3) % width
            channel = pos % 3
            r, g, b = pixels[x, y]
            bits.append((r, g, b)[channel] & 1)
        return bits
    
    len_bits = read_bits(32)
    ciphertext_len = int.from_bytes(_bits_to_bytes(len_bits), 'big')
    
    if 32 + ciphertext_len * 8 > max_pos:
        raise ValueError("No hidden message or corrupted data")
    
    data_bits = read_bits(ciphertext_len * 8)
    ciphertext = _bits_to_bytes(data_bits)
    
    # Decrypt using selected method
    plaintext = decrypt_data(method, key, ciphertext)
    return plaintext.decode('utf-8')

# ---------- Minimalist GUI ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Steganography")
        self.geometry("700x500")
        
        # Initialize theme manager with dark as default
        self.theme_manager = ThemeManager(self)
        self.theme_manager.set_mode('dark')  # Default to dark mode
        
        self.processing = False
        self.setup_ui()
        
        self.queue = queue.Queue()
        self.check_queue()
    
    def setup_ui(self):
        """Setup the minimalist UI with clean spacing"""
        main = tk.Frame(self)
        main.pack(fill="both", expand=True, padx=20, pady=20)
        main.grid_rowconfigure(1, weight=1)  # Message area expands
        main.grid_columnconfigure(0, weight=1)
        
        # Style for combobox
        style = ttk.Style()
        style.theme_use('clam')
        
        def configure_combobox_theme():
            theme = self.theme_manager.get_theme()
            style.configure(f'{self.theme_manager.mode}.TCombobox', 
                          fieldbackground=theme['entry_bg'],
                          background=theme['button_bg'],
                          foreground=theme['entry_fg'],
                          arrowcolor=theme['button_fg'])
        
        configure_combobox_theme()
        
        # Key Section
        key_frame = tk.LabelFrame(main, text="Encryption Key", padx=10, pady=10, font=('Segoe UI', 9))
        key_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        key_frame.grid_columnconfigure(0, weight=1)
        
        self.key_entry = tk.Entry(key_frame, font=('Courier', 9))
        self.key_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        
        key_btn_frame = tk.Frame(key_frame)
        key_btn_frame.grid(row=0, column=1, sticky="e")
        
        self.paste_btn = self.theme_manager.create_button(key_btn_frame, "Paste", self.paste_key)
        self.paste_btn.pack(side="left", padx=2)
        self.copy_btn = self.theme_manager.create_button(key_btn_frame, "Copy", self.copy_key)
        self.copy_btn.pack(side="left", padx=2)
        self.gen_btn = self.theme_manager.create_button(key_btn_frame, "Generate", self.generate_key)
        self.gen_btn.pack(side="left", padx=2)
        
        # Encryption method selector
        method_frame = tk.Frame(key_frame)
        method_frame.grid(row=1, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self.theme_manager.register(method_frame, 'frame', None)
        
        method_label = tk.Label(method_frame, text="Method:", font=('Segoe UI', 8))
        method_label.pack(side="left")
        self.theme_manager.register(method_label, 'label', None)
        
        self.method_combo = ttk.Combobox(method_frame, values=['Fernet', 'AES-256-GCM'], 
                                       state='readonly', width=15, font=('Segoe UI', 8))
        self.method_combo.set('Fernet')  # Default to Fernet
        self.method_combo.pack(side="left", padx=(5, 0))
        self.theme_manager.register(self.method_combo, 'combobox', None)
        
        method_desc = tk.Label(method_frame, text="Fernet=default, AES-256-GCM=more secure", 
                             font=('Segoe UI', 7), fg='gray')
        method_desc.pack(side="left", padx=(10, 0))
        self.theme_manager.register(method_desc, 'label', None)
        
        # Message Section
        msg_frame = tk.LabelFrame(main, text="Message", padx=10, pady=10, font=('Segoe UI', 9))
        msg_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 15))
        msg_frame.grid_rowconfigure(0, weight=1)
        msg_frame.grid_columnconfigure(0, weight=1)
        
        self.txt = scrolledtext.ScrolledText(msg_frame, font=('Consolas', 9), wrap=tk.WORD)
        self.txt.grid(row=0, column=0, sticky="nsew")
        
        # Action Buttons
        btn_frame = tk.Frame(main)
        btn_frame.grid(row=2, column=0, sticky="ew", pady=(0, 15))
        
        self.encode_btn = self.theme_manager.create_button(btn_frame, "Encode", self.encode, accent_type='encode')
        self.encode_btn.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.decode_btn = self.theme_manager.create_button(btn_frame, "Decode", self.decode, accent_type='decode')
        self.decode_btn.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        clear_btn_frame = tk.Frame(btn_frame)
        clear_btn_frame.pack(side="right")
        self.theme_manager.register(clear_btn_frame, 'frame', None)
        
        self.clear_msg_btn = self.theme_manager.create_button(clear_btn_frame, "Clear Msg", self.clear_message)
        self.clear_msg_btn.pack(side="left", padx=2)
        self.clear_all_btn = self.theme_manager.create_button(clear_btn_frame, "Clear All", self.clear_all)
        self.clear_all_btn.pack(side="left", padx=2)
        
        # Status Bar
        status_frame = tk.Frame(main)
        status_frame.grid(row=3, column=0, sticky="ew")
        status_frame.grid_columnconfigure(0, weight=1)
        
        self.status = tk.Label(status_frame, text="Ready", anchor='w', font=('Segoe UI', 8))
        self.status.grid(row=0, column=0, sticky="w")
        
        self.theme_btn = self.theme_manager.create_button(status_frame, "DARK", self.cycle_theme)
        self.theme_btn.grid(row=0, column=1, sticky="e")
        
        # Register all widgets
        self.theme_manager.register(main, 'frame', None)
        self.theme_manager.register(key_frame, 'labelframe', None)
        self.theme_manager.register(self.key_entry, 'entry', None)
        self.theme_manager.register(key_btn_frame, 'frame', None)
        self.theme_manager.register(msg_frame, 'labelframe', None)
        self.theme_manager.register(self.txt, 'text', None)
        self.theme_manager.register(btn_frame, 'frame', None)
        self.theme_manager.register(clear_btn_frame, 'frame', None)
        self.theme_manager.register(status_frame, 'status_bar', None)
        self.theme_manager.register(self.status, 'status', None)
        
        self.theme_manager._apply_theme()
        # Re-apply combobox theme after main theme application
        configure_combobox_theme()
    
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
    
    def cycle_theme(self):
        """Cycle through dark/light/system modes"""
        modes = ['dark', 'light', 'system']
        current_idx = modes.index(self.theme_manager.mode)
        next_mode = modes[(current_idx + 1) % len(modes)]
        self.theme_manager.set_mode(next_mode)
        
        mode_labels = {'system': 'SYSTEM', 'light': 'LIGHT', 'dark': 'DARK'}
        self.theme_btn.config(text=mode_labels[next_mode])
        self.status.config(text=f"Theme: {next_mode.title()}")
        self.after(1500, lambda: self.status.config(text="Ready"))
    
    def set_processing(self, processing: bool):
        self.processing = processing
        state = tk.DISABLED if processing else tk.NORMAL
        for btn in [self.encode_btn, self.decode_btn, self.clear_msg_btn, self.clear_all_btn, 
                   self.gen_btn, self.copy_btn, self.paste_btn, self.theme_btn]:
            btn.config(state=state)
        self.key_entry.config(state=tk.NORMAL if not processing else tk.DISABLED)
        self.txt.config(state=tk.NORMAL if not processing else tk.DISABLED)
        self.method_combo.config(state=tk.NORMAL if not processing else tk.DISABLED)
        self.status.config(text="Processing... please wait" if processing else "Ready")
    
    def copy_key(self):
        if self.processing: return
        key = self.key_entry.get().strip()
        if key:
            try:
                pyperclip.copy(key)
                self.status.config(text="Key copied")
            except Exception as e:
                self.status.config(text=f"Copy failed: {e}")
                self.after(3000, lambda: self.status.config(text="Ready"))
                return
        else:
            self.status.config(text="No key to copy")
        self.after(1500, lambda: self.status.config(text="Ready"))
    
    def paste_key(self):
        if self.processing: return
        try:
            clipboard_content = pyperclip.paste()
            if not clipboard_content:
                self.status.config(text="Clipboard empty")
                self.after(1500, lambda: self.status.config(text="Ready"))
                return
            
            # Clear existing text before pasting
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, clipboard_content)
            self.status.config(text="Key pasted")
            self.after(1500, lambda: self.status.config(text="Ready"))
        except Exception as e:
            self.status.config(text=f"Paste failed: {e}")
            self.after(3000, lambda: self.status.config(text="Ready"))
    
    def generate_key(self):
        if self.processing: return
        method = self.get_method()
        key = generate_key(method)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.decode())
        self.status.config(text="Key generated – save it safe!")
        self.after(3000, lambda: self.status.config(text="Ready"))
    
    def get_key(self) -> bytes:
        key_str = self.key_entry.get().strip()
        if not key_str:
            raise ValueError("Key required! Generate one or paste it here.")
        return key_str.encode()
    
    def get_method(self) -> str:
        """Get selected encryption method"""
        method_map = {
            'Fernet': 'fernet',
            'AES-256-GCM': 'aes256gcm'
        }
        return method_map[self.method_combo.get()]
    
    def encode(self):
        if self.processing: return
        try:
            key = self.get_key()
        except ValueError as e:
            return messagebox.showwarning("Key", str(e))
        
        image_path = filedialog.askopenfilename(title="Select cover image", 
                                              filetypes=[("PNG/BMP", "*.png;*.bmp"), ("All", "*.*")])
        if not image_path: return
        
        text = self.txt.get("1.0", tk.END)
        if not text.strip(): return messagebox.showwarning("Input", "No text to hide")
        
        save_path = filedialog.asksaveasfilename(title="Save stego image", defaultextension=".png", 
                                               filetypes=[("PNG", "*.png")])
        if not save_path: return
        
        method = self.get_method()
        self.set_processing(True)
        threading.Thread(target=self.encode_worker, args=(image_path, text, save_path, key, method), daemon=True).start()
    
    def encode_worker(self, image_path: str, text: str, save_path: str, key: bytes, method: str):
        try:
            encode_image(image_path, text, save_path, key, method)
            self.queue.put({'type': 'done', 'action': 'encode', 'data': save_path})
        except Exception as e:
            self.queue.put({'type': 'error', 'exception': e})
    
    def decode(self):
        if self.processing: return
        try:
            key = self.get_key()
        except ValueError as e:
            return messagebox.showwarning("Key", str(e))
        
        image_path = filedialog.askopenfilename(title="Select image", 
                                              filetypes=[("PNG/BMP", "*.png;*.bmp"), ("All", "*.*")])
        if not image_path: return
        
        method = self.get_method()
        self.set_processing(True)
        threading.Thread(target=self.decode_worker, args=(image_path, key, method), daemon=True).start()
    
    def decode_worker(self, image_path: str, key: bytes, method: str):
        try:
            text = decode_image(image_path, key, method)
            self.queue.put({'type': 'done', 'action': 'decode', 'data': text})
        except Exception as e:
            self.queue.put({'type': 'error', 'exception': e})
    
    def on_complete(self, action: str, data):
        self.set_processing(False)
        if action == 'encode':
            messagebox.showinfo("Success", f"Text encrypted and hidden!\n\n"
                                          f"KEY (SAVE THIS):\n{self.key_entry.get()}\n\n"
                                          f"Image saved to:\n{data}")
        elif action == 'decode':
            self.txt.delete("1.0", tk.END)
            self.txt.insert("1.0", data)
            messagebox.showinfo("Success", "Message decrypted and revealed!")
    
    def on_error(self, exception: Exception):
        self.set_processing(False)
        messagebox.showerror("Error", f"Operation failed:\n\n{exception}")
    
    def clear_message(self):
        if not self.processing:
            self.txt.delete("1.0", tk.END)
            self.status.config(text="Message cleared")
            self.after(1500, lambda: self.status.config(text="Ready"))
    
    def clear_all(self):
        if not self.processing:
            self.key_entry.delete(0, tk.END)
            self.txt.delete("1.0", tk.END)
            self.status.config(text="All fields cleared")
            self.after(1500, lambda: self.status.config(text="Ready"))

if __name__ == "__main__":
    app = App()
    app.mainloop()
