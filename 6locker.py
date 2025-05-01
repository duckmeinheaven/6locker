import tkinter as tk
from tkinter import ttk, scrolledtext, Toplevel, font
import hashlib
import base64
import secrets
import time
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os

class ModernUI:
    """Modern UI theme for tkinter"""
    
    # Color scheme - Dark theme
    DARK_BG = "#1e1e1e"
    DARKER_BG = "#252526"
    ACCENT = "#007acc"  # Blue accent
    TEXT = "#ffffff"
    TEXT_DISABLED = "#a0a0a0"
    HIGHLIGHT = "#3e3e3e"
    BUTTON_BG = "#2d2d2d"
    BUTTON_ACTIVE = "#3c3c3c"
    BUTTON_PRESSED = "#0066aa"
    ERROR = "#f44336"  # Red
    SUCCESS = "#4caf50"  # Green
    WARNING = "#ff9800"  # Orange
    INFO = "#2196f3"  # Light blue
    
    @staticmethod
    def apply_theme(root):
        """Apply modern theme to the application"""
        style = ttk.Style()
        
        # Configure basic styles
        style.configure("TFrame", background=ModernUI.DARK_BG)
        style.configure("TLabel", background=ModernUI.DARK_BG, foreground=ModernUI.TEXT)
        style.configure("TLabelframe", background=ModernUI.DARK_BG, foreground=ModernUI.TEXT)
        style.configure("TLabelframe.Label", background=ModernUI.DARK_BG, foreground=ModernUI.TEXT)
        style.configure("TCheckbutton", background=ModernUI.DARK_BG, foreground=ModernUI.TEXT)
        
        # Button styles
        style.configure("TButton", 
                       background=ModernUI.DARK_BG,
                       foreground=ModernUI.TEXT, 
                       focuscolor=ModernUI.ACCENT,
                       borderwidth=1,
                       relief="raised",
                       padding=(10, 5),
                       font=("Segoe UI", 9, "bold"))
        
        style.map("TButton",
                background=[('pressed', ModernUI.BUTTON_PRESSED), ('active', ModernUI.BUTTON_ACTIVE)],
                foreground=[('pressed', ModernUI.TEXT), ('active', ModernUI.TEXT)],
                relief=[('pressed', 'sunken')])
        
        # Special button styles
        style.configure("Accent.TButton", 
                      background=ModernUI.ACCENT,
                      foreground=ModernUI.TEXT,
                      borderwidth=1,
                      relief="raised",
                      padding=(10, 5),
                      font=("Segoe UI", 9, "bold"))
                      
        style.map("Accent.TButton",
                background=[('pressed', "#005c99"), ('active', "#0088cc")],
                foreground=[('pressed', ModernUI.TEXT), ('active', ModernUI.TEXT)],
                relief=[('pressed', 'sunken')])
        
        # Progress bar
        style.configure("TProgressbar", 
                      background=ModernUI.ACCENT,
                      troughcolor=ModernUI.DARKER_BG,
                      borderwidth=0)
        
        # Configure the scale
        style.configure("TScale", 
                      background=ModernUI.DARK_BG,
                      troughcolor=ModernUI.HIGHLIGHT,
                      sliderrelief="flat")
        
        # Set the main background
        root.configure(background=ModernUI.DARK_BG)
        
        # Create custom fonts
        default_font = font.nametofont("TkDefaultFont")
        default_font.configure(family="Segoe UI", size=10)
        
        heading_font = font.Font(family="Segoe UI", size=12, weight="bold")
        code_font = font.Font(family="Consolas", size=10)
        
        return heading_font, code_font

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Şifreleme Uygulaması")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Apply modern theme
        self.heading_font, self.code_font = ModernUI.apply_theme(root)
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # App title
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = ttk.Label(title_frame, text="MODERN ŞİFRELEME UYGULAMASI", 
                              font=("Segoe UI", 16, "bold"))
        title_label.pack(side=tk.LEFT)
        
        # Input area
        input_frame = ttk.LabelFrame(main_frame, text="Metin Girişi", padding="10")
        input_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.text_input = scrolledtext.ScrolledText(
            input_frame, 
            wrap=tk.WORD, 
            height=6,
            bg=ModernUI.DARKER_BG,
            fg=ModernUI.TEXT,
            insertbackground=ModernUI.TEXT,  # Cursor color
            selectbackground=ModernUI.ACCENT,
            font=("Consolas", 11)
        )
        self.text_input.pack(fill=tk.BOTH, expand=True)
        
        # Encryption level selection
        level_frame = ttk.Frame(main_frame)
        level_frame.pack(fill=tk.X, pady=5)
        
        level_label = ttk.Label(level_frame, text="Şifreleme Seviyesi (1-100):", font=("Segoe UI", 10, "bold"))
        level_label.pack(side=tk.LEFT, padx=5)
        
        self.level_var = tk.IntVar(value=50)
        self.level_scale = ttk.Scale(level_frame, from_=1, to=100, orient=tk.HORIZONTAL, 
                                    variable=self.level_var, length=300)
        self.level_scale.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        self.level_label = ttk.Label(level_frame, text="50", width=3)
        self.level_label.pack(side=tk.LEFT, padx=5)
        
        # Bind scale change to update label
        self.level_var.trace_add("write", self.update_level_label)
        
        # Encryption method selection
        method_frame = ttk.LabelFrame(main_frame, text="Şifreleme Yöntemleri", padding="10")
        method_frame.pack(fill=tk.X, pady=5)
        
        # Grid layout for encryption buttons
        button_frame1 = ttk.Frame(method_frame)
        button_frame1.pack(fill=tk.X, pady=5)
        
        self.auto_method_var = tk.BooleanVar(value=True)
        self.auto_method_check = ttk.Checkbutton(button_frame1, 
                                               text="Otomatik Yöntem Seçimi (Seviyeye Göre)", 
                                               variable=self.auto_method_var,
                                               command=self.toggle_method_buttons)
        self.auto_method_check.pack(pady=5)
        
        # Create a frame for the encryption buttons
        button_frame2 = ttk.Frame(method_frame)
        button_frame2.pack(fill=tk.X, pady=5)
        
        # Standart buton stilleri
        button_style = {
            "bg": ModernUI.BUTTON_BG,
            "fg": ModernUI.TEXT,
            "activebackground": ModernUI.BUTTON_ACTIVE,
            "activeforeground": ModernUI.TEXT,
            "relief": "raised",
            "borderwidth": 1,
            "padx": 10,
            "pady": 5,
            "font": ("Segoe UI", 9, "bold")
        }
        
        accent_button_style = button_style.copy()
        accent_button_style["bg"] = ModernUI.ACCENT
        accent_button_style["activebackground"] = "#0088cc"
        
        # Create encryption buttons with standard tk buttons
        self.caesar_button = tk.Button(
            button_frame2, 
            text="Sezar Şifresi", 
            command=lambda: self.start_encryption("caesar"),
            state=tk.DISABLED,
            **button_style
        )
        self.caesar_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        self.aes_button = tk.Button(
            button_frame2, 
            text="AES Şifreleme", 
            command=lambda: self.start_encryption("aes"),
            state=tk.DISABLED,
            **button_style
        )
        self.aes_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        self.fernet_button = tk.Button(
            button_frame2, 
            text="Fernet Şifreleme", 
            command=lambda: self.start_encryption("fernet"),
            state=tk.DISABLED,
            **button_style
        )
        self.fernet_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        
        self.rsa_button = tk.Button(
            button_frame2, 
            text="RSA Şifreleme", 
            command=lambda: self.start_encryption("rsa"),
            state=tk.DISABLED,
            **button_style
        )
        self.rsa_button.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        
        self.blowfish_button = tk.Button(
            button_frame2, 
            text="Blowfish Şifreleme", 
            command=lambda: self.start_encryption("blowfish"),
            state=tk.DISABLED,
            **button_style
        )
        self.blowfish_button.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        self.auto_button = tk.Button(
            button_frame2, 
            text="Otomatik Şifreleme", 
            command=lambda: self.start_encryption("auto"),
            **accent_button_style
        )
        self.auto_button.grid(row=1, column=2, padx=5, pady=5, sticky="ew")
        
        # Configure button weights for even spacing
        button_frame2.columnconfigure(0, weight=1)
        button_frame2.columnconfigure(1, weight=1)
        button_frame2.columnconfigure(2, weight=1)
        
        # Action buttons frame
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        # Decrypt guide button (initially disabled)
        self.decrypt_guide_button = tk.Button(
            action_frame, 
            text="Şifre Çözme Rehberi", 
            command=self.show_decrypt_guide, 
            state=tk.DISABLED,
            **button_style
        )
        self.decrypt_guide_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar (hidden initially)
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.pack(fill=tk.X, pady=10)
        self.progress_frame.pack_forget()
        
        self.progress_label = ttk.Label(self.progress_frame, text="Şifreleniyor...")
        self.progress_label.pack(pady=5)
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, mode="indeterminate", length=400)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # Output area with modern styling
        output_frame = ttk.LabelFrame(main_frame, text="Şifreleme Sonucu", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, 
            wrap=tk.WORD, 
            height=14, 
            bg=ModernUI.DARKER_BG,
            fg=ModernUI.TEXT,
            insertbackground=ModernUI.TEXT,
            selectbackground=ModernUI.ACCENT,
            font=self.code_font
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Store encryption results for later use in decryption guide
        self.current_encryption = {
            "encrypted": None,
            "method": None,
            "level": None,
            "decrypt_info": None,
            "detailed_steps": None
        }
        
        # Add status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(10, 0))
        
        status_label = ttk.Label(status_frame, text="Hazır", anchor=tk.W)
        status_label.pack(side=tk.LEFT)
        
        version_label = ttk.Label(status_frame, text="v1.0.0", anchor=tk.E)
        version_label.pack(side=tk.RIGHT)
        
    def update_level_label(self, *args):
        self.level_label.config(text=str(self.level_var.get()))
        
    def toggle_method_buttons(self):
        if self.auto_method_var.get():
            state = tk.DISABLED
            self.auto_button["state"] = tk.NORMAL
        else:
            state = tk.NORMAL
            self.auto_button["state"] = tk.DISABLED
            
        self.caesar_button["state"] = state
        self.aes_button["state"] = state
        self.fernet_button["state"] = state
        self.rsa_button["state"] = state
        self.blowfish_button["state"] = state
        
    def start_encryption(self, method="auto"):
        # Get input text and encryption level
        text = self.text_input.get("1.0", tk.END).strip()
        level = self.level_var.get()
        
        if not text:
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, "Lütfen şifrelenecek bir metin girin.")
            return
        
        # Disable all buttons during encryption
        self.disable_all_buttons()
        
        # Show progress bar
        self.progress_frame.pack(fill=tk.X, pady=10)
        self.progress_bar.start(10)
        
        # Start encryption in a separate thread
        threading.Thread(target=self.perform_encryption, args=(text, level, method), daemon=True).start()
    
    def disable_all_buttons(self):
        self.auto_button["state"] = tk.DISABLED
        self.caesar_button["state"] = tk.DISABLED
        self.aes_button["state"] = tk.DISABLED
        self.fernet_button["state"] = tk.DISABLED
        self.rsa_button["state"] = tk.DISABLED
        self.blowfish_button["state"] = tk.DISABLED
        self.decrypt_guide_button["state"] = tk.DISABLED
        self.auto_method_check.config(state=tk.DISABLED)
    
    def enable_buttons(self):
        auto_mode = self.auto_method_var.get()
        self.auto_method_check.config(state=tk.NORMAL)
        self.auto_button["state"] = tk.NORMAL if auto_mode else tk.DISABLED
        self.caesar_button["state"] = tk.DISABLED if auto_mode else tk.NORMAL
        self.aes_button["state"] = tk.DISABLED if auto_mode else tk.NORMAL
        self.fernet_button["state"] = tk.DISABLED if auto_mode else tk.NORMAL
        self.rsa_button["state"] = tk.DISABLED if auto_mode else tk.NORMAL
        self.blowfish_button["state"] = tk.DISABLED if auto_mode else tk.NORMAL
        self.decrypt_guide_button["state"] = tk.NORMAL
    
    def perform_encryption(self, text, level, method="auto"):
        # Simulate encryption processing time based on level
        time.sleep(1 + (level / 100))
        
        # Determine which encryption method to use
        if method == "auto":
            # Choose method based on level
            if level < 30:
                actual_method = "caesar"
            elif level < 60:
                actual_method = "fernet"
            else:
                actual_method = "rsa"
        else:
            actual_method = method
        
        # Perform the selected encryption
        if actual_method == "caesar":
            encrypted, decrypt_info, detailed_steps = self.simple_encryption(text, level)
            method_name = "Sezar Şifresi ve Base64"
        elif actual_method == "aes":
            encrypted, decrypt_info, detailed_steps = self.aes_encryption(text, level)
            method_name = "AES Şifreleme"
        elif actual_method == "fernet":
            encrypted, decrypt_info, detailed_steps = self.medium_encryption(text, level)
            method_name = "Fernet Şifreleme"
        elif actual_method == "blowfish":
            encrypted, decrypt_info, detailed_steps = self.blowfish_encryption(text, level)
            method_name = "Blowfish Şifreleme"
        elif actual_method == "rsa":
            encrypted, decrypt_info, detailed_steps = self.advanced_encryption(text, level)
            method_name = "RSA Asimetrik Şifreleme"
        else:
            # Fallback to simple encryption
            encrypted, decrypt_info, detailed_steps = self.simple_encryption(text, level)
            method_name = "Basit Şifreleme"
        
        # Store current encryption details
        self.current_encryption = {
            "encrypted": encrypted,
            "method": method_name,
            "level": level,
            "decrypt_info": decrypt_info,
            "detailed_steps": detailed_steps,
            "original_text": text
        }
        
        # Update UI in the main thread
        self.root.after(0, self.update_ui_after_encryption, encrypted, decrypt_info, method_name, level)
    
    def update_ui_after_encryption(self, encrypted, decrypt_info, method, level):
        # Stop progress animation and hide resource frame
        self.progress_bar.stop()
        self.progress_frame.pack_forget()
        
        # Re-enable buttons
        self.enable_buttons()
        
        # Update output
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, f"Şifrelenmiş Metin:\n{encrypted}\n\n")
        self.output_text.insert(tk.END, f"Kullanılan Şifreleme Metodu: {method} (Seviye: {level})\n\n")
        self.output_text.insert(tk.END, f"Şifre Çözme Bilgileri:\n{decrypt_info}")
    
    def simple_encryption(self, text, level):
        # Caesar cipher with level as shift and base64 encoding
        shift = level % 26
        shifted = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                shifted += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                shifted += char
        
        # Add some randomness and use base64
        salt = secrets.token_hex(4)
        salted = salt + shifted
        encrypted = base64.b64encode(salted.encode()).decode()
        
        decrypt_info = (f"1. Base64 ile çöz: base64.b64decode(şifreli_metin).decode()\n"
                        f"2. İlk 8 karakteri (salt) at\n"
                        f"3. Sezar şifresini {26-shift} kaydırarak çöz")
        
        # Detailed step-by-step guide for the decryption window
        original_example = text[:10] + "..." if len(text) > 10 else text
        detailed_steps = f"""# Sezar Şifresi ve Base64 Şifre Çözme Rehberi

## Şifreleme Detayları:
- Şifreleme Seviyesi: {level}
- Sezar Şifresi Kaydırma Değeri: {shift}
- Kullanılan Salt: {salt}

## Örnek:
- Orijinal metin: "{original_example}"
- Salt eklenmiş: "{salt + (shifted[:10] + '...' if len(shifted) > 10 else shifted)}"
- Base64 ile şifrelenmiş: "{encrypted}"

## Adım Adım Şifre Çözme:

1. **Base64 Şifresini Çöz:**
   ```python
   import base64
   coded_text = "{encrypted}"
   decoded_text = base64.b64decode(coded_text).decode()
   # Sonuç: "{salt + (shifted[:10] + '...' if len(shifted) > 10 else shifted)}"
   ```

2. **Salt Değerini Kaldır:**
   ```python
   # Salt değeri ilk 8 karakterdir
   salt = decoded_text[:8]  # "{salt}"
   text_with_caesar = decoded_text[8:]
   # Sonuç: "{shifted[:10] + '...' if len(shifted) > 10 else shifted}"
   ```

3. **Sezar Şifresini Çöz:**
   ```python
   reverse_shift = {26-shift}  # ({26} - {shift})
   decrypted = ""
   
   for char in text_with_caesar:
       if char.isalpha():
           ascii_offset = 65 if char.isupper() else 97
           decrypted += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
       else:
           decrypted += char
   
   # Sonuç: "{original_example}"
   ```

4. **Tam Python Kodu:**
   ```python
   import base64
   
   def decode_text(encrypted_text, shift):
       # Base64 decode
       decoded = base64.b64decode(encrypted_text).decode()
       
       # Remove salt (first 8 characters)
       text_with_caesar = decoded[8:]
       
       # Reverse Caesar cipher
       decrypted = ""
       for char in text_with_caesar:
           if char.isalpha():
               ascii_offset = 65 if char.isupper() else 97
               decrypted += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
           else:
               decrypted += char
       
       return decrypted
   
   # Decrypt the text
   decrypted_text = decode_text("{encrypted}", {shift})
   print(decrypted_text)
   ```"""
        
        return encrypted, decrypt_info, detailed_steps
    
    def medium_encryption(self, text, level):
        # Use PBKDF2 with Fernet
        salt = os.urandom(16)
        iterations = 100000 + (level * 1000)
        
        # Generate a key using PBKDF2
        password = secrets.token_hex(8)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Encrypt with Fernet
        f = Fernet(key)
        encrypted = f.encrypt(text.encode()).decode()
        
        # Encode salt for storage
        salt_b64 = base64.b64encode(salt).decode()
        
        decrypt_info = (f"Şifre Çözme Anahtarı: {password}\n"
                        f"Salt (Base64): {salt_b64}\n"
                        f"İterasyon Sayısı: {iterations}\n"
                        f"Çözüm için PBKDF2HMAC ve Fernet kullanın:\n"
                        f"1. Şifreyi, salt'ı ve iterasyon sayısını kullanarak anahtarı türetin\n"
                        f"2. Fernet ile çözün: f.decrypt(encrypted.encode())")
        
        # Detailed step-by-step guide for the decryption window
        original_example = text[:10] + "..." if len(text) > 10 else text
        detailed_steps = f"""# PBKDF2 ve Fernet Şifre Çözme Rehberi

## Şifreleme Detayları:
- Şifreleme Seviyesi: {level}
- İterasyon Sayısı: {iterations}
- Şifre Çözme Anahtarı: {password}
- Salt (Base64): {salt_b64}

## Örnek:
- Orijinal metin: "{original_example}"
- Fernet ile şifrelenmiş: "{encrypted[:40]}..." (kısaltılmış)

## Adım Adım Şifre Çözme:

1. **Gerekli Kütüphaneleri İçe Aktar:**
   ```python
   import base64
   from cryptography.fernet import Fernet
   from cryptography.hazmat.primitives import hashes
   from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
   ```

2. **Salt Değerini Hazırla:**
   ```python
   salt_b64 = "{salt_b64}"
   salt = base64.b64decode(salt_b64)
   ```

3. **PBKDF2 ile Anahtar Türet:**
   ```python
   password = "{password}"
   iterations = {iterations}
   
   kdf = PBKDF2HMAC(
       algorithm=hashes.SHA256(),
       length=32,
       salt=salt,
       iterations=iterations,
   )
   key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
   ```

4. **Fernet ile Şifreyi Çöz:**
   ```python
   f = Fernet(key)
   encrypted_text = "{encrypted}"
   decrypted_text = f.decrypt(encrypted_text.encode()).decode()
   # Sonuç: "{original_example}"
   ```

5. **Tam Python Kodu:**
   ```python
   import base64
   from cryptography.fernet import Fernet
   from cryptography.hazmat.primitives import hashes
   from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
   
   def decrypt_fernet(encrypted_text, password, salt_b64, iterations):
       # Decode salt from base64
       salt = base64.b64decode(salt_b64)
       
       # Create key with PBKDF2
       kdf = PBKDF2HMAC(
           algorithm=hashes.SHA256(),
           length=32,
           salt=salt,
           iterations=iterations,
       )
       key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
       
       # Decrypt with Fernet
       f = Fernet(key)
       decrypted_text = f.decrypt(encrypted_text.encode()).decode()
       
       return decrypted_text
   
   # Decrypt the text
   decrypted_text = decrypt_fernet(
       "{encrypted}",
       "{password}",
       "{salt_b64}",
       {iterations}
   )
   print(decrypted_text)
   ```"""
        
        return encrypted, decrypt_info, detailed_steps
    
    def advanced_encryption(self, text, level):
        # Use RSA encryption
        key_size = 2048 + (level - 60) * 10  # 2048-2448 bits based on level
        
        # Generate keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()
        
        # Encrypt data - RSA can only encrypt small amounts, so hash it first for demo
        text_hash = hashlib.sha256(text.encode()).digest()
        
        # Encrypt the hash
        encrypted_hash = public_key.encrypt(
            text_hash,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # For demonstration, store the original text with a simple encoding too
        simple_encrypted = base64.b64encode(text.encode()).decode()
        
        # Encode the encrypted hash
        encrypted_hash_b64 = base64.b64encode(encrypted_hash).decode()
        
        # Export private key for decryption instructions
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        # Shortened key for display
        short_key = private_pem.split('\n')[1][:20] + "..." + private_pem.split('\n')[-2][-20:]
        
        decrypt_info = (f"Şifrelenmiş Hash (Base64): {encrypted_hash_b64}\n"
                        f"Şifrelenmiş Metin (Base64): {simple_encrypted}\n"
                        f"RSA Özel Anahtar (kısaltılmış): {short_key}\n"
                        f"Anahtar Boyutu: {key_size} bits\n"
                        f"Şifre çözmek için RSA özel anahtarı kullanılmalıdır.")
        
        # Detailed step-by-step guide for the decryption window
        original_example = text[:10] + "..." if len(text) > 10 else text
        detailed_steps = f"""# RSA Asimetrik Şifreleme Çözme Rehberi

## Şifreleme Detayları:
- Şifreleme Seviyesi: {level}
- RSA Anahtar Boyutu: {key_size} bits
- Public Exponent: 65537 (standart)

## Örnek:
- Orijinal metin: "{original_example}"
- SHA-256 hash değeri: "{hashlib.sha256(text.encode()).hexdigest()}"
- RSA ile şifrelenmiş hash (Base64): "{encrypted_hash_b64[:40]}..." (kısaltılmış)
- Basit Base64 şifrelenmiş metin: "{simple_encrypted}"

## Adım Adım Şifre Çözme:

1. **Gerekli Kütüphaneleri İçe Aktar:**
   ```python
   import base64
   from cryptography.hazmat.primitives.asymmetric import padding
   from cryptography.hazmat.primitives import hashes, serialization
   ```

2. **Özel Anahtarı Yükle:**
   ```python
   # Not: Bu, gerçek RSA özel anahtarınızdır (güvenli bir şekilde saklayın)
   private_key_pem = \"\"\"
{private_pem}
   \"\"\"
   
   private_key = serialization.load_pem_private_key(
       private_key_pem.encode(),
       password=None
   )
   ```

3. **Şifrelenmiş Hash'i Çöz:**
   ```python
   encrypted_hash_b64 = "{encrypted_hash_b64}"
   encrypted_hash = base64.b64decode(encrypted_hash_b64)
   
   decrypted_hash = private_key.decrypt(
       encrypted_hash,
       padding.OAEP(
           mgf=padding.MGF1(algorithm=hashes.SHA256()),
           algorithm=hashes.SHA256(),
           label=None
       )
   )
   # Sonuç: Orijinal metnin SHA-256 hash değeri
   ```

4. **Base64 Şifreli Metni Çöz:**
   ```python
   simple_encrypted = "{simple_encrypted}"
   original_text = base64.b64decode(simple_encrypted).decode()
   # Sonuç: "{original_example}"
   ```

5. **Tam Python Kodu:**
   ```python
   import base64
   import hashlib
   from cryptography.hazmat.primitives.asymmetric import padding
   from cryptography.hazmat.primitives import hashes, serialization
   
   def decrypt_rsa(encrypted_hash_b64, simple_encrypted, private_key_pem):
       # Load the private key
       private_key = serialization.load_pem_private_key(
           private_key_pem.encode(),
           password=None
       )
       
       # Decrypt the hash
       encrypted_hash = base64.b64decode(encrypted_hash_b64)
       decrypted_hash = private_key.decrypt(
           encrypted_hash,
           padding.OAEP(
               mgf=padding.MGF1(algorithm=hashes.SHA256()),
               algorithm=hashes.SHA256(),
               label=None
           )
       )
       
       # Decode the base64 encoded text
       original_text = base64.b64decode(simple_encrypted).decode()
       
       # Verify the hash
       calculated_hash = hashlib.sha256(original_text.encode()).digest()
       is_valid = (calculated_hash == decrypted_hash)
       
       return original_text, is_valid
   
   # Private key (keep this secure!)
   private_key_pem = \"\"\"
{private_pem}
   \"\"\"
   
   # Decrypt the text
   result = decrypt_rsa(
       "{encrypted_hash_b64}",
       "{simple_encrypted}",
       private_key_pem
   )
   original_text, is_valid = result
   
   print(f"Çözülmüş metin: {{original_text}}")
   print(f"Hash doğrulama: {{('Başarılı' if is_valid else 'Başarısız')}}")
   ```

**Not:** RSA özel anahtarları çok hassastır. Gerçek dünya uygulamalarında her zaman güvenli bir şekilde saklanmalıdır."""
        
        # Return both for demonstration purposes
        return f"{encrypted_hash_b64}\n{simple_encrypted}", decrypt_info, detailed_steps
    
    def aes_encryption(self, text, level):
        """AES encryption implementation"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        # Generate a random key and IV
        key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)   # 128-bit IV
        
        # Create the cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CFB(iv),
        )
        
        # Encrypt the data
        encryptor = cipher.encryptor()
        padded_data = text.encode()
        # Pad to block size if needed
        block_size = 16
        if len(padded_data) % block_size != 0:
            padding_length = block_size - (len(padded_data) % block_size)
            padded_data += bytes([padding_length]) * padding_length
            
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encode key, iv, and data for storage
        key_b64 = base64.b64encode(key).decode()
        iv_b64 = base64.b64encode(iv).decode()
        encrypted_b64 = base64.b64encode(encrypted_data).decode()
        
        decrypt_info = (f"AES Anahtar (Base64): {key_b64}\n"
                        f"IV (Base64): {iv_b64}\n"
                        f"Şifre Çözme Adımları:\n"
                        f"1. Anahtarı ve IV'yi base64 ile çözün\n"
                        f"2. AES-CFB ile şifreyi çözün\n"
                        f"3. Padding'i kaldırın (varsa)")
        
        detailed_steps = f"""# AES Şifreleme Çözme Rehberi

## Şifreleme Detayları:
- Şifreleme Seviyesi: {level}
- Algoritma: AES-256-CFB
- Anahtar Uzunluğu: 256 bit
- IV Uzunluğu: 128 bit

## Anahtar Bilgileri:
- AES Anahtar (Base64): {key_b64}
- IV (Base64): {iv_b64}

## Adım Adım Şifre Çözme:

1. **Gerekli Kütüphaneleri İçe Aktar:**
   ```python
   import base64
   from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
   ```

2. **Anahtarı ve IV'yi Hazırla:**
   ```python
   key_b64 = "{key_b64}"
   iv_b64 = "{iv_b64}"
   
   key = base64.b64decode(key_b64)
   iv = base64.b64decode(iv_b64)
   ```

3. **Şifreli Veriyi Hazırla:**
   ```python
   encrypted_b64 = "{encrypted_b64}"
   encrypted_data = base64.b64decode(encrypted_b64)
   ```

4. **AES Şifresini Çöz:**
   ```python
   cipher = Cipher(
       algorithms.AES(key),
       modes.CFB(iv)
   )
   
   decryptor = cipher.decryptor()
   decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
   ```

5. **Padding'i Kaldır (Varsa):**
   ```python
   # Eğer padding kullanıldıysa
   if decrypted_data[-1] < 16:
       padding_length = decrypted_data[-1]
       if all(x == padding_length for x in decrypted_data[-padding_length:]):
           decrypted_data = decrypted_data[:-padding_length]
   
   plaintext = decrypted_data.decode()
   print(plaintext)
   ```

6. **Tam Python Kodu:**
   ```python
   import base64
   from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
   
   def decrypt_aes(encrypted_b64, key_b64, iv_b64):
       # Decode base64 strings
       encrypted_data = base64.b64decode(encrypted_b64)
       key = base64.b64decode(key_b64)
       iv = base64.b64decode(iv_b64)
       
       # Create AES cipher
       cipher = Cipher(
           algorithms.AES(key),
           modes.CFB(iv)
       )
       
       # Decrypt the data
       decryptor = cipher.decryptor()
       decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
       
       # Remove padding if present
       if decrypted_data[-1] < 16:
           padding_length = decrypted_data[-1]
           if all(x == padding_length for x in decrypted_data[-padding_length:]):
               decrypted_data = decrypted_data[:-padding_length]
       
       return decrypted_data.decode()
   
   # Decrypt the message
   plaintext = decrypt_aes(
       "{encrypted_b64}",
       "{key_b64}",
       "{iv_b64}"
   )
   print(plaintext)
   ```"""
        
        return encrypted_b64, decrypt_info, detailed_steps
        
    def blowfish_encryption(self, text, level):
        """Blowfish encryption implementation"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        # Generate key (variable length, up to 448 bits)
        key_length = min(56, 8 + int(level / 3))  # 8-56 bytes (64-448 bits)
        key = os.urandom(key_length)
        iv = os.urandom(8)  # 8 bytes for Blowfish
        
        # Create the cipher
        cipher = Cipher(
            algorithms.Blowfish(key),
            modes.CBC(iv)
        )
        
        # Encrypt the data (with padding)
        encryptor = cipher.encryptor()
        data = text.encode()
        
        # Add PKCS7 padding
        block_size = 8  # Blowfish block size
        padding_length = block_size - (len(data) % block_size)
        padded_data = data + bytes([padding_length]) * padding_length
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encode for storage
        key_b64 = base64.b64encode(key).decode()
        iv_b64 = base64.b64encode(iv).decode()
        encrypted_b64 = base64.b64encode(encrypted_data).decode()
        
        decrypt_info = (f"Blowfish Anahtar (Base64): {key_b64}\n"
                        f"IV (Base64): {iv_b64}\n"
                        f"Anahtar Uzunluğu: {key_length * 8} bit\n"
                        f"Şifre Çözme Adımları:\n"
                        f"1. Anahtarı ve IV'yi base64 ile çözün\n"
                        f"2. Blowfish-CBC modu ile şifreyi çözün\n"
                        f"3. PKCS7 padding'i kaldırın")
        
        detailed_steps = f"""# Blowfish Şifreleme Çözme Rehberi

## Şifreleme Detayları:
- Şifreleme Seviyesi: {level}
- Algoritma: Blowfish-CBC
- Anahtar Uzunluğu: {key_length * 8} bit ({key_length} byte)
- IV Uzunluğu: 64 bit (8 byte)

## Anahtar Bilgileri:
- Blowfish Anahtar (Base64): {key_b64}
- IV (Base64): {iv_b64}

## Adım Adım Şifre Çözme:

1. **Gerekli Kütüphaneleri İçe Aktar:**
   ```python
   import base64
   from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
   ```

2. **Anahtarı ve IV'yi Hazırla:**
   ```python
   key_b64 = "{key_b64}"
   iv_b64 = "{iv_b64}"
   
   key = base64.b64decode(key_b64)
   iv = base64.b64decode(iv_b64)
   ```

3. **Şifreli Veriyi Hazırla:**
   ```python
   encrypted_b64 = "{encrypted_b64}"
   encrypted_data = base64.b64decode(encrypted_b64)
   ```

4. **Blowfish Şifresini Çöz:**
   ```python
   cipher = Cipher(
       algorithms.Blowfish(key),
       modes.CBC(iv)
   )
   
   decryptor = cipher.decryptor()
   decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
   ```

5. **PKCS7 Padding'i Kaldır:**
   ```python
   padding_length = decrypted_padded[-1]
   decrypted_data = decrypted_padded[:-padding_length]
   plaintext = decrypted_data.decode()
   print(plaintext)
   ```

6. **Tam Python Kodu:**
   ```python
   import base64
   from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
   
   def decrypt_blowfish(encrypted_b64, key_b64, iv_b64):
       # Decode base64 strings
       encrypted_data = base64.b64decode(encrypted_b64)
       key = base64.b64decode(key_b64)
       iv = base64.b64decode(iv_b64)
       
       # Create Blowfish cipher
       cipher = Cipher(
           algorithms.Blowfish(key),
           modes.CBC(iv)
       )
       
       # Decrypt the data
       decryptor = cipher.decryptor()
       decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
       
       # Remove PKCS7 padding
       padding_length = decrypted_padded[-1]
       decrypted_data = decrypted_padded[:-padding_length]
       
       return decrypted_data.decode()
   
   # Decrypt the message
   plaintext = decrypt_blowfish(
       "{encrypted_b64}",
       "{key_b64}",
       "{iv_b64}"
   )
   print(plaintext)
   ```"""
        
        return encrypted_b64, decrypt_info, detailed_steps
    
    def show_decrypt_guide(self):
        if not self.current_encryption["encrypted"]:
            return
        
        # Create a new window for the decryption guide
        guide_window = Toplevel(self.root)
        guide_window.title("Şifre Çözme Adımları")
        guide_window.geometry("800x600")
        guide_window.configure(background=ModernUI.DARK_BG)
        
        # Create frame for the content
        guide_frame = ttk.Frame(guide_window, padding=20)
        guide_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add title
        title_label = ttk.Label(guide_frame, 
                             text=f"{self.current_encryption['method']} - Şifre Çözme Rehberi", 
                             font=("Segoe UI", 14, "bold"))
        title_label.pack(pady=(0, 15))
        
        # Create scrollable text area with modern styling
        guide_text = scrolledtext.ScrolledText(
            guide_frame, 
            wrap=tk.WORD, 
            font=("Consolas", 11),
            bg=ModernUI.DARKER_BG,
            fg=ModernUI.TEXT,
            insertbackground=ModernUI.TEXT,
            selectbackground=ModernUI.ACCENT
        )
        guide_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a tag for headings
        guide_text.tag_configure("heading", font=("Segoe UI", 12, "bold"), foreground=ModernUI.ACCENT)
        guide_text.tag_configure("subheading", font=("Segoe UI", 11, "bold"), foreground=ModernUI.WARNING)
        guide_text.tag_configure("code", background="#1f1f1f", relief="solid", borderwidth=1)
        
        # Parse and format the detailed steps with syntax highlighting
        detailed_steps = self.current_encryption["detailed_steps"]
        
        # Add the detailed steps to the text area with formatting
        guide_text.insert(tk.END, self.format_guide_content(detailed_steps))
        
        # Add a close button at the bottom
        button_frame = ttk.Frame(guide_frame)
        button_frame.pack(pady=(10, 0))
        
        close_button = tk.Button(
            button_frame,
            text="Kapat",
            command=guide_window.destroy,
            bg=ModernUI.BUTTON_BG,
            fg=ModernUI.TEXT,
            activebackground=ModernUI.BUTTON_ACTIVE,
            activeforeground=ModernUI.TEXT,
            relief="raised",
            borderwidth=1,
            padx=20,
            pady=5,
            font=("Segoe UI", 9, "bold")
        )
        close_button.pack()
    
    def format_guide_content(self, content):
        """Format the guide content with simple markdown-like styling"""
        # This is a simple implementation
        # For a full markdown parser, you'd need more sophisticated processing
        return content

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop() 