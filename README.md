# 🔒 6locker - Advanced Encryption Tool

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License MIT"/>
  <img src="https://img.shields.io/badge/Version-1.0.0-orange.svg" alt="Version 1.0.0"/>
</div>

<p align="center">
  <img src="https://raw.githubusercontent.com/duckmeinheaven/6locker/main/assets/logo.png" alt="6locker Logo" width="200"/>
</p>

## 🌟 Features

- 🔐 **Multiple encryption algorithms**:
  - Caesar Cipher with Base64 encoding
  - AES-256 encryption
  - Fernet encryption (PBKDF2)
  - Blowfish encryption
  - RSA asymmetric encryption
- 🎚️ **Adjustable security level** (1-100)
- 🎨 **Modern dark mode UI**
- 🔄 **Automatic or manual algorithm selection**
- 📝 **Detailed decryption instructions**
- 📱 **Cross-platform** (Windows, macOS, Linux)

## 📷 Screenshot

<p align="center">
  <img src="https://raw.githubusercontent.com/duckmeinheaven/6locker/main/assets/screenshot.png" alt="6locker Screenshot" width="600"/>
</p>

## 🚀 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/duckmeinheaven/6locker.git
   cd 6locker
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

Run the application:
```bash
python 6locker.py
```

### Encryption Process:

1. Enter the text you want to encrypt in the input field
2. Select the encryption level (1-100)
3. Choose an encryption method:
   - Use "Automatic Encryption" for level-based algorithm selection
   - Or uncheck "Automatic Method Selection" to manually choose an algorithm
4. View the encryption result and decryption instructions in the output area
5. Click "Decryption Guide" for detailed step-by-step instructions

## 🔍 Encryption Methods

| Method | Security Level | Description |
|--------|---------------|-------------|
| Caesar Cipher | Low (1-29) | Simple character shift with Base64 encoding |
| AES | Medium (30-59) | Advanced Encryption Standard with 256-bit key |
| Fernet | Medium (30-59) | PBKDF2-based encryption with secure key derivation |
| Blowfish | Medium (30-59) | Classic symmetric block cipher |
| RSA | High (60-100) | Asymmetric encryption with 2048+ bit keys |

## 🔧 Requirements

- Python 3.8+
- cryptography library
- tkinter (included in most Python installations)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/duckmeinheaven/6locker/issues).

