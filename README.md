# Fast Secure Steganography Tool

![Python](https://img.shields.io/badge/Python-3.8+-blue )
![License](https://img.shields.io/badge/License-MIT-green )

A Python tool to securely hide text in images using **strong AES encryption** and randomized pixel positions. Optimized for large images with a simple **Tkinter GUI**.

---

## Update History

### Latest Version (Stego.py)

**Date:** January 10, 2026

**What's New:**

* **Security Enhancement:** Replaced `random` library with `secrets` module and custom deterministic RNG using SHA-256 hashing
* Added support for **AES-256-GCM** encryption (more secure & modern)
* Enhanced GUI for better usability and clarity
* Improved overall stability and user experience

**Technical Details of Today's Update:**
- **Removed dependency on `random` module** - now uses cryptographically secure deterministic RNG
- **Added `DeterministicRNG` class** that uses repeated SHA-256 hashing for position generation
- **Maintains backward compatibility** - same keys will produce same results
- **More secure than standard `random.Random`** while preserving deterministic behavior required for decoding

### Older Version (OldStego.py)

* Used basic **AES (Fernet)** encryption
* Simpler GUI
* Core LSB steganography functionality

---

## Features

* **Enhanced Security:** Cryptographically secure deterministic RNG using SHA-256
* Encrypt text using **AES-256-GCM** (latest version)
* Hide encrypted data in randomized pixel positions
* Supports PNG and BMP images
* Memory-efficient for large images
* Non-blocking GUI using threading
* Simple and user-friendly Tkinter interface

---

## Installation

Requires Python 3.8+ and the following libraries:

```bash
pip install pillow cryptography pyperclip
```

Clone the repository:

```bash
git clone https://github.com/JulianApollo/secure-lsb-stego.git 
cd secure-lsb-stego
```

---

## Usage

### New Version (Recommended)

```bash
python3 Stego.py
```

### Older Version (Legacy)

```bash
python3 OldStego.py
```

**Steps:**

1. Generate or paste a key (save it securely).
2. Enter the text you want to hide.
3. Click **Encode**, select a cover image, and save the stego image.
4. To decode, click **Decode**, select the image, and enter the key.

---

## How It Works

1. Text is encrypted using **AES-256-GCM** (or Fernet in older version).
2. Encrypted data is converted to bits.
3. A cryptographically secure random sequence of pixel positions is generated from the key using SHA-256 hashing.
4. Bits are embedded in the least significant bits of RGB channels.
5. To decode, the same key regenerates the pixel positions to read and decrypt the message.

```mermaid
graph LR
    A[Text] --> B[Encrypt with AES]
    B --> C[Convert to bits]
    C --> D[Secure random pixel positions]
    D --> E[Embed in RGB LSBs]
    E --> F[Stego Image]
    F --> G[Decode with same key]
```

---

## Security Features

* **Deterministic RNG:** Uses SHA-256 hashing instead of Python's `random` module for better security
* **Hardware RNG Support:** Automatically detects and uses available hardware random number generators
* **Graceful Fallback:** Falls back to software entropy if hardware RNG fails
* **Cross-platform:** Same API works on all platforms
* **No Version Signatures:** Encoded data contains no version markers for stealth

---

## Notes

* Only text messages are supported.
* Large messages require larger images.
* Clipboard features require `xclip` on Linux.
* This project is experimental and intended for learning/testing purposes.

---

You can find the license in the **LICENSE** file.
