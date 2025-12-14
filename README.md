# 🔒 Stego Tool v1 – Hide Stuff in Pics (kinda experimental)

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

yo, so this is a lil Python thing i made to **hide text in images**.  
it uses AES encryption + random spots in the pic so no one can peek unless they got the key.  

> ⚠️ heads up: this is just for fun/testing. don’t trust it with ur super secret stuff lol.

---

## ✨ Features

- encrypts ur text with **AES/Fernet** (fancy math, basically safe-ish)
- hides data in **random pixel spots** so it’s kinda sneaky
- won’t crash ur PC on big images (i tried)
- simple **GUI with Tkinter** (click buttons, boom)
- works with **PNG/BMP** (no JPEG pls)
- makes a **44-char key** – save it or u’re screwed

---

## ⚙️ Setup

u need **Python 3.8+** and a few libs:

```bash
pip install pillow cryptography
