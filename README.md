# 🔒 Stego Tool v1 – Hide Stuff in Pics (Chill AF Edition)

![Python](https://img.shields.io/badge/Python-3.8+-blue)

yo yo yo, welcome to my little corner of the internet where i just mess around with **hiding text in images**. yeah, sounds kinda nerdy, but hear me out: sometimes you just wanna send a secret message to your future self or a friend without them realizing it’s even there. that’s where this project comes in. i call it “stego tool” because “steganography” is a long word and nobody’s got time for that.  

> ⚠️ heads up: this is totally experimental. i made this for fun/testing and learning. do not trust it with your top-secret, government-level stuff. like, if someone really wants your lunch menu or what you had for breakfast, fine. but don’t use it to hide nuclear codes.

---

## ✨ What it even does

alright, lemme break it down for you in chill terms:

- takes **any text** you give it (your deep thoughts, memes, random ASCII art, whatever)  
- encrypts it using **AES/Fernet** – fancy math stuff that basically turns your text into gobbledygook unless you have the key  
- turns that encrypted gobbledygook into **bits** (0s and 1s – like a computer language only computers speak)  
- picks **random pixel positions** in your image to hide each bit – nobody’s going to find your secrets just scanning sequentially  
- messes with the **least significant bit** in the RGB channels of the pixels – basically tiny changes nobody notices unless they stare at it with a microscope  
- saves a **new PNG image** with your hidden text inside – your original pic is safe, and your secret is tucked away  
- if you wanna read it back, the tool regenerates the same random positions using your key, grabs the bits, decrypts them, and voila – your text is back  

it’s super memory-efficient too. like, i tested it with huge images and it didn’t crash my computer (which is a win because i hate waiting 10 minutes for a program to finish).

---

## 🛠️ Setup / Chill Installation

first things first, you need **Python 3.8+** and a couple libraries. if you don’t have them, run this in your terminal:  

```bash
pip install pillow cryptography
