# Assignment 2 - Web-Based Text Encryption Tool

This assignment contains a single-page web application built in plain HTML, CSS, and JavaScript.

## What has been implemented

- Plain text input area for users to enter text.
- Dropdown menu to select an encryption algorithm.
- Encrypt button to run encryption.
- Cipher text output area to display encrypted result.
- Basic validation:
  - Prevents empty plain text input.
  - Prevents encryption without selecting a method.
  - Requires AES key when AES is selected.

## Encryption algorithms included

1. Caesar Cipher (with configurable shift value)
2. AES encryption (using CryptoJS)
3. Base64 encoding

## Files in Assignment2

- `index.html`: Complete web app (UI, styling, and encryption logic)
- `README.md`: This documentation

## How to run

1. Open `index.html` in any modern browser.
2. Enter plain text.
3. Select an algorithm.
4. If AES is selected, enter a secret key.
5. Click **Encrypt** to see the ciphertext.
