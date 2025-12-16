# 🔐 Cryptography Algorithms
<div align="center">
  <img width="340" height="327" alt="Screenshot 2025-12-16 085307" src="https://github.com/user-attachments/assets/0096cc48-b3ac-489f-9d1f-3616d4edf375" />
</div>

A GUI application built with Tkinter that implements five classical encryption algorithms for educational and experimentation purposes. Users select an algorithm, input plaintext/ciphertext and keys, then encrypt or decrypt with validation for correct inputs.

## ✨ Features
- **Baconian Cipher** - 5-bit A/B encoding for letters only
- **One-Time Pad** - Perfect secrecy with matching key length
- **Caesar Cipher** - ASCII shift (mod 256) with numeric key
- **Columnar Transposition** - Key-sorted column reordering + padding
- **Rail Fence Cipher** - Zigzag rail pattern (spaces → `_`)
- Interactive dropdown selection, real-time error popups, clear/reset functionality

## 🛠 Tech Stack
| Component | Details |
|-----------|---------|
| **Language** | Python |
| **GUI** | `tkinter` + `ttk` (styled widgets) |
| **Dependencies** | None (standalone) |

## 🔒 Algorithm Details
| Cipher | Encrypts To | Key Req. | Notes |
|--------|-------------|----------|-------|
| Baconian | A/B strings | No | 26 letters → 5-bit codes |
| OTP | Byte-shifted | Yes (len match) | Unbreakable if key random/single-use |
| Caesar | Shifted ASCII | Yes (#) | Full 256 range |
| Columnar | Rearranged cols | Yes (str) | Pads with `_` |
| Rail Fence | Rail zigzag | Yes (# rails) | Spaces → `_` [1] |

## ⚠️ Limitations
- No file I/O, batch processing, or modern ciphers
- Caesar/OTP: Full bytes (not letter-only)
- Baconian: No spaces/special chars
