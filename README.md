## Overview
This Go-based text processing tool offers various text transformations including:
- Reverse
- ROT13
- Caesar Cipher
- Atbash Cipher
- Vigenere Cipher
- Base64 Encoding/Decoding
- URL Encoding/Decoding
- Hex Encoding/Decoding
- XOR Cipher

The tool can be configured using flags or a YAML configuration file, enabling batch processing and customization.

---

## Functionalities

### 1. **Reverse**
Reverses the input string.
- **Command**: `--no-reverse`
- **Example**:
  - Input: `hello`
  - Output: `olleh`

### 2. **ROT13**
Applies the ROT13 substitution cipher.
- **Command**: `--rot13`
- **Example**:
  - Input: `hello`
  - Output: `uryyb`

### 3. **Caesar Cipher**
Applies a Caesar cipher with a specified shift.
- **Command**: `--caesar <shift>`
- **Example**:
  - Input: `hello`, Shift: `3`
  - Output: `khoor`

### 4. **Atbash Cipher**
Applies the Atbash cipher where `a -> z`, `b -> y`, etc.
- **Command**: `--atbash`
- **Example**:
  - Input: `hello`
  - Output: `svool`

### 5. **Vigenere Cipher**
Encrypts using the Vigenere cipher with a provided key.
- **Command**: `--vigenere-key <key>`
- **Example**:
  - Input: `hello`, Key: `key`
  - Output: `riijq`

### 6. **Base64 Encoding**
Encodes the input string in Base64 format.
- **Command**: `--base64-encode`
- **Example**:
  - Input: `hello`
  - Output: `aGVsbG8=`

### 7. **Base64 Decoding**
Decodes a Base64-encoded string.
- **Command**: `--base64-decode`
- **Example**:
  - Input: `aGVsbG8=`
  - Output: `hello`

### 8. **URL Encoding**
Encodes the input string into a URL-safe format.
- **Command**: `--url-encode`
- **Example**:
  - Input: `hello world`
  - Output: `hello%20world`

### 9. **URL Decoding**
Decodes a URL-encoded string.
- **Command**: `--url-decode`
- **Example**:
  - Input: `hello%20world`
  - Output: `hello world`

### 10. **Hex Encoding**
Encodes the input string in hexadecimal format.
- **Command**: `--hex-encode`
- **Example**:
  - Input: `hello`
  - Output: `68656c6c6f`

### 11. **Hex Decoding**
Decodes a hexadecimal string.
- **Command**: `--hex-decode`
- **Example**:
  - Input: `68656c6c6f`
  - Output: `hello`

### 12. **XOR Cipher**
Encrypts/decrypts the input string using XOR with a specified key.
- **Command**: `--xor-key <key>`
- **Example**:
  - Input: `hello`, Key: `key`
  - Output: (varies based on key)

---

## Usage

### CLI Example:
```sh
./TT.go --rot13 "example text"
```

### YAML Configuration Example:
```yaml
input_file: input.txt
output_file: output.txt
caesar_shift: 5
log_level: debug
```

### Executing With YAML:
```sh
./TT.go --config config.yaml
```

---

## Notes
- Ensure the input text is valid for the transformations applied.
- For advanced use, combine multiple transformations (e.g., `--caesar 3 --base64-encode`).
- This tool is not intended for secure encryption but for educational and obfuscation purposes.

