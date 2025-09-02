# Advanced Encryption Tool
### Overview

The Advanced Encryption Tool provides a simple and secure way to encrypt and decrypt files using modern cryptographic techniques.

It includes both a Graphical User Interface (GUI) for ease of use and a Command Line Interface (CLI) for flexibility.

### Features

- AES-256 encryption for strong data protection

- Scrypt-based key derivation for secure password handling

- Password-protected file encryption & decryption

- Graphical User Interface (GUI) for user-friendly interaction

- Error handling for wrong passwords or invalid files

### Requirements

#### Make sure you have the following installed:

 Python 3.8+

#### Required libraries:

 pip install cryptography tkinter

### File Structure
advanced_encryption_tool/

│── encryption_tool.py     # Main encryption & decryption logic

│── gui.py                 # Graphical User Interface

│── README.md              # Project documentation

### Usage
#### Run the GUI (recommended):
python gui.py


### Select Encrypt or Decrypt

1) Choose the file you want to process

2) Enter your password

3) Save the encrypted/decrypted file

4) Run via CLI (optional):

Encrypt a file:

python encryption_tool.py encrypt myfile.txt


Decrypt a file:

python encryption_tool.py decrypt myfile.txt.enc

### Example

#### Encrypt a file:

Input file: secret.txt

Password: mypassword123

Output file: secret.txt.enc

#### Decrypt the same file:

Input file: secret.txt.enc

Password: mypassword123

Output file: secret.txt

### Author

Developed by Gauri Salvi
