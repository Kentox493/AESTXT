# AESTXT: AES Encryption & Decryption Tool

**AESTXT** is a Python tool for performing AES encryption and decryption, supporting multiple modes of operation, including **ECB**, **CBC**, **CTR**, and **GCM**. This tool allows users to securely encrypt and decrypt data using the AES algorithm with a customizable set of parameters.

## Features

- **AES Modes**:
  - **ECB (Electronic Codebook)**: Simple mode, not recommended for encrypting large data due to security weaknesses.
  - **CBC (Cipher Block Chaining)**: Adds randomness to encryption with an Initialization Vector (IV) to prevent repeating patterns in ciphertext.
  - **CTR (Counter)**: Transforms AES into a stream cipher, allowing the encryption of data of arbitrary length.
  - **GCM (Galois/Counter Mode)**: Provides both encryption and integrity (authentication), commonly used for secure communications.

- **Key Length**: Supports key lengths of 16, 24, or 32 bytes for all modes.
- **IV Input**: Required for **CBC**, **CTR**, and **GCM** modes (16 bytes long).
- **Tag Length for GCM Mode**: Selectable tag lengths of 96, 104, 112, 120, or 128 bits for GCM encryption.
  
## Installation

To run the application, you'll need Python 3.6+ and the following dependencies:

1. Clone the repository:

    ```bash
    git clone https://github.com/yourusername/AESTXT.git
    cd AESTXT
    ```

2. Set up a virtual environment (optional):

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

4. Run the application:

    ```bash
    python aes.py
    ```

## Usage

1. **Input Key**: Enter a 16, 24, or 32-byte key, depending on the AES mode you're using.
2. **Text or File Input**: Enter text directly or load a `.txt` file for encryption or decryption.
3. **Choose AES Mode**: Select the AES mode (ECB, CBC, CTR, or GCM).
4. **Input IV** (for CBC, CTR, and GCM): Provide a 16-byte Initialization Vector (IV).
5. **Tag Length** (for GCM): Choose a tag length between 96,104,112,120 and 128 bits for GCM encryption.
6. **Encrypt or Decrypt**: Click the "Encrypt" or "Decrypt" button to perform the operation.
7. **Result**: The result will be displayed, and you can copy the encrypted or decrypted data.


