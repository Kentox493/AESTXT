# 🔒 **AESTXT: AES Encryption & Decryption Tool**

**AESTXT** is a Python tool for AES encryption and decryption, supporting multiple modes of operation, including **ECB**, **CBC**, **CTR**, and **GCM**. With customizable parameters, it allows users to securely encrypt and decrypt data using the AES algorithm.

---

## 🚀 **Features**

- **🔐 AES Modes**:
  - **📂 ECB (Electronic Codebook)**: Simple mode, not recommended for large data due to security weaknesses.
  - **🔗 CBC (Cipher Block Chaining)**: Adds randomness with an Initialization Vector (IV) to prevent repeating patterns in ciphertext.
  - **🔢 CTR (Counter)**: Transforms AES into a stream cipher, allowing encryption of arbitrary-length data.
  - **🌐 GCM (Galois/Counter Mode)**: Provides both encryption and integrity (authentication), commonly used for secure communications.

- **🔑 Key Length**: Supports key lengths of **16**, **24**, or **32** bytes for all modes.
- **🔐 IV Input**: Required for **CBC**, **CTR**, and **GCM** modes (16 bytes long).
- **📏 Tag Length (GCM Mode)**: Selectable tag lengths of **96**, **104**, **112**, **120**, or **128** bits for GCM encryption.

---

## 🛠️ **Installation**

To run the application, you'll need **Python 3.6+** and the following dependencies:

### 1. Clone the repository:

```bash
git clone https://github.com/yourusername/AESTXT.git
cd AESTXT
```
### 2. Set up a virtual environment (optional):

To avoid conflicts with your global Python environment, it is recommended to use a virtual environment. Here's how to set it up:

```bash
python -m venv venv
source venv/bin/activate
```
### 3. Install Dependencies:

```bash
pip install -r requirements.txt
```

### 4. Run The Application:

```bash
python aes.py
```
## 💡 **Usage**

1. **🔑 Input Key**:  
   Enter a **16**, **24**, or **32-byte** key, depending on the AES mode you're using.

2. **📄 Text or File Input**:  
   Enter text directly or load a `.txt` file for encryption or decryption.

3. **⚙️ Choose AES Mode**:  
   Select the AES mode:  
   - **ECB** (Electronic Codebook)  
   - **CBC** (Cipher Block Chaining)  
   - **CTR** (Counter)  
   - **GCM** (Galois/Counter Mode)

4. **🔑 Input IV** (for CBC, CTR, and GCM):  
   Provide a **16-byte Initialization Vector (IV)**. This is required for **CBC**, **CTR**, and **GCM** modes.

5. **🖋️ Tag Length** (for GCM):  
   If you're using **GCM mode**, choose a **tag length** from the following options:  
   - **96 bits**  
   - **104 bits**  
   - **112 bits**  
   - **120 bits**  
   - **128 bits**

6. **🔒 Encrypt or Decrypt**:  
   Once everything is set, click the **"Encrypt"** or **"Decrypt"** button to perform the operation.

7. **📋 Result**:  
   The encrypted or decrypted result will be displayed. You can **copy** the data for further use.

---


