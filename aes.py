import sys
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QComboBox, QTabWidget, QTextEdit, QFileDialog
from PyQt6.QtCore import Qt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter  
import qdarkstyle

class AESApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AESTXT: AES Encryption & Decryption Tool")
        self.setGeometry(300, 100, 800, 700)

        # theme
        self.setStyleSheet("""
            QWidget {
                background-color: #1A1A1D;
                color: #1A99FF;
                font-family: "Arial";
            }
            QLabel {
                color: #1A99FF;
                font-size: 24px;
                font-weight: bold;
            }
            QPushButton {
                background-color: #00264d;
                border: 1px solid #1A99FF;
                color: #1A99FF;
                padding: 10px;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #003366;
            }
            QTabWidget::pane {
                border: 2px solid #1A99FF;
                background-color: #1A1A1D;
            }
            QTabBar::tab {
                background-color: #00264d;
                border: 1px solid #1A99FF;
                padding: 5px;
                font-size: 14px;
            }
            QTabBar::tab:selected {
                background-color: #003366;
            }
            QLineEdit, QTextEdit {
                background-color: #003366;
                border: 1px solid #1A99FF;
                color: #fff;
                padding: 10px;
                font-size: 16px;
            }
            QTextEdit {
                height: 100px;
                width: 100%;
            }
            QLabel.watermark {
                color: #ff3333;
                font-size: 12px;
                font-style: italic;
                text-align: center;
            }
        """)

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Header
        header_layout = QVBoxLayout()
        header_label = QLabel("AESTXT: AES Encryption & Decryption Tool", self)
        header_label.setStyleSheet("font-size: 32px; font-weight: bold; color: #1A99FF;")
        header_layout.addWidget(header_label)
        header_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Add space between header and content
        header_layout.addSpacing(20)

        layout.addLayout(header_layout)

        # Create tab widget for AES modes
        self.tabs = QTabWidget(self)
        self.tabs.addTab(self.create_ecb_tab(), "ECB")
        self.tabs.addTab(self.create_cbc_tab(), "CBC")
        self.tabs.addTab(self.create_ctr_tab(), "CTR")
        self.tabs.addTab(self.create_gcm_tab(), "GCM")
        
        layout.addWidget(self.tabs)
        
        # Add Buttons for File Input and Encryption/Decryption
        button_layout = QHBoxLayout()

        self.load_button = QPushButton("Load Text from File", self)
        self.encrypt_button = QPushButton("Encrypt", self)
        self.decrypt_button = QPushButton("Decrypt", self)
        
        self.load_button.clicked.connect(self.load_text_from_file)
        self.encrypt_button.clicked.connect(self.encrypt)
        self.decrypt_button.clicked.connect(self.decrypt)
        
        button_layout.addWidget(self.load_button)
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        
        layout.addLayout(button_layout)

        # Result Text Area 
        self.result_text = QTextEdit(self)
        self.result_text.setReadOnly(True)
        layout.addWidget(QLabel("Result:"))
        layout.addWidget(self.result_text)

        # Watermark label
        watermark_label = QLabel("Program created by Kentox493", self)
        watermark_label.setStyleSheet("color: #1A99FF; font-size: 12px; font-style: italic;")
        layout.addWidget(watermark_label)
        layout.setAlignment(watermark_label, Qt.AlignmentFlag.AlignCenter)

        self.setLayout(layout)

    def create_ecb_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.key_input = QLineEdit(self)
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(QLabel("Key (16, 24, or 32 bytes):"))
        layout.addWidget(self.key_input)

        self.text_input = QLineEdit(self)
        layout.addWidget(QLabel("Text to Encrypt/Decrypt:"))
        layout.addWidget(self.text_input)
        
        tab.setLayout(layout)
        return tab

    def create_cbc_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.key_input_cbc = QLineEdit(self)
        self.key_input_cbc.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(QLabel("Key (16, 24, or 32 bytes):"))
        layout.addWidget(self.key_input_cbc)

        self.iv_input_cbc = QLineEdit(self)
        layout.addWidget(QLabel("Initialization Vector (IV) (16 bytes):"))
        layout.addWidget(self.iv_input_cbc)

        self.text_input_cbc = QLineEdit(self)
        layout.addWidget(QLabel("Text to Encrypt/Decrypt:"))
        layout.addWidget(self.text_input_cbc)

        tab.setLayout(layout)
        return tab

    def create_ctr_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.key_input_ctr = QLineEdit(self)
        self.key_input_ctr.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(QLabel("Key (16, 24, or 32 bytes):"))
        layout.addWidget(self.key_input_ctr)

        self.iv_input_ctr = QLineEdit(self)
        layout.addWidget(QLabel("Initialization Vector (IV) (16 bytes):"))
        layout.addWidget(self.iv_input_ctr)

        self.text_input_ctr = QLineEdit(self)
        layout.addWidget(QLabel("Text to Encrypt/Decrypt:"))
        layout.addWidget(self.text_input_ctr)

        tab.setLayout(layout)
        return tab

    def create_gcm_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.key_input_gcm = QLineEdit(self)
        self.key_input_gcm.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(QLabel("Key (16, 24, or 32 bytes):"))
        layout.addWidget(self.key_input_gcm)

        self.iv_input_gcm = QLineEdit(self)
        layout.addWidget(QLabel("Initialization Vector (IV) (16 bytes):"))
        layout.addWidget(self.iv_input_gcm)

        self.tag_len_input_gcm = QComboBox(self)
        self.tag_len_input_gcm.addItems(['96', '104', '112', '120', '128'])  
        layout.addWidget(QLabel("Tag Length (in bits):"))
        layout.addWidget(self.tag_len_input_gcm)

        self.text_input_gcm = QLineEdit(self)
        layout.addWidget(QLabel("Text to Encrypt/Decrypt:"))
        layout.addWidget(self.text_input_gcm)

        tab.setLayout(layout)
        return tab

    def load_text_from_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "Open Text File", "", "Text Files (*.txt)")
        if file:
            with open(file, "r") as f:
                text = f.read()
                mode = self.tabs.currentIndex()
                if mode == 0:  # ECB Mode
                    self.text_input.setText(text)
                elif mode == 1:  # CBC Mode
                    self.text_input_cbc.setText(text)
                elif mode == 2:  # CTR Mode
                    self.text_input_ctr.setText(text)
                elif mode == 3:  # GCM Mode
                    self.text_input_gcm.setText(text)

    def encrypt(self):
        mode = self.tabs.currentIndex()
        text = self.get_text_input(mode)
        key = self.get_key_input(mode)
        iv = self.get_iv_input(mode)
        tag_len = self.get_tag_len_input(mode)
        
        if len(key) not in [16, 24, 32]:
            self.result_text.setText("Key must be 16, 24, or 32 bytes long!")
            return
        
        key = key.encode()
        cipher = None
        encrypted = None

        try:
            if mode == 0:  # ECB Mode
                cipher = AES.new(key, AES.MODE_ECB)
                encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
            elif mode == 1:  # CBC Mode
                iv = iv.encode()
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
            elif mode == 2:  # CTR Mode
                iv = iv.encode()
                counter = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))  
                cipher = AES.new(key, AES.MODE_CTR, counter=counter)
                encrypted = cipher.encrypt(text.encode())
            elif mode == 3:  # GCM Mode
                iv = iv.encode()
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=tag_len // 8)
                encrypted, tag = cipher.encrypt_and_digest(text.encode())
                encrypted = encrypted + tag  

            self.result_text.setText(encrypted.hex())
        except Exception as e:
            self.result_text.setText(f"Encryption failed: {str(e)}")

    def decrypt(self):
        mode = self.tabs.currentIndex()
        text = self.get_text_input(mode)
        key = self.get_key_input(mode)
        iv = self.get_iv_input(mode)
        tag_len = self.get_tag_len_input(mode)
        
        if len(key) not in [16, 24, 32]:
            self.result_text.setText("Key must be 16, 24, or 32 bytes long!")
            return
        
        key = key.encode()
        cipher = None
        decrypted = None

        try:
            if mode == 0:  # ECB Mode
                cipher = AES.new(key, AES.MODE_ECB)
                decrypted = unpad(cipher.decrypt(bytes.fromhex(text)), AES.block_size).decode()
            elif mode == 1:  # CBC Mode
                iv = iv.encode()
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(bytes.fromhex(text)), AES.block_size).decode()
            elif mode == 2:  # CTR Mode
                iv = iv.encode()
                counter = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))  
                cipher = AES.new(key, AES.MODE_CTR, counter=counter)
                decrypted = cipher.decrypt(bytes.fromhex(text)).decode()
            elif mode == 3:  # GCM Mode
                iv = iv.encode()
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=tag_len // 8)
                ciphertext = bytes.fromhex(text)[:-tag_len // 8]  
                tag = bytes.fromhex(text)[-tag_len // 8:]
                decrypted = cipher.decrypt_and_verify(ciphertext, tag).decode()

            self.result_text.setText(decrypted)
        except Exception as e:
            self.result_text.setText(f"Decryption failed: {str(e)}")

    def get_text_input(self, mode):
        if mode == 0:
            return self.text_input.text()
        elif mode == 1:
            return self.text_input_cbc.text()
        elif mode == 2:
            return self.text_input_ctr.text()
        elif mode == 3:
            return self.text_input_gcm.text()

    def get_key_input(self, mode):
        if mode == 0:
            return self.key_input.text()
        elif mode == 1:
            return self.key_input_cbc.text()
        elif mode == 2:
            return self.key_input_ctr.text()
        elif mode == 3:
            return self.key_input_gcm.text()

    def get_iv_input(self, mode):
        if mode == 1:
            return self.iv_input_cbc.text()
        elif mode == 2:
            return self.iv_input_ctr.text()
        elif mode == 3:
            return self.iv_input_gcm.text()
        return ""

    def get_tag_len_input(self, mode):
        if mode == 3:
            try:
                return int(self.tag_len_input_gcm.currentText())
            except ValueError:
                return 96  
        return 96  

# Application entry point
def main():
    app = QtWidgets.QApplication(sys.argv)
    window = AESApp()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
