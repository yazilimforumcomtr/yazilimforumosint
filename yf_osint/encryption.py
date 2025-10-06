"""Encryption utilities for secure result storage."""

import base64
import json
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .colors import Colors

class EncryptionManager:
    """AES şifreleme yönetimi sınıfı"""
    
    def __init__(self, password: str = "YF_OSINT_2025_SECURE_KEY"):
        """Åifreleme yöneticisini başlat"""
        self.password = password.encode()
        self.salt = b'YF_OSINT_SALT_2025'  # Sabit salt (gerçek uygulamada rastgele olmalı)
        self._derive_key()
    
    def _derive_key(self):
        """PBKDF2 ile anahtar türet"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(self.password))
        self.cipher = Fernet(self.key)
    
    def encrypt_data(self, data: dict) -> str:
        """Veriyi şifrele"""
        try:
            json_data = json.dumps(data, ensure_ascii=False, indent=2)
            encrypted_data = self.cipher.encrypt(json_data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            print(Colors.error(f"Åifreleme hatası: {e}"))
            return None
    
    def decrypt_data(self, encrypted_data: str) -> dict:
        """Veriyi şifre çöz"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self.cipher.decrypt(encrypted_bytes)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            print(Colors.error(f"Åifre çözme hatası: {e}"))
            return {}
    
    def save_encrypted_file(self, data: dict, filename: str) -> bool:
        """Åifrelenmiş veriyi dosyaya kaydet"""
        try:
            encrypted_data = self.encrypt_data(data)
            if encrypted_data:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(encrypted_data)
                return True
        except Exception as e:
            print(Colors.error(f"Dosya kaydetme hatası: {e}"))
        return False
    
    def load_encrypted_file(self, filename: str) -> dict:
        """Åifrelenmiş dosyayı yükle"""
        try:
            if os.path.exists(filename):
                with open(filename, 'r', encoding='utf-8') as f:
                    encrypted_data = f.read()
                return self.decrypt_data(encrypted_data)
        except Exception as e:
            print(Colors.error(f"Dosya yükleme hatası: {e}"))
        return {}

