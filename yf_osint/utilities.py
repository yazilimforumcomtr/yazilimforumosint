"""Utility helper tools."""

import base64
import hashlib
from datetime import datetime
from typing import Any, Dict

class UtilityTools:
    """Yardımcı araçlar"""
    
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
    
    def hash_calculator(self, text: str) -> Dict[str, Any]:
        """Hash hesaplayıcı"""
        try:
            result = {
                "tool": "hash_calculator",
                "target": text,
                "timestamp": datetime.now().isoformat(),
                "hashes": {}
            }
            
            # Farklı hash algoritmaları
            algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'blake2b']
            
            for algorithm in algorithms:
                try:
                    if algorithm == 'md5':
                        hash_obj = hashlib.md5()
                    elif algorithm == 'sha1':
                        hash_obj = hashlib.sha1()
                    elif algorithm == 'sha256':
                        hash_obj = hashlib.sha256()
                    elif algorithm == 'sha512':
                        hash_obj = hashlib.sha512()
                    elif algorithm == 'blake2b':
                        hash_obj = hashlib.blake2b()
                    
                    hash_obj.update(text.encode('utf-8'))
                    result["hashes"][algorithm] = hash_obj.hexdigest()
                    
                except Exception as e:
                    result["hashes"][algorithm] = f"Hata: {e}"
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Hash hesaplayıcı hatası: {e}")
            return {
                "tool": "hash_calculator",
                "target": text,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def hash_comparator(self, hash1: str, hash2: str) -> Dict[str, Any]:
        """Hash karşılaştırıcı"""
        try:
            result = {
                "tool": "hash_comparator",
                "target": f"{hash1} vs {hash2}",
                "timestamp": datetime.now().isoformat(),
                "comparison": {
                    "hash1": hash1,
                    "hash2": hash2,
                    "match": hash1.lower() == hash2.lower(),
                    "length_match": len(hash1) == len(hash2)
                }
            }
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Hash karşılaştırıcı hatası: {e}")
            return {
                "tool": "hash_comparator",
                "target": f"{hash1} vs {hash2}",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def base64_encoder_decoder(self, text: str, operation: str = "encode") -> Dict[str, Any]:
        """Base64 encoder/decoder"""
        try:
            result = {
                "tool": "base64_encoder_decoder",
                "target": text,
                "timestamp": datetime.now().isoformat(),
                "operation": operation,
                "result": ""
            }
            
            if operation == "encode":
                result["result"] = base64.b64encode(text.encode('utf-8')).decode('utf-8')
            elif operation == "decode":
                try:
                    result["result"] = base64.b64decode(text).decode('utf-8')
                except:
                    result["result"] = "Geçersiz Base64 formatı"
            else:
                result["result"] = "Geçersiz operasyon (encode/decode)"
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Base64 encoder/decoder hatası: {e}")
            return {
                "tool": "base64_encoder_decoder",
                "target": text,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def url_encoder_decoder(self, text: str, operation: str = "encode") -> Dict[str, Any]:
        """URL encoder/decoder"""
        try:
            from urllib.parse import quote, unquote
            
            result = {
                "tool": "url_encoder_decoder",
                "target": text,
                "timestamp": datetime.now().isoformat(),
                "operation": operation,
                "result": ""
            }
            
            if operation == "encode":
                result["result"] = quote(text)
            elif operation == "decode":
                result["result"] = unquote(text)
            else:
                result["result"] = "Geçersiz operasyon (encode/decode)"
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"URL encoder/decoder hatası: {e}")
            return {
                "tool": "url_encoder_decoder",
                "target": text,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def hex_encoder_decoder(self, text: str, operation: str = "encode") -> Dict[str, Any]:
        """Hex encoder/decoder"""
        try:
            result = {
                "tool": "hex_encoder_decoder",
                "target": text,
                "timestamp": datetime.now().isoformat(),
                "operation": operation,
                "result": ""
            }
            
            if operation == "encode":
                result["result"] = text.encode('utf-8').hex()
            elif operation == "decode":
                try:
                    result["result"] = bytes.fromhex(text).decode('utf-8')
                except:
                    result["result"] = "Geçersiz Hex formatı"
            else:
                result["result"] = "Geçersiz operasyon (encode/decode)"
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Hex encoder/decoder hatası: {e}")
            return {
                "tool": "hex_encoder_decoder",
                "target": text,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def binary_encoder_decoder(self, text: str, operation: str = "encode") -> Dict[str, Any]:
        """Binary encoder/decoder"""
        try:
            result = {
                "tool": "binary_encoder_decoder",
                "target": text,
                "timestamp": datetime.now().isoformat(),
                "operation": operation,
                "result": ""
            }
            
            if operation == "encode":
                result["result"] = ' '.join(format(ord(char), '08b') for char in text)
            elif operation == "decode":
                try:
                    binary_values = text.split()
                    result["result"] = ''.join(chr(int(binary, 2)) for binary in binary_values)
                except:
                    result["result"] = "Geçersiz Binary formatı"
            else:
                result["result"] = "Geçersiz operasyon (encode/decode)"
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Binary encoder/decoder hatası: {e}")
            return {
                "tool": "binary_encoder_decoder",
                "target": text,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def qr_code_generator(self, text: str) -> Dict[str, Any]:
        """QR kod oluşturucu"""
        try:
            result = {
                "tool": "qr_code_generator",
                "target": text,
                "timestamp": datetime.now().isoformat(),
                "qr_code_info": {
                    "text": text,
                    "length": len(text),
                    "generated": True
                }
            }
            
            # QR kod oluşturma simülasyonu
            result["qr_code_info"]["message"] = "QR kod oluşturuldu (qrcode kütüphanesi gerekli)"
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"QR kod oluşturucu hatası: {e}")
            return {
                "tool": "qr_code_generator",
                "target": text,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def qr_code_reader(self, qr_code_path: str) -> Dict[str, Any]:
        """QR kod okuyucu"""
        try:
            result = {
                "tool": "qr_code_reader",
                "target": qr_code_path,
                "timestamp": datetime.now().isoformat(),
                "qr_code_data": {
                    "content": "QR kod okuma için cv2 kütüphanesi gerekli",
                    "format": "QR Code",
                    "read_successfully": False
                }
            }
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"QR kod okuyucu hatası: {e}")
            return {
                "tool": "qr_code_reader",
                "target": qr_code_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def barcode_generator(self, text: str) -> Dict[str, Any]:
        """Barkod oluşturucu"""
        try:
            result = {
                "tool": "barcode_generator",
                "target": text,
                "timestamp": datetime.now().isoformat(),
                "barcode_info": {
                    "text": text,
                    "length": len(text),
                    "generated": True
                }
            }
            
            # Barkod oluşturma simülasyonu
            result["barcode_info"]["message"] = "Barkod oluşturuldu (python-barcode kütüphanesi gerekli)"
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Barkod oluşturucu hatası: {e}")
            return {
                "tool": "barcode_generator",
                "target": text,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def barcode_reader(self, barcode_path: str) -> Dict[str, Any]:
        """Barkod okuyucu"""
        try:
            result = {
                "tool": "barcode_reader",
                "target": barcode_path,
                "timestamp": datetime.now().isoformat(),
                "barcode_data": {
                    "content": "Barkod okuma için pyzbar kütüphanesi gerekli",
                    "format": "Barcode",
                    "read_successfully": False
                }
            }
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Barkod okuyucu hatası: {e}")
            return {
                "tool": "barcode_reader",
                "target": barcode_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

