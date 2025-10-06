"""Configuration management."""

import json
from pathlib import Path

from .colors import Colors

class ConfigManager:
    """Tek merkezi yapılandırma yöneticisi"""
    
    def __init__(self):
        self.config_file = Path("config.json")
        self.default_config = {
            "api_timeouts": {
                "default": 10,
                "dns": 5,
                "http": 15
            },
            "rate_limits": {
                "requests_per_minute": 60,
                "delay_between_requests": 1
            },
            "output_format": {
                "colors": True,
                "detailed": True,
                "save_to_file": True
            },
            "tools": {
                "person_intelligence": {
                    "enabled": True,
                    "max_results": 50
                },
                "site_intelligence": {
                    "enabled": True,
                    "max_results": 100
                },
                "social_media": {
                    "enabled": True,
                    "max_results": 25
                }
            },
            "security": {
                "encrypt_results": False,
                "log_level": "INFO"
            }
        }
        self.load_config()
    
    def load_config(self):
        """Yapılandırmayı yükle"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                print(Colors.success("Yapılandırma yüklendi"))
            except Exception as e:
                print(Colors.warning(f"Yapılandırma yüklenemedi: {e}"))
                self.config = self.default_config.copy()
        else:
            self.config = self.default_config.copy()
            self.save_config()
    
    def save_config(self):
        """Yapılandırmayı kaydet"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            print(Colors.success("Yapılandırma kaydedildi"))
        except Exception as e:
            print(Colors.error(f"Yapılandırma kaydedilemedi: {e}"))
    
    def get(self, key_path: str, default=None):
        """Yapılandırma değeri al"""
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return default
            return value
        except (KeyError, TypeError):
            return default

