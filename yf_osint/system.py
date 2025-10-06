"""System management helpers."""

import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

from .colors import Colors

class SystemManager:
    """Sistem yönetimi ve platform algılama"""
    
    def __init__(self):
        self.platform = sys.platform
        self.python_version = sys.version_info
        self.working_dir = Path.cwd()
        self.is_windows = os.name == 'nt'
        self.is_linux = sys.platform.startswith('linux')
        self.is_macos = sys.platform == 'darwin'
        
    def get_system_info(self) -> Dict[str, Any]:
        """Sistem bilgilerini getir"""
        return {
            "platform": self.platform,
            "python_version": f"{self.python_version.major}.{self.python_version.minor}.{self.python_version.micro}",
            "working_directory": str(self.working_dir),
            "os_type": "Windows" if self.is_windows else "Linux" if self.is_linux else "macOS" if self.is_macos else "Unknown"
        }
    
    def clear_screen(self):
        """Ekranı temizle"""
        os.system('cls' if self.is_windows else 'clear')
    
    def create_directories(self):
        """Gerekli dizinleri oluştur"""
        directories = [
            "data",
            "logs", 
            "reports",
            "temp",
            "backups",
            "encrypted_data"
        ]
        
        for directory in directories:
            Path(directory).mkdir(exist_ok=True)
            print(Colors.success(f"Dizin oluşturuldu: {directory}"))
    
    def check_dependencies(self) -> bool:
        """Bağımlılıkları kontrol et"""
        required_modules = ['requests', 'beautifulsoup4', 'dnspython', 'cryptography']
        missing = []
        
        for module in required_modules:
            try:
                __import__(module)
                print(Colors.success(f"{module} - OK"))
            except ImportError:
                missing.append(module)
                print(Colors.error(f"{module} - Eksik"))
        
        if missing:
            print(Colors.warning(f"Eksik modüller: {', '.join(missing)}"))
            print(Colors.info("Otomatik yükleme başlatılıyor..."))
            
            for module in missing:
                try:
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', module])
                    print(Colors.success(f"{module} yüklendi"))
                except subprocess.CalledProcessError:
                    print(Colors.error(f"{module} yüklenemedi"))
                    return False
        
        return True

