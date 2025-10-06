"""Result formatting and persistence."""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .colors import Colors
from .config import ConfigManager
from .encryption import EncryptionManager

class ResultManager:
    """Sonuçları okunabilir formatta yazdırma ve şifreli kaydetme"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.encryption = EncryptionManager()
    
    def print_result(self, result: Dict[str, Any]):
        """Sonucu görsel ve tablolu formatta yazdır"""
        if "error" in result:
            print(Colors.error(f"Hata: {result['error']}"))
            return
        
        tool_name = result.get('tool', 'Unknown Tool')
        target = result.get('target', 'Unknown Target')
        timestamp = result.get('timestamp', 'Unknown Time')
        
        # Başlık ve bilgi tablosu
        print(Colors.separator())
        print(Colors.title(f"OSINT SONUCU - {tool_name.upper()}"))
        
        # Bilgi tablosu
        self._print_info_table([
            ("Hedef", target),
            ("Zaman", timestamp),
            ("Araç", tool_name)
        ])
        
        # Sonuç verilerini kategorilere göre yazdır
        for key, value in result.items():
            if key not in ['tool', 'target', 'timestamp']:
                self._print_data_section(key, value)
        
        print(Colors.separator())
    
    def _print_info_table(self, data: List[tuple]):
        """Bilgi tablosu yazdır"""
        print(f"\n{Colors.bold_blue('ğŸ“Š BİLGİLER')}")
        print(f"{Colors.cyan('â”Œ' + 'â”€' * 50 + 'â”')}")
        
        for label, value in data:
            label_padded = f"{label:15}"
            value_str = str(value)[:30] + "..." if len(str(value)) > 30 else str(value)
            print(f"{Colors.cyan('â”‚')} {Colors.highlight(label_padded)} {Colors.muted(value_str):<30} {Colors.cyan('â”‚')}")
        
        print(f"{Colors.cyan('â””' + 'â”€' * 50 + 'â”˜')}")
    
    def _print_data_section(self, section_name: str, data: Any):
        """Veri bölümünü yazdır"""
        section_title = section_name.replace('_', ' ').title()
        
        if isinstance(data, dict):
            self._print_dict_table(section_title, data)
        elif isinstance(data, list):
            self._print_list_table(section_title, data)
        else:
            self._print_simple_value(section_title, data)
    
    def _print_dict_table(self, title: str, data: dict):
        """Sözlük verisini tablo olarak yazdır"""
        print(f"\n{Colors.bold_cyan(f'ğŸ” {title.upper()}')}")
        
        if not data:
            print(f"{Colors.muted('  Veri bulunamadı')}")
            return
        
        # Tablo başlığı
        print(f"{Colors.cyan('â”Œ' + 'â”€' * 60 + 'â”')}")
        print(f"{Colors.cyan('â”‚')} {Colors.bold_green('Özellik'):<25} {Colors.cyan('â”‚')} {Colors.bold_green('Değer'):<30} {Colors.cyan('â”‚')}")
        print(f"{Colors.cyan('â”œ' + 'â”€' * 25 + 'â”¼' + 'â”€' * 32 + 'â”¤')}")
        
        for key, value in data.items():
            key_str = str(key)[:24]
            value_str = str(value)[:29]
            print(f"{Colors.cyan('â”‚')} {Colors.highlight(key_str):<25} {Colors.cyan('â”‚')} {Colors.muted(value_str):<30} {Colors.cyan('â”‚')}")
        
        print(f"{Colors.cyan('â””' + 'â”€' * 60 + 'â”˜')}")
    
    def _print_list_table(self, title: str, data: list):
        """Liste verisini tablo olarak yazdır"""
        print(f"\n{Colors.bold_cyan(f'ğŸ“‹ {title.upper()}')}")
        
        if not data:
            print(f"{Colors.muted('  Liste boş')}")
            return
        
        # Tablo başlığı
        print(f"{Colors.cyan('â”Œ' + 'â”€' * 50 + 'â”')}")
        print(f"{Colors.cyan('â”‚')} {Colors.bold_green('Sıra'):<5} {Colors.cyan('â”‚')} {Colors.bold_green('İçerik'):<40} {Colors.cyan('â”‚')}")
        print(f"{Colors.cyan('â”œ' + 'â”€' * 5 + 'â”¼' + 'â”€' * 42 + 'â”¤')}")
        
        for i, item in enumerate(data, 1):
            item_str = str(item)[:39]
            print(f"{Colors.cyan('â”‚')} {Colors.highlight(f'{i:3}'):<5} {Colors.cyan('â”‚')} {Colors.muted(item_str):<40} {Colors.cyan('â”‚')}")
        
        print(f"{Colors.cyan('â””' + 'â”€' * 50 + 'â”˜')}")
    
    def _print_simple_value(self, title: str, value: Any):
        """Basit değeri yazdır"""
        print(f"\n{Colors.bold_cyan(f'ğŸ“„ {title.upper()}')}")
        print(f"{Colors.cyan('â”Œ' + 'â”€' * 50 + 'â”')}")
        print(f"{Colors.cyan('â”‚')} {Colors.muted(str(value)):<48} {Colors.cyan('â”‚')}")
        print(f"{Colors.cyan('â””' + 'â”€' * 50 + 'â”˜')}")
    
    def save_result(self, result: Dict[str, Any]):
        """Sonucu şifreli olarak dosyaya kaydet"""
        if not self.config.get('output_format.save_to_file', True):
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tool_name = result.get('tool', 'unknown')
        filename = f"encrypted_data/{tool_name}_{timestamp}.enc"
        
        try:
            Path("encrypted_data").mkdir(exist_ok=True)
            if self.encryption.save_encrypted_file(result, filename):
                print(Colors.success(f"Sonuç şifreli olarak kaydedildi: {filename}"))
            else:
                print(Colors.error("Åifreli kaydetme başarısız"))
        except Exception as e:
            print(Colors.error(f"Sonuç kaydedilemedi: {e}"))
    
    def load_encrypted_result(self, filename: str) -> dict:
        """Åifreli sonucu yükle"""
        try:
            return self.encryption.load_encrypted_file(filename)
        except Exception as e:
            print(Colors.error(f"Åifreli dosya yüklenemedi: {e}"))
            return {}
    
    def list_encrypted_results(self) -> list:
        """Åifreli sonuçları listele"""
        try:
            encrypted_dir = Path("encrypted_data")
            if not encrypted_dir.exists():
                return []
            
            files = list(encrypted_dir.glob("*.enc"))
            return [str(f) for f in files]
        except Exception as e:
            print(Colors.error(f"Åifreli dosyalar listelenemedi: {e}"))
            return []

