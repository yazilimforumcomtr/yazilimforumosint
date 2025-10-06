"""Centralized error handling."""

import time
from datetime import datetime
from pathlib import Path

class ErrorHandler:
    """Kapsamlı hata yakalama ve raporlama sistemi"""
    
    def __init__(self):
        self.log_file = Path("logs/error.log")
        self.critical_log_file = Path("logs/critical.log")
        self.performance_log_file = Path("logs/performance.log")
        self.log_file.parent.mkdir(exist_ok=True)
        self.error_count = 0
        self.critical_count = 0
        self.performance_data = []
    
    def log_error(self, error: Exception, context: str = "", level: str = "ERROR"):
        """Hatayı logla"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        error_type = type(error).__name__
        error_msg = f"[{timestamp}] {level} in {context}: {error_type}: {str(error)}\n"
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(error_msg)
            
            if level == "CRITICAL":
                with open(self.critical_log_file, 'a', encoding='utf-8') as f:
                    f.write(error_msg)
                self.critical_count += 1
            
            self.error_count += 1
        except:
            pass  # Log yazma hatası göz ardı et
    
    def log_performance(self, func_name: str, execution_time: float, success: bool):
        """Performans verilerini logla"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        perf_msg = f"[{timestamp}] {func_name}: {execution_time:.2f}s - {'SUCCESS' if success else 'FAILED'}\n"
        
        try:
            with open(self.performance_log_file, 'a', encoding='utf-8') as f:
                f.write(perf_msg)
            
            self.performance_data.append({
                'timestamp': timestamp,
                'function': func_name,
                'execution_time': execution_time,
                'success': success
            })
        except:
            pass
    
    def handle_error(self, func):
        """Hata yakalama decorator'ı"""
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                self.log_performance(func.__name__, execution_time, True)
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                self.log_performance(func.__name__, execution_time, False)
                self.log_error(e, func.__name__)
                return {"error": str(e), "tool": func.__name__, "timestamp": datetime.now().isoformat()}
        return wrapper
    
    def handle_critical_error(self, func):
        """Kritik hata yakalama decorator'ı"""
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                self.log_performance(func.__name__, execution_time, True)
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                self.log_performance(func.__name__, execution_time, False)
                self.log_error(e, func.__name__, "CRITICAL")
                return {"error": str(e), "tool": func.__name__, "timestamp": datetime.now().isoformat(), "critical": True}
        return wrapper
    
    def get_error_stats(self):
        """Hata istatistiklerini getir"""
        return {
            "total_errors": self.error_count,
            "critical_errors": self.critical_count,
            "recent_performance": self.performance_data[-10:] if self.performance_data else []
        }
    
    def clear_logs(self):
        """Log dosyalarını temizle"""
        try:
            if self.log_file.exists():
                self.log_file.unlink()
            if self.critical_log_file.exists():
                self.critical_log_file.unlink()
            if self.performance_log_file.exists():
                self.performance_log_file.unlink()
            self.error_count = 0
            self.critical_count = 0
            self.performance_data = []
        except:
            pass

