"""Main platform orchestrator."""

import os
import time
import webbrowser
from typing import Any, Dict, List, Optional

from .colors import Colors
from .config import ConfigManager
from .errors import ErrorHandler
from .media import MediaAnalysis
from .person import PersonIntelligence
from .results import ResultManager
from .site import SiteIntelligence
from .social import SocialMediaIntelligence
from .system import SystemManager
from .utilities import UtilityTools
from .web import FLASK_AVAILABLE, WebServer

class YFOSINTPlatform:
    """YF OSINT Platform - Ana sınıf"""
    
    def __init__(self):
        # Sistem bileşenleri
        self.system = SystemManager()
        self.config = ConfigManager()
        self.error_handler = ErrorHandler()
        self.result_manager = ResultManager(self.config)
        
        # OSINT araçları
        self.person_intelligence = PersonIntelligence(self.config, self.error_handler)
        self.site_intelligence = SiteIntelligence(self.config, self.error_handler)
        self.social_media = SocialMediaIntelligence(self.config, self.error_handler)
        self.media_analysis = MediaAnalysis(self.config, self.error_handler)
        self.utility_tools = UtilityTools(self.config, self.error_handler)
        
        # Araç listesi
        self.tools = self._initialize_tools()
        self._enrich_tool_metadata()
        
        # Web sunucusu
        self.web_server = None
        if FLASK_AVAILABLE:
            try:
                self.web_server = WebServer(self)
                print(Colors.success("Web dashboard hazır"))
            except Exception as e:
                print(Colors.warning(f"Web dashboard başlatılamadı: {e}"))
                self.web_server = None
        
    def _initialize_tools(self) -> Dict[str, Dict]:
        """Tüm araçları başlat - 60+ OSINT Aracı"""
        return {
            # =============================================================================
            # KİÅİ İSTİHBARATI (20 Araç)
            # =============================================================================
            "1": {
                "name": "LinkedIn Profil Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.linkedin_analyzer,
                "description": "LinkedIn profillerini detaylı analiz eder"
            },
            "2": {
                "name": "E-posta Sızıntı Kontrolü",
                "category": "Kişi İstihbaratı", 
                "function": self.person_intelligence.email_breach_checker,
                "description": "E-posta adresinin veri sızıntılarında olup olmadığını kontrol eder"
            },
            "3": {
                "name": "Telefon Konum ve Ağ Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.phone_location_analyzer,
                "description": "Telefon numarasının konum ve operatör bilgilerini analiz eder"
            },
            "4": {
                "name": "Sosyal Medya Cross-Check",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.social_cross_check,
                "description": "Farklı sosyal medya platformlarında aynı kişiyi arar"
            },
            "5": {
                "name": "Kullanıcı Adı Arama",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.username_search,
                "description": "Kullanıcı adını farklı platformlarda arar"
            },
            "6": {
                "name": "E-posta Doğrulama",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.email_validation,
                "description": "E-posta adresinin geçerliliğini kontrol eder"
            },
            "7": {
                "name": "Telefon Doğrulama",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.phone_validation,
                "description": "Telefon numarasının geçerliliğini kontrol eder"
            },
            "8": {
                "name": "IP Adres Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.ip_analysis,
                "description": "IP adresinin konum ve sağlayıcı bilgilerini analiz eder"
            },
            "9": {
                "name": "MAC Adres Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.mac_analysis,
                "description": "MAC adresinin üretici bilgilerini analiz eder"
            },
            "10": {
                "name": "Domain WHOIS Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.domain_whois,
                "description": "Domain'in WHOIS bilgilerini analiz eder"
            },
            "11": {
                "name": "E-posta Header Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.email_header_analysis,
                "description": "E-posta header bilgilerini analiz eder"
            },
            "12": {
                "name": "Sosyal Medya Profil Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.social_profile_analysis,
                "description": "Sosyal medya profillerini detaylı analiz eder"
            },
            "13": {
                "name": "Kullanıcı Adı Benzerlik Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.username_similarity,
                "description": "Benzer kullanıcı adlarını bulur"
            },
            "14": {
                "name": "E-posta Domain Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.email_domain_analysis,
                "description": "E-posta domain bilgilerini analiz eder"
            },
            "15": {
                "name": "Telefon Operatör Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.phone_carrier_analysis,
                "description": "Telefon operatör bilgilerini analiz eder"
            },
            "16": {
                "name": "IP Geolocation",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.ip_geolocation,
                "description": "IP adresinin coğrafi konumunu bulur"
            },
            "17": {
                "name": "E-posta MX Kayıt Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.email_mx_analysis,
                "description": "E-posta MX kayıtlarını analiz eder"
            },
            "18": {
                "name": "Kullanıcı Adı Kullanılabilirlik",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.username_availability,
                "description": "Kullanıcı adının farklı platformlarda kullanılabilirliğini kontrol eder"
            },
            "19": {
                "name": "E-posta Format Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.email_format_analysis,
                "description": "E-posta formatını analiz eder"
            },
            "20": {
                "name": "Telefon Format Analizi",
                "category": "Kişi İstihbaratı",
                "function": self.person_intelligence.phone_format_analysis,
                "description": "Telefon numarası formatını analiz eder"
            },
            
            # =============================================================================
            # SİTE İSTİHBARATI (20 Araç)
            # =============================================================================
            "21": {
                "name": "Subdomain Tarama ve SSL Analizi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.subdomain_ssl_analyzer,
                "description": "Subdomainleri tarar ve SSL sertifikalarını analiz eder"
            },
            "22": {
                "name": "Açık Port ve Servis Tarama",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.port_service_scanner,
                "description": "Açık portları ve çalışan servisleri tarar"
            },
            "23": {
                "name": "HTTP Header Bilgi Analizi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.http_header_analyzer,
                "description": "HTTP başlıklarını detaylı analiz eder"
            },
            "24": {
                "name": "DNS Kayıt Analizi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.dns_analysis,
                "description": "DNS kayıtlarını detaylı analiz eder"
            },
            "25": {
                "name": "SSL Sertifika Analizi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.ssl_certificate_analysis,
                "description": "SSL sertifikalarını detaylı analiz eder"
            },
            "26": {
                "name": "Web Teknoloji Tespiti",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.web_technology_detection,
                "description": "Web sitesinde kullanılan teknolojileri tespit eder"
            },
            "27": {
                "name": "Robots.txt Analizi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.robots_analysis,
                "description": "Robots.txt dosyasını analiz eder"
            },
            "28": {
                "name": "Sitemap Analizi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.sitemap_analysis,
                "description": "Sitemap dosyalarını analiz eder"
            },
            "29": {
                "name": "Hassas Dosya Tarama",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.sensitive_file_scan,
                "description": "Hassas dosyaları tarar"
            },
            "30": {
                "name": "Directory Traversal Testi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.directory_traversal_test,
                "description": "Directory traversal zafiyetlerini test eder"
            },
            "31": {
                "name": "SQL Injection Testi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.sql_injection_test,
                "description": "SQL injection zafiyetlerini test eder"
            },
            "32": {
                "name": "XSS Testi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.xss_test,
                "description": "XSS zafiyetlerini test eder"
            },
            "33": {
                "name": "CSRF Testi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.csrf_test,
                "description": "CSRF zafiyetlerini test eder"
            },
            "34": {
                "name": "Web Uygulama Güvenlik Testi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.web_app_security_test,
                "description": "Web uygulama güvenlik testleri yapar"
            },
            "35": {
                "name": "SSL/TLS Güvenlik Analizi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.ssl_tls_security_analysis,
                "description": "SSL/TLS güvenlik ayarlarını analiz eder"
            },
            "36": {
                "name": "HTTP Güvenlik Header Analizi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.http_security_headers,
                "description": "HTTP güvenlik başlıklarını analiz eder"
            },
            "37": {
                "name": "Web Server Bilgi Tespiti",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.web_server_detection,
                "description": "Web server bilgilerini tespit eder"
            },
            "38": {
                "name": "Content Security Policy Analizi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.csp_analysis,
                "description": "Content Security Policy ayarlarını analiz eder"
            },
            "39": {
                "name": "Cookie Analizi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.cookie_analysis,
                "description": "Cookie bilgilerini analiz eder"
            },
            "40": {
                "name": "Web Performans Analizi",
                "category": "Site İstihbaratı",
                "function": self.site_intelligence.web_performance_analysis,
                "description": "Web sitesi performansını analiz eder"
            },
            
            # =============================================================================
            # SOSYAL MEDYA ANALİZİ (10 Araç)
            # =============================================================================
            "41": {
                "name": "Twitter/X Aktivite Analizi",
                "category": "Sosyal Medya",
                "function": self.social_media.twitter_activity_analyzer,
                "description": "Twitter hesaplarının aktivitelerini analiz eder"
            },
            "42": {
                "name": "Instagram Açık Gönderi Analizi",
                "category": "Sosyal Medya",
                "function": self.social_media.instagram_post_analyzer,
                "description": "Instagram gönderilerini analiz eder"
            },
            "43": {
                "name": "Facebook Profil Analizi",
                "category": "Sosyal Medya",
                "function": self.social_media.facebook_profile_analysis,
                "description": "Facebook profillerini analiz eder"
            },
            "44": {
                "name": "YouTube Kanal Analizi",
                "category": "Sosyal Medya",
                "function": self.social_media.youtube_channel_analysis,
                "description": "YouTube kanallarını analiz eder"
            },
            "45": {
                "name": "TikTok Profil Analizi",
                "category": "Sosyal Medya",
                "function": self.social_media.tiktok_profile_analysis,
                "description": "TikTok profillerini analiz eder"
            },
            "46": {
                "name": "LinkedIn Åirket Analizi",
                "category": "Sosyal Medya",
                "function": self.social_media.linkedin_company_analysis,
                "description": "LinkedIn şirket sayfalarını analiz eder"
            },
            "47": {
                "name": "Reddit Kullanıcı Analizi",
                "category": "Sosyal Medya",
                "function": self.social_media.reddit_user_analysis,
                "description": "Reddit kullanıcılarını analiz eder"
            },
            "48": {
                "name": "Discord Sunucu Analizi",
                "category": "Sosyal Medya",
                "function": self.social_media.discord_server_analysis,
                "description": "Discord sunucularını analiz eder"
            },
            "49": {
                "name": "Telegram Kanal Analizi",
                "category": "Sosyal Medya",
                "function": self.social_media.telegram_channel_analysis,
                "description": "Telegram kanallarını analiz eder"
            },
            "50": {
                "name": "Sosyal Medya Cross-Platform Analizi",
                "category": "Sosyal Medya",
                "function": self.social_media.cross_platform_analysis,
                "description": "Farklı platformlarda aynı kullanıcıyı arar"
            },
            
            # =============================================================================
            # MEDYA/GÖRSEL ANALİZİ (10 Araç)
            # =============================================================================
            "51": {
                "name": "EXIF Veri Analizi",
                "category": "Medya/Görsel Analizi",
                "function": self.media_analysis.exif_analysis,
                "description": "Görsel dosyalarındaki EXIF verilerini analiz eder"
            },
            "52": {
                "name": "Görsel Metadata Analizi",
                "category": "Medya/Görsel Analizi",
                "function": self.media_analysis.image_metadata_analysis,
                "description": "Görsel metadata bilgilerini analiz eder"
            },
            "53": {
                "name": "Video Metadata Analizi",
                "category": "Medya/Görsel Analizi",
                "function": self.media_analysis.video_metadata_analysis,
                "description": "Video metadata bilgilerini analiz eder"
            },
            "54": {
                "name": "Görsel Tersine Arama",
                "category": "Medya/Görsel Analizi",
                "function": self.media_analysis.reverse_image_search,
                "description": "Görsel dosyasını tersine arar"
            },
            "55": {
                "name": "Görsel Benzerlik Analizi",
                "category": "Medya/Görsel Analizi",
                "function": self.media_analysis.image_similarity_analysis,
                "description": "Görsel benzerliklerini analiz eder"
            },
            "56": {
                "name": "Görsel Steganografi Analizi",
                "category": "Medya/Görsel Analizi",
                "function": self.media_analysis.steganography_analysis,
                "description": "Görselde gizli veri arar"
            },
            "57": {
                "name": "Görsel OCR Analizi",
                "category": "Medya/Görsel Analizi",
                "function": self.media_analysis.ocr_analysis,
                "description": "Görseldeki metni okur"
            },
            "58": {
                "name": "Görsel Renk Analizi",
                "category": "Medya/Görsel Analizi",
                "function": self.media_analysis.color_analysis,
                "description": "Görsel renk paletini analiz eder"
            },
            "59": {
                "name": "Görsel Boyut ve Format Analizi",
                "category": "Medya/Görsel Analizi",
                "function": self.media_analysis.image_format_analysis,
                "description": "Görsel boyut ve format bilgilerini analiz eder"
            },
            "60": {
                "name": "Görsel GPS Koordinat Analizi",
                "category": "Medya/Görsel Analizi",
                "function": self.media_analysis.gps_coordinate_analysis,
                "description": "Görseldeki GPS koordinatlarını analiz eder"
            },
            
            # =============================================================================
            # YARDIMCI ARAÇLAR (10 Araç)
            # =============================================================================
            "61": {
                "name": "Hash Hesaplayıcı",
                "category": "Yardımcı Araçlar",
                "function": self.utility_tools.hash_calculator,
                "description": "Farklı hash algoritmaları ile hash hesaplar"
            },
            "62": {
                "name": "Hash Karşılaştırıcı",
                "category": "Yardımcı Araçlar",
                "function": self.utility_tools.hash_comparator,
                "description": "Hash değerlerini karşılaştırır"
            },
            "63": {
                "name": "Base64 Encoder/Decoder",
                "category": "Yardımcı Araçlar",
                "function": self.utility_tools.base64_encoder_decoder,
                "description": "Base64 kodlama/çözme işlemleri yapar"
            },
            "64": {
                "name": "URL Encoder/Decoder",
                "category": "Yardımcı Araçlar",
                "function": self.utility_tools.url_encoder_decoder,
                "description": "URL kodlama/çözme işlemleri yapar"
            },
            "65": {
                "name": "Hex Encoder/Decoder",
                "category": "Yardımcı Araçlar",
                "function": self.utility_tools.hex_encoder_decoder,
                "description": "Hex kodlama/çözme işlemleri yapar"
            },
            "66": {
                "name": "Binary Encoder/Decoder",
                "category": "Yardımcı Araçlar",
                "function": self.utility_tools.binary_encoder_decoder,
                "description": "Binary kodlama/çözme işlemleri yapar"
            },
            "67": {
                "name": "QR Code Oluşturucu",
                "category": "Yardımcı Araçlar",
                "function": self.utility_tools.qr_code_generator,
                "description": "QR kod oluşturur"
            },
            "68": {
                "name": "QR Code Okuyucu",
                "category": "Yardımcı Araçlar",
                "function": self.utility_tools.qr_code_reader,
                "description": "QR kod okur"
            },
            "69": {
                "name": "Barcode Oluşturucu",
                "category": "Yardımcı Araçlar",
                "function": self.utility_tools.barcode_generator,
                "description": "Barkod oluşturur"
            },
            "70": {
                "name": "Barcode Okuyucu",
                "category": "Yardımcı Araçlar",
                "function": self.utility_tools.barcode_reader,
                "description": "Barkod okur"
            }
        }
    
    def print_banner(self):
        """Modern ve etkileyici banner göster"""
        banner = f"""
{Colors.cyan('â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—')}
{Colors.cyan('â•‘                                                                              â•‘')}
{Colors.cyan('â•‘  â–ˆâ–ˆâ•—   â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—    â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ•—   â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—                â•‘')}
{Colors.cyan('â•‘  â•šâ–ˆâ–ˆâ•— â–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•”â•â•â•â•â•    â–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ•”â•â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ•‘â•šâ•â•â–ˆâ–ˆâ•”â•â•â•                â•‘')}
{Colors.cyan('â•‘   â•šâ–ˆâ–ˆâ–ˆâ–ˆâ•”â• â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—      â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â–ˆâ–ˆâ•— â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘                   â•‘')}
{Colors.cyan('â•‘    â•šâ–ˆâ–ˆâ•”â•  â–ˆâ–ˆâ•”â•â•â•      â•šâ•â•â•â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘                   â•‘')}
{Colors.cyan('â•‘     â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—    â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘ â•šâ–ˆâ–ˆâ–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘                   â•‘')}
{Colors.cyan('â•‘     â•šâ•â•   â•šâ•â•â•â•â•â•â•    â•šâ•â•â•â•â•â•â• â•šâ•â•â•â•â•â• â•šâ•â•â•šâ•â•  â•šâ•â•â•â•   â•šâ•â•                   â•‘')}
{Colors.cyan('â•‘                                                                              â•‘')}
{Colors.cyan('â•‘                    CYBER GÜVENLİK OPERASYON MERKEZİ                         â•‘')}
{Colors.cyan('â•‘                     Yazılım Forum İstihbarat Ekibi                          â•‘')}
{Colors.cyan('â•‘                                                                              â•‘')}
{Colors.cyan('â•‘                           TEK DOSYALIK KURULUM                              â•‘')}
{Colors.cyan('â•‘                              Versiyon 3.0.0                                 â•‘')}
{Colors.cyan('â•‘                                                                              â•‘')}
{Colors.cyan('â•‘                        OSINT & SİBER GÜVENLİK                               â•‘')}
{Colors.cyan('â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•')}
"""
        print(banner)
        
        # Sistem durumu göstergesi
        print(f"{Colors.bold_blue('â”Œâ”€ SİSTEM DURUMU â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”')}")
        print(f"{Colors.cyan('â”‚')} {Colors.success('Sistem Aktif')} {Colors.cyan('â”‚')} {Colors.info('Web Dashboard Hazır')} {Colors.cyan('â”‚')} {Colors.warning('Åifreli Veri Yönetimi')} {Colors.cyan('â”‚')}")
        print(f"{Colors.bold_blue('â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜')}")
    
    def show_menu(self):
        """Modern ve kategorik ana menüyü göster"""
        print(f"\n{Colors.header('OSINT ARAÇ KATEGORİLERİ')}")
        
        categories = {}
        for tool_id, tool_info in self.tools.items():
            category = tool_info['category']
            if category not in categories:
                categories[category] = []
            categories[category].append((tool_id, tool_info))
        
        # Kategori ikonları ve renkleri
        category_icons = {
            'Person Intelligence': '[P]',
            'Site Intelligence': '[S]',
            'Social Media': '[M]',
            'Media Analysis': '[A]',
            'Utility Tools': '[U]'
        }
        
        category_colors = {
            'Person Intelligence': Colors.bold_red,
            'Site Intelligence': Colors.bold_blue,
            'Social Media': Colors.bold_blue,
            'Media Analysis': Colors.bold_yellow,
            'Utility Tools': Colors.bold_cyan
        }
        
        for category, tools in categories.items():
            icon = category_icons.get(category, 'ğŸ“‹')
            color_func = category_colors.get(category, Colors.bold_blue)
            
            print(f"\n{color_func(f'â”Œâ”€ {icon} {category.upper()} â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”')}")
            
            # Araçları 2 sütunlu olarak göster
            for i in range(0, len(tools), 2):
                row_tools = tools[i:i+2]
                for j, (tool_id, tool_info) in enumerate(row_tools):
                    if j == 0:
                        print(f"{Colors.cyan('â”‚')} {Colors.green(f'[{tool_id:2}]')} {Colors.bold(tool_info['name']):<25} {Colors.cyan('â”‚')}", end="")
                    else:
                        print(f" {Colors.green(f'[{tool_id:2}]')} {Colors.bold(tool_info['name']):<25} {Colors.cyan('â”‚')}")
                
                # Açıklamaları göster
                for j, (tool_id, tool_info) in enumerate(row_tools):
                    if j == 0:
                        print(f"{Colors.cyan('â”‚')} {Colors.muted('    ' + tool_info['description'][:25]):<25} {Colors.cyan('â”‚')}", end="")
                    else:
                        print(f" {Colors.muted('    ' + tool_info['description'][:25]):<25} {Colors.cyan('â”‚')}")
                
                if i + 2 < len(tools):
                    print(f"{Colors.cyan('â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤')}")
            
            print(f"{color_func('â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜')}")
        
        # Sistem menüleri
        print(f"\n{Colors.bold_blue('â”Œâ”€ SİSTEM MENÜLERİ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”')}")
        print(f"{Colors.cyan('â”‚')} {Colors.error('Çıkış')} {Colors.red('[0]')} {Colors.cyan('â”‚')} {Colors.warning('Sistem Bilgileri')} {Colors.yellow('[99]')} {Colors.cyan('â”‚')} {Colors.purple('Åifreli Veri Yönetimi')} {Colors.purple('[enc]')} {Colors.cyan('â”‚')}")
        if self.web_server:
            print(f"{Colors.cyan('â”‚')} {Colors.info('Web Dashboard')} {Colors.cyan('[web]')} {Colors.cyan('â”‚')} {Colors.muted(' ' * 50)} {Colors.cyan('â”‚')}")
        print(f"{Colors.bold_blue('â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜')}")
    
    def show_system_info(self):
        """Modern sistem bilgilerini göster"""
        self.system.clear_screen()
        self.print_banner()
        
        print(f"{Colors.header('ğŸ“Š SİSTEM BİLGİLERİ')}")
        
        # Sistem özeti
        print(f"\n{Colors.bold_blue('â”Œâ”€ SİSTEM ÖZETİ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”')}")
        print(f"{Colors.cyan('â”‚')} {Colors.bold_green('ğŸ”§ OSINT Araçları:')} {Colors.bold(str(len(self.tools))):<10} {Colors.cyan('â”‚')} {Colors.bold_green('ğŸ Python Sürümü:')} {Colors.bold(f'{self.system.python_version.major}.{self.system.python_version.minor}.{self.system.python_version.micro}'):<15} {Colors.cyan('â”‚')}")
        print(f"{Colors.cyan('â”‚')} {Colors.bold_green('ğŸ’» Platform:')} {Colors.bold(self.system.platform):<15} {Colors.cyan('â”‚')} {Colors.bold_green('ğŸ“ Çalışma Dizini:')} {Colors.bold(str(self.system.working_dir)[:30]):<30} {Colors.cyan('â”‚')}")
        print(f"{Colors.bold_blue('â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜')}")
        
        # Araç kategorileri istatistikleri
        categories = {}
        for tool_id, tool_info in self.tools.items():
            category = tool_info['category']
            categories[category] = categories.get(category, 0) + 1
        
        print(f"\n{Colors.bold_yellow('â”Œâ”€ ARAÇ KATEGORİLERİ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”')}")
        for category, count in categories.items():
            icon = {'Person Intelligence': 'ğŸ‘¤', 'Site Intelligence': 'ğŸŒ', 'Social Media': 'ğŸ“±', 'Media Analysis': 'ğŸ“¸', 'Utility Tools': 'ğŸ› ï¸'}.get(category, 'ğŸ“‹')
            print(f"{Colors.cyan('â”‚')} {Colors.bold_green(f'{icon} {category}:')} {Colors.bold(str(count)):<5} {Colors.cyan('â”‚')} {Colors.muted(' ' * 50)} {Colors.cyan('â”‚')}")
        print(f"{Colors.bold_yellow('â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜')}")
        
        # Yapılandırma bilgileri
        print(f"\n{Colors.bold_purple('â”Œâ”€ YAPILANDIRMA AYARLARI â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”')}")
        print(f"{Colors.cyan('â”‚')} {Colors.bold_green('â±ï¸  API Timeout:')} {Colors.bold(str(self.config.get('api_timeouts.default', 10)) + ' saniye'):<15} {Colors.cyan('â”‚')} {Colors.bold_green('ğŸš¦ Rate Limit:')} {Colors.bold(str(self.config.get('rate_limits.requests_per_minute', 60)) + ' istek/dakika'):<20} {Colors.cyan('â”‚')}")
        print(f"{Colors.cyan('â”‚')} {Colors.bold_green('ğŸ¨ Renkli Çıktı:')} {Colors.bold(str(self.config.get('output_format.colors', True))):<15} {Colors.cyan('â”‚')} {Colors.bold_green('ğŸ’¾ Dosyaya Kaydet:')} {Colors.bold(str(self.config.get('output_format.save_to_file', True))):<20} {Colors.cyan('â”‚')}")
        print(f"{Colors.bold_purple('â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜')}")
        
        # Sistem durumu
        print(f"\n{Colors.bold_red('â”Œâ”€ SİSTEM DURUMU â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”')}")
        print(f"{Colors.cyan('â”‚')} {Colors.success('âœ… Sistem Aktif')} {Colors.cyan('â”‚')} {Colors.info('ğŸŒ Web Dashboard Hazır')} {Colors.cyan('â”‚')} {Colors.warning('ğŸ” Åifreli Veri Yönetimi')} {Colors.cyan('â”‚')}")
        print(f"{Colors.bold_red('â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜')}")
        
        input(f"\n{Colors.yellow('ğŸ”™ Ana menüye dönmek için Enter\'a basın...')}")
    
    def show_encryption_menu(self):
        """Åifreli veri yönetimi menüsü"""
        while True:
            self.system.clear_screen()
            self.print_banner()
            
            print(f"{Colors.header('ÅİFRELİ VERİ YÖNETİMİ')}")
            print(f"{Colors.info('1.')} Åifreli dosyaları listele")
            print(f"{Colors.info('2.')} Åifreli dosyayı görüntüle")
            print(f"{Colors.info('3.')} Åifreli dosyayı sil")
            print(f"{Colors.info('4.')} Tüm şifreli dosyaları temizle")
            print(f"{Colors.error('0.')} Ana menüye dön")
            
            choice = input(f"\n{Colors.yellow('Seçiminiz: ')}").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                self.list_encrypted_files()
            elif choice == '2':
                self.view_encrypted_file()
            elif choice == '3':
                self.delete_encrypted_file()
            elif choice == '4':
                self.clear_encrypted_files()
            else:
                print(Colors.error("Geçersiz seçim!"))
                input(Colors.yellow("Devam etmek için Enter'a basın..."))
    
    def list_encrypted_files(self):
        """Åifreli dosyaları listele"""
        files = self.result_manager.list_encrypted_results()
        
        if not files:
            print(Colors.warning("Åifreli dosya bulunamadı."))
        else:
            print(f"\n{Colors.header('ÅİFRELİ DOSYALAR')}")
            for i, file_path in enumerate(files, 1):
                filename = os.path.basename(file_path)
                file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                print(f"{Colors.info(f'{i}.')} {Colors.bold(filename)} ({file_size} bytes)")
        
        input(f"\n{Colors.yellow('Devam etmek için Enter\'a basın...')}")
    
    def view_encrypted_file(self):
        """Åifreli dosyayı görüntüle"""
        files = self.result_manager.list_encrypted_results()
        
        if not files:
            print(Colors.warning("Åifreli dosya bulunamadı."))
            input(Colors.yellow("Devam etmek için Enter'a basın..."))
            return
        
        print(f"\n{Colors.header('ÅİFRELİ DOSYA GÖRÜNTÜLE')}")
        for i, file_path in enumerate(files, 1):
            filename = os.path.basename(file_path)
            print(f"{Colors.info(f'{i}.')} {filename}")
        
        try:
            choice = int(input(f"\n{Colors.yellow('Dosya numarası: ')}")) - 1
            if 0 <= choice < len(files):
                file_path = files[choice]
                result = self.result_manager.load_encrypted_result(file_path)
                
                if result:
                    print(f"\n{Colors.header('ÅİFRELİ DOSYA İÇERİÄİ')}")
                    self.result_manager.print_result(result)
                else:
                    print(Colors.error("Dosya yüklenemedi veya şifre çözülemedi."))
            else:
                print(Colors.error("Geçersiz dosya numarası!"))
        except ValueError:
            print(Colors.error("Geçersiz giriş!"))
        
        input(f"\n{Colors.yellow('Devam etmek için Enter\'a basın...')}")
    
    def delete_encrypted_file(self):
        """Åifreli dosyayı sil"""
        files = self.result_manager.list_encrypted_results()
        
        if not files:
            print(Colors.warning("Åifreli dosya bulunamadı."))
            input(Colors.yellow("Devam etmek için Enter'a basın..."))
            return
        
        print(f"\n{Colors.header('ÅİFRELİ DOSYA SİL')}")
        for i, file_path in enumerate(files, 1):
            filename = os.path.basename(file_path)
            print(f"{Colors.info(f'{i}.')} {filename}")
        
        try:
            choice = int(input(f"\n{Colors.yellow('Silinecek dosya numarası: ')}")) - 1
            if 0 <= choice < len(files):
                file_path = files[choice]
                filename = os.path.basename(file_path)
                
                confirm = input(f"{Colors.warning(f'{filename} dosyasını silmek istediğinizden emin misiniz? (e/h): ')}")
                if confirm.lower() in ['e', 'evet', 'y', 'yes']:
                    try:
                        os.remove(file_path)
                        print(Colors.success(f"{filename} dosyası silindi."))
                    except Exception as e:
                        print(Colors.error(f"Dosya silinemedi: {e}"))
                else:
                    print(Colors.info("Silme işlemi iptal edildi."))
            else:
                print(Colors.error("Geçersiz dosya numarası!"))
        except ValueError:
            print(Colors.error("Geçersiz giriş!"))
        
        input(f"\n{Colors.yellow('Devam etmek için Enter\'a basın...')}")
    
    def clear_encrypted_files(self):
        """Tüm şifreli dosyaları temizle"""
        files = self.result_manager.list_encrypted_results()
        
        if not files:
            print(Colors.warning("Åifreli dosya bulunamadı."))
            input(Colors.yellow("Devam etmek için Enter'a basın..."))
            return
        
        print(f"\n{Colors.header('TÜM ÅİFRELİ DOSYALARI TEMİZLE')}")
        print(Colors.warning(f"Toplam {len(files)} şifreli dosya bulundu."))
        
        confirm = input(f"{Colors.error('TÜM şifreli dosyaları silmek istediğinizden emin misiniz? (e/h): ')}")
        if confirm.lower() in ['e', 'evet', 'y', 'yes']:
            try:
                for file_path in files:
                    os.remove(file_path)
                print(Colors.success(f"{len(files)} şifreli dosya silindi."))
            except Exception as e:
                print(Colors.error(f"Dosyalar silinemedi: {e}"))
        else:
            print(Colors.info("Temizleme işlemi iptal edildi."))
        
        input(f"\n{Colors.yellow('Devam etmek için Enter\'a basın...')}")
    
    def _build_input_field(
        self,
        name: str,
        label: str,
        input_type: str = "text",
        placeholder: str = "",
        required: bool = True,
        options: Optional[List[Dict[str, str]]] = None,
        mode: str = "arg",
    ) -> Dict[str, Any]:
        """Create a field description used by the web interface."""
        field: Dict[str, Any] = {
            "name": name,
            "label": label,
            "type": input_type,
            "required": required,
            "mode": mode,
        }
        if placeholder:
            field["placeholder"] = placeholder
        if options:
            field["options"] = options
        return field

    def _default_target_input(self, label: str = "Hedef", placeholder: str = "") -> Dict[str, Any]:
        """Default single target input configuration."""
        if not placeholder:
            placeholder = "Hedef bilgisini girin"
        return self._build_input_field(
            name="target",
            label=label,
            placeholder=placeholder,
        )

    def _enrich_tool_metadata(self) -> None:
        """Augment tool metadata with web specific descriptors."""
        default_placeholder_by_category = {
            "Kişi İstihbaratı": "E-posta, kullanıcı adı veya kişiye ait diğer bilgiler",
            "Site İstihbaratı": "Domain veya IP adresi",
            "Sosyal Medya": "Profil URL'si veya kullanıcı adı",
            "Medya Analizi": "Dosya yolu veya görsel bağlantısı",
            "Yardımcı Araçlar": "Metin veya veri girdisi",
        }

        for tool_id, data in self.tools.items():
            category = data.get("category", "Genel")
            placeholder = default_placeholder_by_category.get(category, "Hedef bilgisini girin")
            if "inputs" not in data:
                data["inputs"] = [self._default_target_input(placeholder=placeholder)]
            data.setdefault("tags", [category])
            data.setdefault("description", data.get("name", ""))

        encode_decode_options = [
            {"label": "Şifrele", "value": "encode"},
            {"label": "Çöz", "value": "decode"},
        ]

        overrides = {
            "3": [self._default_target_input(label="Telefon Numarası", placeholder="Örn: +90... veya 0532...")],
            "4": [self._default_target_input(label="Kullanıcı Adı", placeholder="Örn: johndoe")],
            "21": [self._default_target_input(label="Domain", placeholder="Örn: example.com")],
            "22": [self._default_target_input(label="IP veya Domain", placeholder="Örn: 192.168.1.1")],
            "23": [self._default_target_input(label="URL", placeholder="https://site.com")],
            "51": [self._default_target_input(label="Görsel Yolu", placeholder="Örn: data/image.jpg")],
            "52": [self._default_target_input(label="Görsel Yolu", placeholder="Örn: data/image.jpg")],
            "53": [self._default_target_input(label="Video Yolu", placeholder="Örn: data/video.mp4")],
            "54": [self._default_target_input(label="Görsel Yolu", placeholder="Örn: data/image.jpg")],
            "55": [self._default_target_input(label="Görsel Yolu", placeholder="Örn: data/image.jpg")],
            "56": [self._default_target_input(label="Görsel Yolu", placeholder="Örn: data/image.jpg")],
            "57": [self._default_target_input(label="Görsel Yolu", placeholder="Örn: data/image.jpg")],
            "58": [self._default_target_input(label="Görsel Yolu", placeholder="Örn: data/image.jpg")],
            "59": [self._default_target_input(label="Görsel Yolu", placeholder="Örn: data/image.jpg")],
            "60": [self._default_target_input(label="Görsel Yolu", placeholder="Örn: data/image.jpg")],
            "61": [self._build_input_field("text", "Metin", placeholder="Analiz edilecek metni girin")],
            "62": [
                self._build_input_field("hash1", "Hash 1", placeholder="İlk hash değeri"),
                self._build_input_field("hash2", "Hash 2", placeholder="İkinci hash değeri"),
            ],
            "63": [
                self._build_input_field("text", "Metin", placeholder="Metni girin"),
                self._build_input_field("operation", "İşlem", input_type="select", options=encode_decode_options, mode="kwarg"),
            ],
            "64": [
                self._build_input_field("text", "Metin veya URL", placeholder="Metni girin"),
                self._build_input_field("operation", "İşlem", input_type="select", options=encode_decode_options, mode="kwarg"),
            ],
            "65": [
                self._build_input_field("text", "Metin", placeholder="Metni girin"),
                self._build_input_field("operation", "İşlem", input_type="select", options=encode_decode_options, mode="kwarg"),
            ],
            "66": [
                self._build_input_field("text", "Metin", placeholder="Metni girin"),
                self._build_input_field("operation", "İşlem", input_type="select", options=encode_decode_options, mode="kwarg"),
            ],
            "67": [self._build_input_field("text", "Metin", placeholder="QR kodu için metin")],
            "68": [self._build_input_field("qr_code_path", "QR Kod Dosyası", placeholder="Örn: data/qrcode.png")],
            "69": [self._build_input_field("text", "Metin", placeholder="Barkod için metin")],
            "70": [self._build_input_field("barcode_path", "Barkod Dosyası", placeholder="Örn: data/barcode.png")],
        }

        for tool_id, inputs in overrides.items():
            if tool_id in self.tools:
                self.tools[tool_id]["inputs"] = inputs

    def get_tool_catalog(self) -> List[Dict[str, Any]]:
        """Return tools grouped by category for the web UI."""
        catalog: Dict[str, Dict[str, Any]] = {}
        for tool_id, data in self.tools.items():
            category = data.get("category", "Genel")
            if category not in catalog:
                catalog[category] = {
                    "name": category,
                    "tools": [],
                }
            catalog[category]["tools"].append(
                {
                    "id": tool_id,
                    "name": data.get("name"),
                    "description": data.get("description"),
                    "inputs": data.get("inputs", [self._default_target_input()]),
                    "tags": data.get("tags", [category]),
                }
            )
        ordered = []
        for category in sorted(catalog.keys()):
            tools = sorted(catalog[category]["tools"], key=lambda item: item["name"])
            ordered.append({"name": category, "tools": tools})
        return ordered

    def execute_tool(self, tool_id: str, payload: Dict[str, Any]) -> Any:
        """Execute a tool using web form payload."""
        if tool_id not in self.tools:
            raise ValueError("Geçersiz araç seçimi")

        tool = self.tools[tool_id]
        inputs = tool.get("inputs", [self._default_target_input()])
        args = []
        kwargs: Dict[str, Any] = {}

        for field in inputs:
            name = field["name"]
            required = field.get("required", True)
            value = payload.get(name)
            if isinstance(value, str):
                value = value.strip()
            if (value is None or value == "") and required:
                raise ValueError(f"{field.get('label', name)} alanı gerekli")
            if field.get("mode") == "kwarg":
                if value != "" and value is not None:
                    kwargs[name] = value
            else:
                if value == "" and not required:
                    continue
                args.append(value)

        result = tool["function"](*args, **kwargs)

        if isinstance(result, dict):
            result.setdefault("tool", tool.get("name"))
            result.setdefault("target", payload.get(inputs[0]["name"]))
            if self.config.get("output_format.save_to_file", True):
                try:
                    self.result_manager.save_result(result)
                except Exception as exc:  # pragma: no cover - best effort
                    self.error_handler.log_error(exc, "save_result")
        return result

    def get_tool_count(self) -> int:
        return len(self.tools)

    def get_tool_categories(self) -> List[str]:
        return sorted({data.get("category", "Genel") for data in self.tools.values()})

    def get_system_snapshot(self) -> Dict[str, Any]:
        """Collect lightweight runtime metrics for the dashboard."""
        system_info = self.system.get_system_info()
        error_stats = self.error_handler.get_error_stats()
        encrypted_files = self.result_manager.list_encrypted_results()
        return {
            "tool_count": self.get_tool_count(),
            "categories": self.get_tool_categories(),
            "system": system_info,
            "errors": error_stats,
            "encrypted_files": len(encrypted_files),
        }

    def start_web_dashboard(
        self,
        host: str = "127.0.0.1",
        port: int = 5000,
        debug: bool = False,
        open_browser: bool = False,
    ) -> None:
        """Launch the interactive web dashboard."""
        if not self.web_server:
            raise RuntimeError("Web dashboard kullanılamıyor. Flask yüklü değil.")

        self.system.create_directories()

        if open_browser:
            try:
                import webbrowser

                webbrowser.open(f"http://{host}:{port}")
            except Exception as exc:  # pragma: no cover - optional comfort
                self.error_handler.log_error(exc, "open_browser")

        self.web_server.start(host=host, port=port, debug=debug)

    def start_web_app(self, host: str = "127.0.0.1", port: int = 5000, debug: bool = False, open_browser: bool = True) -> None:
        """Backwards compatible helper for launching the web dashboard."""
        self.start_web_dashboard(host=host, port=port, debug=debug, open_browser=open_browser)

    def run(self, host: str = "127.0.0.1", port: int = 5000, debug: bool = False, open_browser: bool = True):
        """Start the platform in web mode."""
        self.start_web_dashboard(host=host, port=port, debug=debug, open_browser=open_browser)

    def _cleanup(self):
        """Sistem kapatma işlemleri"""
        try:
            # Hata istatistiklerini göster
            stats = self.error_handler.get_error_stats()
            if stats["total_errors"] > 0:
                print(f"\n{Colors.warning('Hata İstatistikleri:')}")
                print(f"  Toplam Hata: {stats['total_errors']}")
                print(f"  Kritik Hata: {stats['critical_errors']}")
            
            # Performans verilerini göster
            if stats["recent_performance"]:
                print(f"\n{Colors.info('Son Performans Verileri:')}")
                for perf in stats["recent_performance"][-3:]:  # Son 3 işlem
                    status = "âœ…" if perf["success"] else "âŒ"
                    print(f"  {status} {perf['function']}: {perf['execution_time']:.2f}s")
            
            print(Colors.success("Sistem temizlendi ve kapatıldı."))
        except Exception as e:
            print(Colors.error(f"Temizleme hatası: {e}"))

