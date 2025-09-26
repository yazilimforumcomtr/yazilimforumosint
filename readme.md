# YF OSINT Cyber Panel v2.0

🚀 **Modern Hacking Temalı OSINT Platformu** - Yazılım Forum İstihbarat Ekibi

## 🎯 Proje Özeti

YF OSINT Cyber Panel, 30 adet gelişmiş OSINT aracı ile donatılmış, modern web ve terminal arayüzüne sahip kapsamlı bir siber güvenlik platformudur. Tüm veriler AES-256 şifreleme ile güvenli bir şekilde saklanır.

## ✨ Özellikler

### 🔧 30 OSINT Aracı
- **Kişi İstihbaratı (10 Araç)**: LinkedIn analizi, e-posta sızıntı kontrolü, telefon analizi, sosyal medya cross-check, profil fotoğrafı metadata analizi, forum istihbaratı, dark web kontrolü, whois analizi, yüz tanıma, video profil tarama
- **Site İstihbaratı (10 Araç)**: Subdomain tarama, CMS tespiti, port tarama, HTTP header analizi, SSL sertifika analizi, site takibi, GitHub izleme, API kontrolü, robots.txt analizi, dosya erişim testi
- **Sosyal Medya (10 Araç)**: Twitter analizi, Instagram analizi, Facebook tarama, YouTube takibi, yüz tanıma, video analizi, ters görsel arama, metadata analizi, hashtag takibi, sosyal ağ grafiği

### 🎨 Modern Arayüzler
- **Web Dashboard**: Hacking temalı, responsive web arayüzü
- **Terminal Arayüzü**: Gerçek terminal deneyimi
- **Gerçek Zamanlı Güncellemeler**: WebSocket ile canlı veri akışı

### 🔒 Güvenlik
- **AES-256 Şifreleme**: Tüm veriler şifreli saklanır
- **JSON Veri Yönetimi**: Yapılandırılmış veri depolama
- **Güvenli API**: RESTful API endpoint'leri

## 🚀 Kurulum ve Çalıştırma

### Hızlı Başlangıç

#### Windows
```bash
# 1. Projeyi indirin
git clone https://github.com/your-repo/yf-osint-cyber-panel.git
cd yf-osint-cyber-panel

# 2. Başlatın
start.bat
```

#### Linux/macOS
```bash
# 1. Projeyi indirin
git clone https://github.com/your-repo/yf-osint-cyber-panel.git
cd yf-osint-cyber-panel

# 2. Çalıştırılabilir yapın
chmod +x run.py

# 3. Başlatın
python3 run.py
```

### Manuel Kurulum

```bash
# 1. Bağımlılıkları yükleyin
pip install -r requirements.txt

# 2. Platformu başlatın
python run.py
```

## 📱 Kullanım

### Web Arayüzü
1. Platformu başlattıktan sonra tarayıcınızda `http://localhost:5000` adresine gidin
2. Modern hacking temalı dashboard'u kullanın
3. OSINT araçlarını kategorilere göre filtreleyin
4. Hedef girin ve araçları çalıştırın
5. Sonuçları gerçek zamanlı olarak görüntüleyin

### Terminal Arayüzü
1. Platformu başlattıktan sonra terminal seçeneğini seçin
2. Menüden istediğiniz aracı seçin
3. Hedef bilgisini girin
4. Sonuçları terminalde görüntüleyin

### Komut Satırı
```bash
# Terminal arayüzü
python main.py

# Web arayüzü
python app.py
```

## 🛠️ API Kullanımı

### Araçları Listele
```bash
GET /api/tools
```

### Araç Çalıştır
```bash
POST /api/tools/{tool_id}/run
Content-Type: application/json

{
    "target": "hedef_bilgisi"
}
```

### Sonuçları Getir
```bash
GET /api/results
GET /api/results/{tool_id}
```

## 📁 Proje Yapısı

```
yf-osint-cyber-panel/
├── app.py                          # Flask web uygulaması
├── main.py                         # Terminal arayüzü
├── run.py                          # Ana başlatma dosyası
├── start.bat                       # Windows başlatma scripti
├── requirements.txt                # Python bağımlılıkları
├── templates/                      # HTML template'leri
│   ├── index.html                  # Ana web arayüzü
│   └── terminal.html               # Terminal web arayüzü
├── tools/                          # OSINT araçları
│   ├── person_intelligence.py      # Kişi istihbaratı araçları
│   ├── site_intelligence.py       # Site istihbaratı araçları
│   └── social_media.py            # Sosyal medya araçları
├── utils/                          # Yardımcı modüller
│   ├── encryption.py               # AES şifreleme
│   └── data_manager.py            # Veri yönetimi
└── encrypted_data/                 # Şifreli veri depolama
    ├── person_intelligence/        # Kişi istihbaratı sonuçları
    ├── site_intelligence/          # Site istihbaratı sonuçları
    ├── social_media/               # Sosyal medya sonuçları
    └── reports/                    # Raporlar
```

## 🔧 Geliştirme

### Yeni Araç Ekleme
1. İlgili kategori dosyasına (`tools/` klasöründe) yeni fonksiyon ekleyin
2. `app.py` dosyasındaki `OSINT_TOOLS` sözlüğüne aracı ekleyin
3. `main.py` dosyasındaki `tool_map_by_category` sözlüğüne aracı ekleyin

### Veri Formatı
Tüm araçlar aşağıdaki formatı döndürmelidir:
```python
{
    "tool": "araç_adı",
    "target": "hedef_bilgisi",
    "timestamp": "2025-01-13T23:45:12",
    "result": {
        # Araç sonuçları
    }
}
```

## 🚨 Güvenlik Uyarıları

- Bu platform sadece eğitim ve yasal OSINT amaçları için kullanılmalıdır
- Kullanıcılar, hedefledikleri kişi veya kuruluşlardan gerekli izinleri almalıdır
- Tüm veriler AES-256 ile şifrelenir ve güvenli saklanır
- Platform kullanımından doğacak sorumluluk kullanıcıya aittir

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## 👥 Katkıda Bulunma

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

## 📞 İletişim

- **Geliştirici**: Yazılım Forum İstihbarat Ekibi
- **E-posta**: info@yazilimforum.com
- **Website**: https://yazilimforum.com

## 🙏 Teşekkürler

- Tüm açık kaynak geliştiricilere
- OSINT topluluğuna
- Yazılım Forum üyelerine

---

**⚠️ UYARI**: Bu platform sadece eğitim ve yasal amaçlar için tasarlanmıştır. Kötüye kullanım kesinlikle yasaktır.