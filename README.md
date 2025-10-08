# YF OSINT - Gelişmiş Açık Kaynak İstihbarat Platformu

![YF OSINT Banner](https://i.hizliresim.com/sffy2p3.png)

**YF OSINT**, siber güvenlik uzmanları, araştırmacılar ve meraklılar için tasarlanmış, 70'ten fazla güçlü aracı tek bir çatı altında toplayan modern ve esnek bir açık kaynak istihbarat platformudur. Hem komut satırı (CLI) hem de kullanıcı dostu bir web arayüzü sunarak analiz süreçlerinizi kolaylaştırır ve hızlandırır.

---

## ✨ Öne Çıkan Özellikler

- **Geniş Araç Yelpazesi**: Kişi, site, sosyal medya ve görsel analizi gibi farklı kategorilerde 70'ten fazla OSINT aracı.
- **Çift Arayüz Desteği**: Hem geleneksel **komut satırı (CLI)** hem de modern ve interaktif bir **web panosu** ile kullanım imkanı.
- **Güvenli Veri Yönetimi**: Analiz sonuçlarını AES-256 şifreleme ile güvenli bir şekilde saklama ve yönetme.
- **Modüler ve Genişletilebilir**: Yeni araçların ve modüllerin kolayca entegre edilebileceği esnek bir mimari.
- **Otomatik Bağımlılık Yönetimi**: Gerekli Python kütüphanelerini otomatik olarak tespit eder ve kurar.
- **Kullanıcı Dostu Tasarım**: Renkli ve düzenli terminal çıktıları, modern ve duyarlı web arayüzü.

## 🛠️ Araç Kategorileri

Platform, analiz yeteneklerini beş ana kategoriye ayırır:

1.  **Kişi İstihbaratı**: E-posta sızıntı kontrolü, telefon numarası analizi, kullanıcı adı arama, IP ve alan adı analizi gibi araçlarla kişiler hakkında bilgi toplayın.
2.  **Site İstihbaratı**: Subdomain tarama, port analizi, web teknolojisi tespiti ve temel zafiyet testleri ile web sitelerini derinlemesine inceleyin.
3.  **Sosyal Medya Analizi**: Twitter/X, Instagram, LinkedIn gibi popüler platformlardaki profilleri ve aktiviteleri analiz edin.
4.  **Medya/Görsel Analizi**: Görsellerdeki EXIF ve metadata verilerini çıkarın, tersine görsel arama yapın ve görseller hakkında detaylı bilgi edinin.
5.  **Yardımcı Araçlar**: Hash hesaplama, Base64/URL/Hex kodlama-çözme ve QR kod/barkod işlemleri gibi günlük görevleri hızlandıran pratik araçlar.

## 🚀 Kurulum ve Başlatma

Proje, tek bir Python betiği ve standart kütüphaneler ile çalışacak şekilde tasarlanmıştır.

### 1. Gereksinimler

- **Python 3.8+**
- `pip` (Python paket yöneticisi)

### 2. Projeyi İndirme

Projeyi bilgisayarınıza klonlayın veya ZIP olarak indirin:

```bash
git clone https://github.com/kullanici-adiniz/yf-osint.git
cd yf-osint
```

### 3. Bağımlılıkları Yükleme

Proje, ilk çalıştırıldığında eksik olan temel bağımlılıkları (`requests`, `cryptography` vb.) otomatik olarak yüklemeye çalışacaktır. Ancak, tüm özellikleri (özellikle web panosunu) sorunsuz kullanmak için gerekli paketleri manuel olarak yüklemeniz önerilir.

Proje ana dizininde bir `requirements.txt` dosyası oluşturup aşağıdaki içeriği ekleyin:

```txt
requests
Flask
beautifulsoup4
dnspython
cryptography
Pillow
qrcode
python-barcode
pyzbar
opencv-python
```

Ardından bu paketleri yükleyin:

```bash
pip install -r requirements.txt
```

### 4. Projeyi Çalıştırma

Projenin ana giriş noktası `main.py` dosyasıdır. Bu dosya, platformu başlatır.

**Web Arayüzünü Başlatmak İçin:**

Aşağıdaki komut ile web sunucusunu başlatabilirsiniz. Sunucu varsayılan olarak `http://127.0.0.1:5000` adresinde çalışacaktır.

```bash
python main.py
```

Tarayıcınızda `http://127.0.0.1:5000` adresini açarak web panosuna erişebilirsiniz.

*(Not: Eğer projenizde `main.py` dosyası yoksa, aşağıdaki kodlarla `main.py` adında bir dosya oluşturun.)*

```python
# main.py
from yf_osint.platform import YFOSINTPlatform

def main():
    """Platformu başlatır."""
    try:
        platform = YFOSINTPlatform()
        # Web arayüzünü başlatmak için run() metodunu çağırın.
        # open_browser=True tarayıcıyı otomatik açar.
        platform.run(host="127.0.0.1", port=5000, debug=False, open_browser=True)
    except ImportError as e:
        print(f"Hata: Gerekli bir modül eksik: {e}")
        print("Lütfen 'pip install -r requirements.txt' komutu ile bağımlılıkları yükleyin.")
    except Exception as e:
        print(f"Platform başlatılırken bir hata oluştu: {e}")

if __name__ == "__main__":
    main()
```

## ⚖️ Yasal Uyarı

Bu araç, yalnızca **eğitim ve araştırma amaçlı** geliştirilmiştir. Araçların kullanımıyla elde edilen bilgilerin kötüye kullanılması, yasa dışı faaliyetlerde bulunulması veya kişilerin gizliliğinin ihlal edilmesi kesinlikle amaçlanmamıştır.

- Araçları kullanırken yerel ve uluslararası yasalara uymak tamamen **kullanıcının sorumluluğundadır**.
- Başkalarının sistemlerine veya özel bilgilerine izinsiz erişim sağlamak yasa dışıdır.
- Geliştiriciler, bu aracın kullanımından kaynaklanabilecek doğrudan veya dolaylı hiçbir hasar, veri kaybı veya yasal sorundan sorumlu tutulamaz.

Bu platformu kullanarak yukarıdaki şartları kabul etmiş sayılırsınız. Lütfen sorumlu bir şekilde kullanın.

## 🤝 Katkıda Bulunma

Katkılarınız projeyi daha iyi hale getirecektir! Hata bildirimleri, yeni özellik önerileri veya kod katkıları için lütfen bir "Issue" açın veya "Pull Request" gönderin.

---

*Yazılım Forum İstihbarat Ekibi Tarafından Geliştirilmiştir.*
