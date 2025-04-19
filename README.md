# 🔒 MITM Defender – ARP Spoof Tespit Aracı

MITM Defender, yerel ağınızdaki cihazları izleyerek ARP spoofing ve Man-in-the-Middle (MITM) saldırılarını tespit eder. Gerçek zamanlı olarak gateway MAC adresi değişimlerini algılar, şüpheli durumları bildirir ve ağınızı daha güvenli hale getirmenize yardımcı olur.

## 🚀 Özellikler

- 🌐 Ağ cihazlarını tarar ve MAC adreslerini analiz eder
- 🛡 Gateway (varsayılan ağ geçidi) MAC adresini sürekli kontrol eder
- 🔔 MAC adresi değişimi tespit edildiğinde Discord webhook veya e-posta ile alarm gönderir
- 🧠 MAC adresinden cihazın üretici bilgisi (vendor) analiz edilir
- 📊 Renkli terminal çıktısı ve kullanıcı dostu arayüz

## ⚙️ Gereksinimler

```bash
pip install -r requirements.txt
```

## ▶️ Kullanım

```bash
python mitmdefender.py
```

## ⚠️ Notlar

- Discord webhook ve/veya SMTP ayarları `mitmdefender.py` içinde düzenlenmelidir.
- Admin/root yetkisi gerekebilir (`sudo python mitmdefender.py`).

## 📁 Dosya Yapısı

```
mitmdefender/
├── mitmdefender.py
├── README.md
├── requirements.txt
└── LICENSE
```

## 📄 Lisans

MIT Lisansı © 2025 Burak BALTA
