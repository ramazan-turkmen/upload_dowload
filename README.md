# upload_dowload
"Bu proje, paramiko kütüphanesiyle SSH üzerinden dosya yükleme (upload) ve indirme (download) işlemlerini otomatize eder. Kullanıcı dostu arayüzüyle lokal ve uzak sunucular arasında güvenli veri transferi sağlar."

# 🚀 SSH Dosya Transfer Uygulaması

**SSH/SFTP protokolü ile güvenli dosya transferi için modern grafik arayüzlü uygulama**


## 🌟 Öne Çıkan Özellikler

- ✔️ **Güvenli bağlantı** - SSH/SFTP ile şifreli dosya transferi
- ✔️ **Kullanıcı dostu arayüz** - Kolay kullanım için modern GUI
- ✔️ **Çoklu dosya işlemleri** - Toplu yükleme/indirme desteği
- ✔️ **Sunucu tarayıcı** - Uzak sunucudaki dosyaları görüntüleme
- ✔️ **Toplu işlem** - Birden fazla sunucuya aynı anda dosya yükleme
- ✔️ **İşlem takibi** - Gerçek zamanlı ilerleme çubuğu ve log kaydı

## 📦 Kurulum

### Ön Gereksinimler
pip install paramiko colorama


### Uygulamayı Çalıştırma

git clone https://github.com/ramazan-turkmen/upload_dowload
cd ssh-file-transfer
python ssh_transfer.py


## 🖥️ Ekran Görüntüleri
![dosya_transfer](https://github.com/user-attachments/assets/576f4b46-4b5a-46b5-b934-a93d19d2d0c5)

*Uygulamanın ana arayüzü - Bağlantı ve dosya transfer paneli*

## 🛠️ Kullanım Kılavuzu

### 1. Sunucu Bağlantısı
- **Host IP:** Sunucu IP adresi
- **Kullanıcı Adı:** SSH kullanıcı bilgisi
- **Şifre:** Kullanıcı şifresi (güvenliği için göster/gizle butonu mevcut)

### 2. Dosya Yükleme (Upload)
- **Yerel Dosyalar:** Bilgisayarınızdan yüklenecek dosyaları seçin
- **Uzak Dizin:** Sunucuda dosyaların kaydedileceği klasör
- **IP Listesi:** Aynı dosyaları birden fazla sunucuya yüklemek için IP listesi

### 3. Dosya İndirme (Download)
- **Uzak Dizin:** Sunucudan indirilecek dosyaların bulunduğu klasör
- **Yerel Dizin:** İndirilen dosyaların kaydedileceği bilgisayar konumu

### 4. Dosya Yöneticisi
- Çift tıklayarak klasörlere girebilir
- Üst dizine çıkmak için "Up" butonunu kullanabilir
- Dosya bilgileri (boyut, tür, değiştirilme tarihi) görüntülenir

## 📝 Önemli Notlar

- Bağlantı bilgileriniz yerel olarak `ssh_transfer_config.json` dosyasında saklanır
- IP listelerini kaydetmek/yüklemek için "Save IPs/Load IPs" butonlarını kullanabilirsiniz
- Uzun süren işlemleri "Cancel" butonu ile iptal edebilirsiniz

## 🤝 Katkıda Bulunma

Hata bildirimi veya özellik önerileri için **Issue** açabilir veya **Pull Request** gönderebilirsiniz.

## 📜 Lisans

Bu proje MIT lisansı altında dağıtılmaktadır. Detaylar için [LICENSE](LICENSE) dosyasını inceleyin.

---

**✉️ İletişim:** [https://www.linkedin.com/in/ramazan-türkmen01/]  
**🌍 GitHub:** [github.com/ramazan-turkmen](https://github.com/ramazan-turkmen)  
**📅 Son Güncelleme:** 04 Temmuz 2025
