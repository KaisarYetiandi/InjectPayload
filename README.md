# 🧪 InjectPayload v1.2

> 🔥 Powerful Payload Injector for Reverse Shell, Metasploit, and Ransomware  
> 🧠 Coded by: [Emperor_Yetiandi](https://github.com/KaisarYetiandi)

---

## 📌 Deskripsi

**InjectPayload** adalah tool Python serbaguna yang digunakan untuk menyisipkan berbagai jenis payload secara otomatis ke dalam file `.VBS` dan `.PY`. Tool ini mendukung Reverse Shell (Netcat), Payload Metasploit (Meterpreter), dan Ransomware (AES+RSA).

Tujuan utama proyek ini adalah untuk **edukasi, ethical hacking, penetration testing**, dan demonstrasi teknik **stealth injection** serta **payload obfuscation**.

---

## 🚀 Fitur Unggulan

| Fitur | Deskripsi |
|-------|-----------|
| 🔁 Reverse Shell VBS | Membuat file `.vbs` reverse shell (Netcat listener) |
| 🧬 Metode Obfuscation | Mendukung `Chr()` obfuscation dan Base64 (UTF-16LE) |
| 💉 Inject Payload Metasploit | Menyisipkan payload `python/meterpreter/reverse_tcp` ke dalam file `.py` |
| 🛡️ Inject Payload Ransomware | Payload enkripsi AES-RSA untuk ransomware |
| 🧵 Multithreading | Payload berjalan di background tanpa mengganggu kode asli |
| 👻 Stealth Mode | Semua payload berjalan tersembunyi (tanpa membuka jendela CMD) |

---

## ⚠️ Disclaimer

> 🔒 Tool ini dibuat untuk tujuan **EDUKASI dan PENGETESAN KEAMANAN**.  
> ❌ **Dilarang digunakan untuk aktivitas ilegal atau menyerang sistem tanpa izin tertulis**.  
> 🧨 **Ransomware yang dihasilkan benar-benar mengenkripsi file. Gunakan dengan bijak. dan aing tidak akan bertanggung jawab bila terjadi sesuatu yang tidak diinginkan**

---

## 🛠️ Instalasi

### 1. Clone Repository

```bash
git clone https://github.com/KaisarYetiandi/InjectPayload.git
```
Masuk ke folder

```
cd InjectPayload
```
Menjalankan Tool

```
python3 Injection.py
```
