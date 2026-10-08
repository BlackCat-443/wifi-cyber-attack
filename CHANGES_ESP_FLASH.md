# ESP Flash + UI/UX Fixes

## Flow flashing baru
1. Jalankan dashboard pada komputer yang akan dipakai untuk flashing.
2. Colok ESP8266 via USB.
3. Buka tab **ESP** dan tunggu port seperti `COM3`, `COM5`, `/dev/ttyUSB0`, atau `/dev/ttyACM0` muncul.
4. Pilih port secara manual.
5. Pilih firmware `.bin` atau `.ino`.
6. Pilih board profile bila memakai `.ino`.
7. Klik **Flash Selected Port**.

## Dukungan file
- `.bin`: langsung ditulis menggunakan `esptool`.
- `.ino`: dikompile menggunakan `arduino-cli`, lalu binary hasil compile di-flash otomatis.

> Untuk `.ino`, pastikan `arduino-cli` dan ESP8266 board core sudah terpasang. Jika belum, UI akan menampilkan status dan backend mengembalikan error yang jelas. `.bin` tetap dapat digunakan tanpa Arduino CLI.

## Perbaikan
- Flash sekarang wajib memakai port serial yang benar-benar terdeteksi.
- Validasi ulang port dilakukan di backend untuk mencegah flashing ke port yang sudah dicabut.
- Mencegah dua proses flash berjalan bersamaan.
- Validasi `.bin`/`.ino`, ukuran file, flash address, baud rate, dan board profile.
- Deteksi CH340/CH341, CP210x, FTDI dan descriptor ESP umum.
- Polling USB saat tab ESP dibuka.
- Notifikasi ketika port serial baru muncul.
- Perbaikan colspan tabel device kosong dari 7 menjadi 9.
- Progress state + terminal log ketika compile/flash.
- Tema UI cyber/hacker hijau neon dan grid/scanline dashboard.

## Dependency utama
Python dependencies tetap di `requirements.txt` (`pyserial`, `esptool`, dll.). Untuk compile `.ino`, `arduino-cli` merupakan dependency sistem tambahan.
