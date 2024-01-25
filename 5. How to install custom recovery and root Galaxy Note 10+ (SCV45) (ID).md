#  GUIDE TO INSTALL (TWRP - MAGISK ON SCV45)
## ini adalah panduan untuk melakukan instalasi twrp dan magisk di SCV45

Specs dari Galaxy SCV45 (Samsung Galaxy Note 10+ Snapdragon version nama kode "d2q")

|Fitur| Deskripsi| 
|----------------|-----------------------------------------------------------------------------------------|
|PLATFORM	OS    |Android 9.0 (Pie), upgradable to Android 12, One UI 4
|Chipset	        |Qualcomm SM8150 Snapdragon 855 (7 nm) - USA/China
|                |Octa-core (1x2.84 GHz Kryo 485 & 3x2.42 GHz Kryo 485 & 4x1.78 GHz Kryo 485) - USA/China
|GPU	            |Adreno 640 - USA/China
|MEMORY Internal |256GB 12GB RAM - UFS 3.0
|SD Card         |Yes 
|SIMCARD         |Single Slot


------------------------------------------------------------------------------------------------------------
## Apa yang bisa dilakukan :

1. Install TWRP untuk _flash rom custom_
2. Install Magisk untuk _root-ing_

## Apa yang perlu disiapkan dan bagaimana ?
1. Buka / Unlock Developer mode :
   
   ![samsung-note-10-usb-debugging](https://github.com/z3rg/TWRP-MAGISK-SCV45/assets/3973856/9d1fe0d5-e886-426c-8388-02539e5adb4d)
   
2. Unlock OEM Bootloader (membutuhkan koneksi wifi jika ponsel baru di _factory reset_ untuk menu tersebut muncul) :
   
   ![image](https://github.com/z3rg/TWRP-MAGISK-SCV45/assets/3973856/d50302be-0d74-42dd-ba06-0a2f3d67594c)

3. Lalu matikan Ponsel dan jika sudah mati total tekan tombol power + vol up + vol down secara bersamaan untuk masuk menu download maka akan muncul pesan seperti ini untuk pertama kali :
   
   ![image](https://github.com/z3rg/TWRP-MAGISK-SCV45/assets/3973856/ab4aa628-aa51-46ec-9377-f24c6cabc3ea)

4. Jika sudah masuk mode download buka aplikasi odin ( hampir semua yang dibutuhkan akan di upload di repo ini ) :

   ![image](https://github.com/z3rg/TWRP-MAGISK-SCV45/assets/3973856/e3c22813-830c-42ee-b5c9-89f142ba65a9)
   
6. (_Optional_) Jika ingin merubah firmware versi jepang / SCV45 (d2q) ke USA Unlocked / SM-N975U1 (d2qui)

7. (_Optional_) Update AP file dengan milik SM-N975U1 (extract file zip yang 6GB an untuk mendapatkan file AP-nya) >> Link [http:____](https://drive.google.com/drive/folders/1nkPuogX9VF5LooWhmuBdaENANV1BhtrN?usp=sharing)

   ![image](https://github.com/z3rg/TWRP-MAGISK-SCV45/assets/3973856/60645021-e3d9-4c29-8281-8d51f8edac2c)

8. Clone semua file dari repo ini dan masukan file bernama twrp-3.7.0_9-0-d2q.img.tar serta klik start sampai pesan menjadi hijau dan bertuliskan PASS
   
   ![image](https://github.com/z3rg/TWRP-MAGISK-SCV45/assets/3973856/5c9cdf0d-9883-41f4-83d7-5e616a6f438e)

9. Pastikan jangan mencentang pilihan "option > auto reboot"
10. Lalu keluar dari menu Download mode dengan tekan vol down + power
11. Setelah reboot akan ada beberapa notifikasi yang harus dikonfirmasi, untuk itu pada notifikasi pertama tekan power untuk konfirmasi ok , setelah itu masuk ke recovery mode dengan menekan tombol vol up + power
12. Setelah itu pada recovery lakukan wipe data

![Format-Data-in-TWRP-on-Samsung-Galaxy-Note-10-Plus](https://github.com/z3rg/TWRP-MAGISK-SCV45/assets/3973856/12837986-f24f-49e0-a887-dbc7773a91f3)

14. Berikut adalah cara install multidisabler-12.zip (multidisabler ini berlaku untuk Android 12) >> file ini membuat recovery mode twrp menjadi imun untuk di kembalikan dan di lakukan reset oleh file recovery Bawaan

![Install-Multi-Disabler-on-Samsung-Galaxy-Note-10-Plus](https://github.com/z3rg/TWRP-MAGISK-SCV45/assets/3973856/b49d2c5e-07a3-4392-a374-238664d3790f)

14. Setelah itu lakukan install flash zip twrp , file ada pada [http:____](https://drive.google.com/drive/folders/1nkPuogX9VF5LooWhmuBdaENANV1BhtrN?

![magisk-zip](https://github.com/z3rg/TWRP-MAGISK-SCV45/assets/3973856/b4a3cfea-c353-4781-a151-b719b1a1b9fb)

15. Setelah melakukan langkah 14 kembali kemenu reboot dan pilih reboot system
16. Tunggu beberapa saat, Setelah masuk ke dalam android silahkan setup dan lakukan penginstallan Magisk.apk
17. Jika semua lancar maka command su/root dapat diverifikasi oleh aplikasi root checker

![image](https://github.com/z3rg/TWRP-MAGISK-SCV45/assets/3973856/4200ae08-32de-4b92-96ca-b7a05e0d40b2)

Demikian cara dan tools yang dapat saya share untuk rooting dan ubah Firmware untuk SCV45

## Terima Kasih / Thank You







