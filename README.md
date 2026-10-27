# Tugas 2 Keamanan Informasi - Key Distribution (KDC, Alice, Bob)

| NRP | Nama |
|------|--------|
| 5025231206 | Nadine Aulia Putri Fanani |
| 5025231301 | Nona Auliya Wijaya |

## Deskripsi
Program simulasi distribusi kunci dengan KDC. Ada tiga entitas (KDC, Alice, Bob)
yang jalan di tiga IP berbeda. Setelah handshake 5 langkah, Alice dan Bob bisa
chat dua arah, pesannya dienkripsi pakai AES-128 yang ditulis manual (tanpa
library kriptografi).

## Alur protokol
1. Alice -> KDC : IDA || IDB || N1
2. KDC -> Alice : E(Ka, [Ks || IDA || IDB || N1]) || E(Kb, [Ks || IDA])
3. Alice -> Bob : E(Kb, [Ks || IDA])
4. Bob -> Alice : E(Ks, N2)
5. Alice -> Bob : E(Ks, N2 + 1)

Setelah langkah 5, pesan dikirim dalam bentuk hex hasil AES dengan kunci Ks.

## Struktur file
- aes.py      : implementasi AES-128 (mode CBC + padding)
- protocol.py : fungsi bantu (ASCII <-> hex, nonce, session key, kirim data)
- kdc.py      : program KDC
- alice.py    : program Alice
- bob.py      : program Bob

## Cara menjalankan
Butuh Python 3, tanpa install library tambahan.

1. Di perangkat 1: `python kdc.py`, isi ID dan master key (16 karakter ASCII) untuk Alice dan Bob.
2. Di perangkat 2: `python bob.py`, isi Kb (sama dengan di KDC).
3. Di perangkat 3: `python alice.py`, isi Ka, IP KDC, dan IP Bob.
4. Ketik pesan lalu Enter. Ciphertext (hex) tampil di kedua sisi.

Port default: KDC 5000, Bob 5001.

Perintah saat program jalan:
- Alice: `/rekey` (handshake ulang), `/setkey` (ganti Ka), `/quit`
- Bob: `/setkey` (ganti Kb), `/quit`
- KDC: `set <ID> <key>`, `list`, `quit`

## Wireshark
Filter: `tcp.port == 5000 || tcp.port == 5001`, lalu Follow TCP Stream.

## Catatan
- Key harus 16 karakter ASCII dan tidak di-hardcode (diinput saat program jalan).
- Session key dibuat acak oleh KDC setiap handshake.
