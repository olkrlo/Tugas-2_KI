# Tugas 2 KI — Key Distribution (KDC, Alice, Bob) dengan AES-128 Manual

Implementasi *Key Distribution Scenario* (Stallings) dengan tiga entitas di tiga IP berbeda.
AES-128 (mode CBC + padding PKCS#7) dan KDC diimplementasikan manual, tanpa library kriptografi.

## File
| File | Fungsi |
|---|---|
| `aes.py` | AES-128 manual: S-box (dibangkitkan di GF(2^8)), key expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey, CBC |
| `protocol.py` | Helper bersama: konversi ASCII↔hex, generator nonce & session key, kirim/terima baris |
| `kdc.py` | KDC: menyimpan master key Ka/Kb, membuat session key Ks |
| `alice.py` | Initiator: langkah 1, 3, 5, lalu chat |
| `bob.py` | Responder: langkah 4, lalu chat |

## Protokol
```
(1) A -> KDC : IDA || IDB || N1
(2) KDC -> A : E(Ka,[Ks||IDA||IDB||N1]) || E(Kb,[Ks||IDA])
(3) A -> B   : E(Kb,[Ks||IDA])
(4) B -> A   : E(Ks, N2)
(5) A -> B   : E(Ks, f(N2))        f(N2) = N2 + 1
```
Setelah langkah 5, Alice dan Bob bertukar pesan dua arah: `MSG|<hex E(Ks, pesan)>`.

## Cara menjalankan (3 perangkat dalam satu jaringan)
1. Perangkat 1 (KDC): `python kdc.py` → isi ID & master key (16 karakter ASCII) Alice dan Bob, port 5000.
2. Perangkat 3 (Bob): `python bob.py` → isi Kb (sama dengan di KDC), port 5001.
3. Perangkat 2 (Alice): `python alice.py` → isi Ka, IP KDC, IP Bob.
4. Ketik pesan di Alice atau Bob; ciphertext hex ditampilkan.

Perintah interaktif: `/rekey` (handshake ulang, Ks baru), `/setkey` (ganti master key), `/quit`.
Di KDC: `set <ID> <key>`, `list`, `quit`.

## Wireshark
Filter: `tcp.port == 5000 || tcp.port == 5001` lalu *Follow → TCP Stream*.
Langkah 1 terlihat plaintext (ID dan nonce), langkah 2–5 dan semua pesan chat berupa hex.
