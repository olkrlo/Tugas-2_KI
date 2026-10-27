"""
Alice (initiator) - jalankan di perangkat/IP ke-2.

  (1) A -> KDC : IDA || IDB || N1
  (2) KDC -> A : E(Ka,[Ks||IDA||IDB||N1]) || E(Kb,[Ks||IDA])
  (3) A -> B   : E(Kb,[Ks||IDA])
  (4) B -> A   : E(Ks, N2)
  (5) A -> B   : E(Ks, f(N2))      f(N2) = N2 + 1
Setelah langkah 5, Alice & Bob chat dua arah dengan AES memakai Ks.
"""
import socket
import threading

from protocol import (DELIM, ask_key, valid_key, gen_nonce, enc, dec,
                      send_line, log, send_message, chat_receive)

state = {"sock": None, "ks": None}


def handshake(my_id, ka, peer_id, kdc, bob):
    # ---- langkah 1 : ke KDC
    n1 = gen_nonce()
    s = socket.create_connection(kdc, timeout=10)
    f = s.makefile("r")
    msg1 = f"1|{my_id}|{peer_id}|{n1}"
    send_line(s, msg1)
    log("Alice", f"-> KDC  langkah 1 : {msg1}")

    # ---- langkah 2 : dari KDC
    resp = f.readline().strip()
    s.close()
    p = resp.split("|")
    if p[0] != "2":
        raise RuntimeError(f"KDC menolak: {resp}")
    h_a, h_b = p[1], p[2]
    log("Alice", f"<- KDC  langkah 2 : {h_a} || {h_b}")
    ks, ida, idb, n1_back = dec(ka, h_a).split(DELIM)       # hanya bisa dibuka dgn Ka
    if (ida, idb, n1_back) != (my_id, peer_id, n1):
        raise RuntimeError("verifikasi N1/ID gagal (kemungkinan replay)")
    log("Alice", f"   Ks = {ks}  (N1 cocok)")

    # ---- langkah 3 : ke Bob
    b = socket.create_connection(bob, timeout=10)
    bf = b.makefile("r")
    send_line(b, f"3|{h_b}")
    log("Alice", f"-> Bob  langkah 3 : {h_b}")

    # ---- langkah 4 : dari Bob
    l4 = bf.readline().strip().split("|")
    if l4[0] != "4":
        raise RuntimeError("Bob menolak / gagal dekripsi (Kb salah?)")
    n2 = int(dec(ks, l4[1]))
    log("Alice", f"<- Bob  langkah 4 : {l4[1]}  (N2 = {n2})")

    # ---- langkah 5 : ke Bob
    h5 = enc(ks, str(n2 + 1))
    send_line(b, f"5|{h5}")
    log("Alice", f"-> Bob  langkah 5 : {h5}  (f(N2) = {n2 + 1})")
    b.settimeout(None)
    return b, bf, ks


def start(my_id, ka, peer_id, kdc, bob):
    if state["sock"]:
        try:
            state["sock"].close()
        except OSError:
            pass
    sock, rf, ks = handshake(my_id, ka, peer_id, kdc, bob)
    state["sock"], state["ks"] = sock, ks
    threading.Thread(target=chat_receive, args=(rf, ks, peer_id), daemon=True).start()
    print(f"\n=== Terhubung ke {peer_id}. Ketik pesan lalu Enter. "
          f"Perintah: /rekey  /setkey  /quit ===")


if __name__ == "__main__":
    print("=== Alice ===")
    my_id = input("ID saya [alice]: ").strip() or "alice"
    peer_id = input("ID lawan bicara [bob]: ").strip() or "bob"
    ka = ask_key(f"Master key Ka ({my_id}) - harus sama dengan di KDC")
    kdc_host = input("IP KDC: ").strip()
    kdc_port = int(input("Port KDC [5000]: ").strip() or 5000)
    bob_host = input("IP Bob: ").strip()
    bob_port = int(input("Port Bob [5001]: ").strip() or 5001)
    kdc, bob = (kdc_host, kdc_port), (bob_host, bob_port)

    try:
        start(my_id, ka, peer_id, kdc, bob)
    except Exception as e:
        print("Handshake gagal:", e)
        raise SystemExit(1)

    while True:
        try:
            text = input().strip()
        except EOFError:
            break
        if not text:
            continue
        if text == "/quit":
            break
        elif text == "/setkey":
            k = ask_key("Ka baru (jangan lupa 'set' juga di KDC)")
            ka = k
            print("Ka diganti. Jalankan /rekey untuk handshake ulang.")
        elif text == "/rekey":
            try:
                start(my_id, ka, peer_id, kdc, bob)
            except Exception as e:
                print("Handshake gagal:", e)
        else:
            if state["sock"] is None:
                print("Belum ada sesi.")
                continue
            try:
                h = send_message(state["sock"], state["ks"], text)
                print(f"      ciphertext (hex): {h}")
            except OSError:
                print("Koneksi terputus. Coba /rekey.")
