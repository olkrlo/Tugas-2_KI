"""
Bob (responder) - jalankan di perangkat/IP ke-3. Bob hanya tahu Kb (master key
bersama KDC), Ks didapat dari langkah 3.

  (3) A -> B : E(Kb,[Ks||IDA])
  (4) B -> A : E(Ks, N2)
  (5) A -> B : E(Ks, f(N2))
"""
import socket
import threading

from protocol import (DELIM, ask_key, gen_nonce, enc, dec, send_line, log,
                      send_message, chat_receive)

kb = None
session = {"conn": None, "ks": None, "peer": None}
lock = threading.Lock()


def handle(conn, addr):
    f = conn.makefile("r")
    try:
        # ---- langkah 3
        p = f.readline().strip().split("|")
        if len(p) != 2 or p[0] != "3":
            conn.close()
            return
        log("Bob", f"<- {addr[0]}  langkah 3 : {p[1]}")
        try:
            ks, ida = dec(kb, p[1]).split(DELIM)
        except Exception:
            log("Bob", "dekripsi langkah 3 GAGAL (Kb salah?)")
            send_line(conn, "ERR|dekripsi gagal")
            conn.close()
            return
        log("Bob", f"   Ks = {ks}, lawan = {ida}")

        # ---- langkah 4
        n2 = gen_nonce()
        h4 = enc(ks, n2)
        send_line(conn, f"4|{h4}")
        log("Bob", f"-> {ida}  langkah 4 : {h4}  (N2 = {n2})")

        # ---- langkah 5
        p5 = f.readline().strip().split("|")
        if p5[0] != "5" or int(dec(ks, p5[1])) != int(n2) + 1:
            log("Bob", "verifikasi langkah 5 GAGAL")
            conn.close()
            return
        log("Bob", f"<- {ida}  langkah 5 : {p5[1]}  (f(N2) cocok -> autentikasi OK)")
    except Exception as e:
        log("Bob", f"handshake error: {e}")
        conn.close()
        return

    with lock:
        old = session["conn"]
        session.update(conn=conn, ks=ks, peer=ida)
    if old:
        try:
            old.close()
        except OSError:
            pass
    print(f"\n=== Sesi dengan {ida} aktif. Ketik pesan lalu Enter. "
          f"Perintah: /setkey /quit ===")
    chat_receive(f, ks, ida)
    with lock:
        if session["conn"] is conn:
            session.update(conn=None, ks=None, peer=None)
            print("\n[Bob] koneksi dengan lawan bicara terputus.")


def server(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


if __name__ == "__main__":
    print("=== Bob ===")
    kb = ask_key("Master key Kb (harus sama dengan di KDC)")
    port = int(input("Port Bob [5001]: ").strip() or 5001)
    threading.Thread(target=server, args=(port,), daemon=True).start()
    log("Bob", f"listen di 0.0.0.0:{port}, menunggu Alice...")

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
            kb = ask_key("Kb baru (jangan lupa 'set' juga di KDC)")
            print("Kb diganti, berlaku untuk handshake berikutnya.")
        else:
            with lock:
                conn, ks = session["conn"], session["ks"]
            if conn is None:
                print("Belum ada sesi.")
                continue
            try:
                h = send_message(conn, ks, text)
                print(f"      ciphertext (hex): {h}")
            except OSError:
                print("Koneksi terputus.")
