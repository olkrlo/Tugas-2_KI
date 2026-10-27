"""
KDC (Key Distribution Center) - jalankan di perangkat/IP ke-1.

Langkah (sesuai slide "Key Distribution Scenario"):
  (1) A -> KDC : IDA || IDB || N1
  (2) KDC -> A : E(Ka, [Ks || IDA || IDB || N1]) || E(Kb, [Ks || IDA])
"""
import socket
import threading

from protocol import DELIM, ask_key, valid_key, gen_session_key, enc, send_line, log

keys = {}                  # {ID: master key}  (Ka, Kb), bisa diubah saat program jalan
lock = threading.Lock()


def handle(conn, addr):
    f = conn.makefile("r")
    try:
        line = f.readline().strip()
        log("KDC", f"<- {addr[0]}  langkah 1 : {line}")
        p = line.split("|")
        if len(p) != 4 or p[0] != "1":
            send_line(conn, "ERR|format salah")
            return
        _, ida, idb, n1 = p
        with lock:
            ka, kb = keys.get(ida), keys.get(idb)
        if ka is None or kb is None:
            send_line(conn, "ERR|ID tidak dikenal")
            log("KDC", f"ID tidak dikenal: {ida} / {idb}")
            return

        ks = gen_session_key()                                  # session key
        h_a = enc(ka, DELIM.join([ks, ida, idb, n1]))           # E(Ka,[Ks||IDA||IDB||N1])
        h_b = enc(kb, DELIM.join([ks, ida]))                    # E(Kb,[Ks||IDA])
        log("KDC", f"   Ks dibuat = {ks}")
        log("KDC", f"   E(Ka,[Ks||IDA||IDB||N1]) = {h_a}")
        log("KDC", f"   E(Kb,[Ks||IDA])          = {h_b}")
        send_line(conn, f"2|{h_a}|{h_b}")
        log("KDC", f"-> {addr[0]}  langkah 2 terkirim")
    except Exception as e:
        log("KDC", f"error: {e}")
    finally:
        conn.close()


def server(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


if __name__ == "__main__":
    print("=== KDC ===")
    ida = input("ID Alice [alice]: ").strip() or "alice"
    keys[ida] = ask_key(f"Master key Ka ({ida})")
    idb = input("ID Bob [bob]: ").strip() or "bob"
    keys[idb] = ask_key(f"Master key Kb ({idb})")
    port = int(input("Port KDC [5000]: ").strip() or 5000)
    threading.Thread(target=server, args=(port,), daemon=True).start()
    log("KDC", f"listen di 0.0.0.0:{port}")
    print("Perintah: set <ID> <key> | list | quit")
    while True:
        try:
            cmd = input().strip().split()
        except EOFError:
            break
        if not cmd:
            continue
        if cmd[0] == "quit":
            break
        elif cmd[0] == "list":
            with lock:
                for k, v in keys.items():
                    print(f"  {k}: {v}")
        elif cmd[0] == "set" and len(cmd) == 3 and valid_key(cmd[2]):
            with lock:
                keys[cmd[1]] = cmd[2]
            print(f"  key {cmd[1]} diubah")
        else:
            print("  perintah tidak dikenal / key tidak valid")
