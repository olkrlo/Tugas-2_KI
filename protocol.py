"""Fungsi bersama untuk KDC, Alice, dan Bob."""
import secrets
import string

import aes

DELIM = "||"          # pemisah field di dalam plaintext (sesuai notasi slide: ||)
KEY_LEN = 16          # AES-128 -> key 16 karakter ASCII


# ------------------------------------------------------------------ key
def valid_key(k):
    return len(k) == KEY_LEN and all(32 <= ord(c) < 127 for c in k) and "|" not in k


def ask_key(prompt):
    """Minta key dari user (tidak di-hardcode)."""
    while True:
        k = input(f"{prompt} ({KEY_LEN} karakter ASCII): ").strip()
        if valid_key(k):
            return k
        print(f"  Key harus tepat {KEY_LEN} karakter ASCII yang tercetak dan tanpa '|'.")


def gen_session_key():
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(KEY_LEN))


def gen_nonce():
    return str(secrets.randbelow(10 ** 8))


# -------------------------------------------------------- enkripsi (ASCII<->hex)
def enc(key, text):
    """key: str ASCII, text: str ASCII -> ciphertext hex (IV + C)."""
    return aes.encrypt(text.encode("ascii"), key.encode("ascii")).hex()


def dec(key, hex_text):
    """Kebalikan enc(). Raise ValueError bila key salah / data rusak."""
    try:
        return aes.decrypt(bytes.fromhex(hex_text), key.encode("ascii")).decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("hasil dekripsi bukan ASCII (key salah?)")


# ---------------------------------------------------------------- jaringan
def send_line(sock, line):
    sock.sendall((line + "\n").encode("ascii"))


def log(tag, msg):
    print(f"[{tag}] {msg}", flush=True)


# ------------------------------------------------------------------- chat
def send_message(sock, ks, text):
    h = enc(ks, text)
    send_line(sock, "MSG|" + h)
    return h


def chat_receive(rfile, ks, peer):
    """Baca pesan terenkripsi dari peer sampai koneksi putus."""
    try:
        for line in rfile:
            line = line.strip()
            if not line.startswith("MSG|"):
                continue
            h = line[4:]
            try:
                pt = dec(ks, h)
            except ValueError:
                print(f"\n[!] pesan dari {peer} gagal didekripsi", flush=True)
                continue
            print(f"\n[{peer}] {pt}\n      ciphertext (hex): {h}", flush=True)
    except (OSError, ValueError):
        pass
