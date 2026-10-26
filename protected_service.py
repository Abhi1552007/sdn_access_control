"""
Protected TCP service (runs on h4, 10.0.0.4:9000).

It has no password check of its own: the network decides who can reach it.
If the SDN controller has not granted a flow rule, packets never arrive here.
Every connection that does arrive is written to logs/access.log.
"""
import socket
import threading
import logging
import os
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(HERE, "logs"), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [access] %(message)s",
    handlers=[logging.FileHandler(os.path.join(HERE, "logs", "access.log")), logging.StreamHandler()],
)
log = logging.getLogger("access")


def handle(conn, addr):
    log.info("ACCESS from %s:%s", *addr)
    with conn:
        conn.sendall(b"Welcome to the protected file server.\n")
        data = conn.recv(1024).decode(errors="ignore").strip()
        if data:
            log.info("REQUEST from %s: %s", addr[0], data)
            conn.sendall(f"[{datetime.datetime.now():%H:%M:%S}] You asked for: {data}\n".encode())


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 9000))
    srv.listen(20)
    log.info("Protected service listening on port 9000")
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


if __name__ == "__main__":
    main()
