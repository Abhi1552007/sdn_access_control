"""
Protected TCP service (D2).

  python3 protected_service.py --name fileserver --port 9000     (on h4, 10.0.0.4)
  python3 protected_service.py --name dbserver   --port 9100     (on h6, 10.0.0.6)

It has no password check of its own: the SDN rules decide who can reach it.
Every connection that arrives is written to logs/access.log.
"""
import argparse
import datetime
import logging
import os
import socket
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(HERE, "logs"), exist_ok=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="fileserver")
    ap.add_argument("--port", type=int, default=9000)
    a = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format=f"%(asctime)s [{a.name}] %(message)s",
        handlers=[logging.FileHandler(os.path.join(HERE, "logs", "access.log")), logging.StreamHandler()],
    )
    log = logging.getLogger(a.name)

    def handle(conn, addr):
        log.info("ACCESS from %s:%s", *addr)
        with conn:
            conn.sendall(f"Welcome to the protected {a.name}.\n".encode())
            data = conn.recv(1024).decode(errors="ignore").strip()
            if data:
                log.info("REQUEST from %s: %s", addr[0], data)
                conn.sendall(f"[{datetime.datetime.now():%H:%M:%S}] {a.name} served: {data}\n".encode())

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", a.port))
    srv.listen(50)
    log.info("%s listening on port %d", a.name, a.port)
    while True:
        c, addr = srv.accept()
        threading.Thread(target=handle, args=(c, addr), daemon=True).start()


if __name__ == "__main__":
    main()
