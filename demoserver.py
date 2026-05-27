#!/usr/bin/env python3

import argparse
import logging
import re
import socket
import threading

from framing import Mapi, ResultSet
from handshake import Handshake


def parse_sockaddr(s):
    try:
        n = int(s, 10)
        return ("localhost", n)
    except ValueError:
        host, port = s.rsplit(":", 1)
        port = int(port)
        return (host, port)


argparser = argparse.ArgumentParser()
argparser.add_argument(
    "listen_addr",
    type=parse_sockaddr,
    nargs="?",
    default="50000",
    help="[Host:]port to listen on, default is 50000",
)


def main(args):
    addrspec = args.listen_addr
    listen_socks = []
    for a in socket.getaddrinfo(
        host=addrspec[0], port=addrspec[1], type=socket.SOCK_STREAM
    ):
        if a[0] in [socket.AF_INET, socket.AF_INET6]:
            sock = socket.create_server(address=a[4], family=a[0])
            logging.info(f"Listening on {sock.getsockname()}")
            listen_socks.append(sock)
    threads = [
        threading.Thread(target=accept_connections, args=(sock, args))
        for sock in listen_socks
    ]
    for th in threads:
        th.start()


def accept_connections(listen_sock: socket.socket, args):
    while True:
        sock, peer = listen_sock.accept()
        id = pick_connection_id()
        logging.info(f"{id}: Incoming connection from {peer}")
        th = threading.Thread(target=handle_connection, args=(sock, id, args))
        th.start()


def handle_connection(sock: socket.socket, id: str, args):
    try:
        conn = Mapi(sock, id)
        hs = Handshake(conn, args)
        if hs.execute():
            interact(conn, hs)
    finally:
        logging.info(f"{id}: Closing")
        try:
            sock.close()
        except IOError:
            pass


def interact(conn: Mapi, hs: Handshake):
    while True:
        msg = conn.receive()
        if msg is None:
            return
        if msg.startswith("Xclientinfo "):
            conn.send("")
            continue
        if msg.startswith("s") and interact_sql(conn, hs, msg[1:].strip(" \t\n;")):
            # interact_sql has handled it
            continue

        conn.send(f"!This is the demo server, cannot handle message: {msg}")
        return


def interact_sql(conn: Mapi, hs: Handshake, sql: str) -> bool:
    m = re.match(
        '^SELECT "?name"?, "?value"? FROM "?sys"?."?env"?\\(\\)(?: AS env) WHERE name IN \\(([a-z_\', ]*)\\)$',
        sql,
        re.I,
    )
    if m:
        requested = set(n.strip().strip("'") for n in m.group(1).split(","))
        rs = ResultSet(".env", name="varchar", value="varchar")
        if "gdk_dbname" in requested:
            rs.add(name="gdk_dbname", value=hs.dbname)
        if "revision" in requested:
            rs.add(name="revision", value="Unknown")
        if "monet_version" in requested:
            rs.add(name="monet_version", value="56.0.0")
        if "monet_release" in requested:
            rs.add(name="monet_release", value="Unknown")
        conn.send(rs.render())
        return True

    m = re.match(
        """^SELECT "name", "value" FROM "sys"."env"\\(\\) WHERE "name" IN \\(([a-z_', ]*)\\) UNION SELECT 'current_user' as "name", current_user as "value"$""",
        sql,
        re.I,
    )
    if m:
        requested = set(n.strip().strip("'") for n in m.group(1).split(","))
        rs = ResultSet(".env", name="varchar", value="varchar")
        if "gdk_dbname" in requested:
            rs.add(name="gdk_dbname", value=hs.dbname)
        if "revision" in requested:
            rs.add(name="revision", value="Unknown")
        if "monet_version" in requested:
            rs.add(name="monet_version", value="56.0.0")
        if "monet_release" in requested:
            rs.add(name="monet_release", value="Unknown")
        if "max_clients" in requested:
            rs.add(name="max_clients", value="64")
        if "monet_release" in requested:
            rs.add(name="raw_strings", value="false")
        rs.add(name="current_user", value=hs.user)
        conn.send(rs.render())
        return True

    if sql.lower() == "select current_schema":
        rs = ResultSet(".%2", **{ "%2": "varchar"})
        rs.add(**{"%2": "sys"})
        conn.send(rs.render())
        return True

    return False


def pick_connection_id() -> str:
    global connection_id_lock, connection_id_counter
    with connection_id_lock:
        id = connection_id_counter
        connection_id_counter += 1
        return f"#{id}"


connection_id_lock = threading.Lock()
connection_id_counter = 10


if __name__ == "__main__":
    args = argparser.parse_args()
    logging.basicConfig(level=logging.DEBUG)
    logging.debug(args)
    main(args)
