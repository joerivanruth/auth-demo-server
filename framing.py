from collections.abc import Buffer
import contextlib
from io import StringIO
import logging
import socket
import struct
from typing import Dict, Optional, Union


class Mapi:
    sock: socket.socket
    id: str
    CHUNK_SIZE = 8190

    def __init__(self, sock: socket.socket, id: str):
        self.sock = sock
        self.id = id

    def send(self, msg: Union[str | Buffer]):
        msg = memoryview(bytes(msg, "utf-8") if isinstance(msg, str) else msg)
        logging.debug(f"{self.id}: SEND {bytes(msg)}")

        for i in range(0, len(msg) or 1, self.CHUNK_SIZE):
            start = i * self.CHUNK_SIZE
            end = start + self.CHUNK_SIZE
            chunk = msg[start:end]
            is_last = end >= len(msg)
            header = struct.pack("<H", 2 * len(chunk) + int(is_last))
            self.sock.sendall(header)
            self.sock.sendall(chunk)

    def receive_binary(self) -> Optional[bytes]:
        """Read a message from the socket and return it, or None if socket closed at a block boundary"""

        parts = []
        header = self._recvbytes(2, True)
        if not header:
            logging.debug(f"{self.id}: Peer gracefully closed the connection")
            return None
        while True:
            n = struct.unpack("<H", header)[0]
            nbytes = n // 2
            is_last = n & 1
            parts.append(self._recvbytes(nbytes, False))
            if is_last:
                break
            header = self._recvbytes(2, False)
        msg = b"".join(parts)
        logging.debug(f"{self.id}: RECV {msg!r}")
        return msg

    def receive(self) -> Optional[str]:
        msg = self.receive_binary()
        if msg is None:
            return None
        return str(msg, "utf-8")

    def shutdown(self):
        self.sock.shutdown(socket.SHUT_WR)

    def close(self):
        self.sock.close()

    def _recvbytes(self, nbytes: int, eof_allowed: bool) -> bytes:
        """Try to read exactly nbytes.

        Raise EOFError if not all bytes can be read, unless
        eof_allowed is True and no bytes have been read yet.
        In that case, an empty buffer is returned.
        """

        msg = b""
        while len(msg) < nbytes:
            more = self.sock.recv(nbytes - len(msg))
            if not more:
                if eof_allowed and not msg:
                    return msg
                else:
                    raise EOFError("Message ended halfway a message")
            msg += more
        return msg


class ResultSet:
    result_id: int
    col_idx: Dict[str, int]
    table_name: str
    column_names: list[str]
    column_types: list[str]
    column_widths: list[int]
    rows: list[list[str]]

    def __init__(self, table_name, result_id=0, /, **coldescs):
        self.result_id = result_id
        self.col_idx = dict()
        self.table_name = table_name
        self.column_names = []
        self.column_types = []
        self.column_widths = []
        self.rows = []
        for colname, coltype in coldescs.items():
            self.col_idx[colname] = len(self.column_names)
            self.column_names.append(colname)
            self.column_types.append(coltype)
            self.column_widths.append(0)

    def add(self, /, **colvalues):
        row: list[str] = ["null"] * len(self.column_names)
        for col, value in colvalues.items():
            width = None
            escaped_value: str
            if isinstance(value, str):
                width = len(value)
                value = (
                    value.replace("\\", "\\\\")
                    .replace("\n", "\\\n")
                    .replace("\t", "\\\t")
                    .replace('"', '\\"')
                )
                escaped_value = f'"{value}"'
            else:
                escaped_value = str(value)
                width = len(escaped_value)
            idx = self.col_idx[col]
            row[idx] = escaped_value
            self.column_widths[idx] = max(self.column_widths[idx], width)
        self.rows.append(row)

    def render(self):
        w = StringIO()
        with contextlib.redirect_stdout(w):
            res_id = self.result_id
            nrows = len(self.rows)
            ncols = len(self.column_names)
            nrows_in_msg = nrows
            query_id = 42
            query_time = 0
            malopt_time = 0
            sqlopt_time = 0
            print(
                f"&1 {res_id} {nrows} {ncols} {nrows_in_msg} {query_id} {query_time} {malopt_time} {sqlopt_time}"
            )
            print(fmt_header_line("table_name", [self.table_name] * ncols))
            print(fmt_header_line("name", self.column_names))
            print(fmt_header_line("type", self.column_types))
            print(fmt_header_line("length", [str(w) for w in self.column_widths]))
            for row in self.rows:
                print("[ " + ",\t".join(row) + "\t]")
        return w.getvalue()


def fmt_header_line(desc, values):
    return "% " + ",\t".join(values) + " # " + desc
