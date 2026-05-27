import hashlib
import logging
import secrets

import framing


# ** [0] t=0.506s RECV HANDSHAKE (DATA) mapi_handshake(), line 469
# 	b'KkPabZ3W:mserver:9:RIPEMD160,SHA512,SHA384,SHA256,SHA224,SHA1:LIT:SHA512:sql=6:BINARY=1:OOBINTR=1:CLIENTINFO:',
#
# ** [0] t=0.506s HANDSHAKE SEND (DATA) mapi_handshake(), line 723
# 	b'LIT:monetdb:{RIPEMD160}786a66a7f1d35ee677117ffaaff162567bfeedde:sql:demo:FILETRANS:auto_commit=1,reply_size=1000,size_header=0,columnar_protocol=0,time_zone=7200:\n',
#
# ** [0] t=0.512s RECV (DATA) read_line(), line 2730
# 	b'',
#


class Handshake:
    hash_algorithms = [
        algo
        for algo in ["ripemd160", "sha512", "sha384", "sha256", "sha224", "sha1"]
        if algo in hashlib.algorithms_available
    ]
    obfuscation_algo = "sha512"
    passwords = dict(monetdb="monetdb")
    id: str
    conn: framing.Mapi
    args = None
    user: str
    dbname: str

    def __init__(self, conn, args):
        self.id = conn.id
        self.conn = conn
        self.args = args

    def execute(self) -> bool:
        return self.initial_handshake()

    def initial_handshake(self) -> bool:
        ini_nonce = secrets.token_urlsafe()
        ini_nonce = ini_nonce[:10]  # shorten it for readability
        algos = ",".join(self.hash_algorithms).upper()
        challenge = f"{ini_nonce}:mserver:9:{algos}:LIT:{self.obfuscation_algo.upper()}:sql=6:BINARY=1:OOBINTR=1:CLIENTINFO:"
        self.conn.send(challenge)

        response = self.conn.receive()
        if response is None:
            logging.info(f"{self.id}: Client closed the connection")
            return False
        response_parts = response.rstrip("\n").split(":")
        if len(response_parts) < 5:
            logging.error(f"{self.id}: Too few response components: {response}")
            return False
        self.user = response_parts[1]
        self.dbname = response_parts[4]

        err_msg = self.validate_initial_response(ini_nonce, response_parts[2])
        if err_msg is not None:
            err_msg = f"Classic authentication failed: {err_msg}"
            logging.error(f"{self.id}: {err_msg}")
            self.conn.send(f"!{err_msg}\n")
            return False

        self.conn.send("")
        return True

    def validate_initial_response(self, nonce: str, hashed_response: str):
        invalid_credentials = "Invalid credentials"

        if not hashed_response.startswith("{") or "}" not in hashed_response:
            logging.error(f"{self.id}: invalid hashed response: {hashed_response}")
            return "invalid hashed response"
        algo, client_finalhash = hashed_response[1:].split("}", 1)
        algo = algo.lower()
        if algo not in self.hash_algorithms:
            logging.error(f"{self.id}: unsupported hash algo: {algo}")
            return f"Unsupported hash algo: {algo}"

        plain_password = self.passwords.get(self.user)
        if plain_password is None:
            logging.error(f"{self.id}: Unknown user: {self.user}")
            return invalid_credentials
        obfuscated_password = hashlib.new(
            self.obfuscation_algo, data=bytes(plain_password, "utf-8")
        ).hexdigest()

        hash_material = obfuscated_password + nonce
        our_finalhash = hashlib.new(
            algo, data=bytes(hash_material, "utf-8")
        ).hexdigest()

        if our_finalhash == client_finalhash:
            return None
        else:
            logging.debug(
                f"{self.id}: {algo=} {nonce=} {plain_password=} {obfuscated_password=}"
            )
            logging.debug(f"{self.id}: {our_finalhash=} {client_finalhash=}")
            return invalid_credentials
