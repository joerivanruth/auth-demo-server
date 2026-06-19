import hashlib
import secrets
from typing import Any, Optional, Tuple

from credentials import PLAIN, CredStore
from mechanisms import ClientSide, Mechanism, ServerSide, invalid_credentials


class ClassicMechanism(Mechanism):
    client_first = False
    hash_algo: str
    obfuscation_algo: str

    def __init__(self, hash_algo, obfuscation_algo):
        self.wire_name = hash_algo.upper()
        self.hash_algo = hash_algo
        self.obfuscation_algo = obfuscation_algo

    def start_client(self, target):
        return ClassicClient(self, target.password)

    def start_server(self, user, credstore: CredStore, opts: dict[str, Any]):
        return ClassicServer(self, credstore.get_last(user, PLAIN))

    def squish(self, nonce: bytes, password: str) -> bytes:
        obfuscated = hashlib.new(self.obfuscation_algo, bytes(password, 'utf-8')).hexdigest()
        data = bytes(obfuscated, 'utf-8') + nonce
        hash = hashlib.new(self.hash_algo, data).hexdigest()
        return bytes(hash, 'utf-8')


class ClassicClient(ClientSide):
    mech: ClassicMechanism
    password: str

    def __init__(self, mech: ClassicMechanism, password: str):
        self.mech = mech
        self.password = password

    def respond(self, token):
        return self.mech.squish(token, self.password)


class ClassicServer(ServerSide):
    mech: ClassicMechanism
    password: Optional[str]
    nonce: bytes

    def __init__(self, mech: ClassicMechanism, password: Optional[str]):
        self.mech = mech
        self.password = password
        self.nonce = bytes(secrets.token_urlsafe(10), 'utf-8')

    def initial_challenge(self):
        return self.nonce

    def next_challenge(self, token) -> Tuple[bool, Optional[bytes]]:
        if self.password is None:
            expected = None
        else:
            expected = self.mech.squish(self.nonce, self.password)

        if token == expected:
            return True, None
        else:
            raise invalid_credentials()
