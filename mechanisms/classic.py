import hashlib
import secrets
from typing import Any, Optional, Tuple

from credentials import PLAIN, CredStore
from mechanisms import ClientSide, Mechanism, Reject, ServerSide


class ClassicMechanism(Mechanism):
    client_first = False
    hash_algo: str
    obfuscation_algo: str

    def __init__(self, hash_algo, obfuscation_algo):
        self.wire_name = hash_algo.upper()
        self.hash_algo = hash_algo
        self.obfuscation_algo = obfuscation_algo

    def start_client(self, target):
        # user name has already been sent, isn't used here anymore
        return ClassicClient(self, target.password)

    def start_server(self, *, credstore: CredStore, opts: dict[str, Any]):
        return ClassicServer(self, credstore)

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
    credstore: CredStore
    nonce: Optional[bytes]

    def __init__(self, mech: ClassicMechanism, credstore: CredStore):
        self.mech = mech
        self.credstore = credstore
        self.nonce = None

    def set_nonce(self, nonce: bytes):
        self.nonce = nonce

    def set_user(self, user: str):
        self.authcid = user

    def initial_challenge(self):
        return self.nonce

    def next_challenge(self, token) -> Tuple[bool, Optional[bytes]]:
        assert self.authcid

        if self.nonce is None:
            # we get to pick the nonce, in real life it will usually
            # have been set with set_nonce()
            self.nonce = bytes(secrets.token_urlsafe(10), 'utf-8')

        password = self.credstore.get_last(self.authcid, PLAIN)
        expected = self.mech.squish(self.nonce, password) if password else None
        if token == expected:
            self.authzid = None
            return True, None
        else:
            raise Reject(f"Wrong password for authcid '{self.authcid}'")

