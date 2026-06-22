import hashlib
import secrets
from typing import Any, Optional, Tuple

from credentials import PLAIN, CredStore
from mechanisms import ClientSide, Mechanism, ServerSide, invalid_credentials


class NaiveDigestMechanism(Mechanism):
    wire_name = 'NAIVE_DIGEST'
    client_first = False

    def start_client(self, target):
        return NaiveDigestClient(target.password)

    def start_server(self, user, credstore: CredStore, opts: dict[str, Any]):
        return NaiveDigestServer(credstore.get_last(user, PLAIN))


def squish(nonce: bytes, password: str) -> bytes:
    return hashlib.sha256(nonce + bytes(password, 'utf-8')).digest()


class NaiveDigestClient(ClientSide):
    def __init__(self, password: str):
        self.password = password

    def respond(self, token):
        return squish(token, self.password)


class NaiveDigestServer(ServerSide):
    nonce: bytes
    expected: Optional[bytes]

    def __init__(self, password: Optional[str]):
        self.nonce = bytes(secrets.token_urlsafe(10), 'utf-8')
        if password is None:
            self.expected = None
        else:
            self.expected = squish(self.nonce, password)

    def initial_challenge(self):
        return self.nonce

    def next_challenge(self, token) -> Tuple[bool, Optional[bytes]]:
        if self.expected is not None and token == self.expected:
            return True, None
        else:
            raise invalid_credentials()
