import hashlib
import secrets
from typing import Any, Optional

from credentials import PLAIN, CredStore
from mechanisms import ClientSide, Mechanism, ServerSide, invalid_credentials


class DigestMechanism(Mechanism):
    wire_name = 'DIGEST'
    client_first = False

    def start_client(self, target):
        return DigestClient(target.password)

    def start_server(self, user, credstore: CredStore, opts: dict[str, Any]):
        return DigestServer(credstore.get_last(user, PLAIN))


def squish(nonce: bytes, password: str) -> bytes:
    return hashlib.sha256(nonce + bytes(password, 'utf-8')).digest()


class DigestClient(ClientSide):
    def __init__(self, password: str):
        self.password = password

    def respond(self, token):
        return squish(token, self.password)


class DigestServer(ServerSide):
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

    def next_challenge(self, token):
        if self.expected is not None and token == self.expected:
            return None
        else:
            raise invalid_credentials()
