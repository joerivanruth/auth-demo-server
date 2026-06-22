import hashlib
import secrets
from typing import Any, Optional, Tuple

from credentials import PLAIN, CredStore
from mechanisms import ClientSide, Mechanism, Reject, ServerSide, invalid_credentials


class NaiveDigestMechanism(Mechanism):
    wire_name = 'NAIVE_DIGEST'
    client_first = False

    def start_client(self, target):
        return NaiveDigestClient(target.user, target.password)

    def start_server(self, *, credstore: CredStore, opts: dict[str, Any]):
        return NaiveDigestServer(credstore)


def squish(nonce: bytes, password: str) -> str:
    return hashlib.sha256(bytes(password, 'utf-8') + nonce).hexdigest()


class NaiveDigestClient(ClientSide):
    def __init__(self, user: str, password: str):
        self.user = user
        self.password = password

    def respond(self, token):
        hash = squish(token, self.password)
        resp = f'\x00{self.user}\x00{hash}'
        return bytes(resp, 'utf-8')


class NaiveDigestServer(ServerSide):
    credstore: CredStore
    nonce: bytes

    def __init__(self, credstore: CredStore):
        self.credstore = credstore
        self.nonce = bytes(secrets.token_urlsafe(10), 'utf-8')

    def initial_challenge(self):
        return self.nonce

    def next_challenge(self, raw_token: bytes) -> Tuple[bool, Optional[bytes]]:
        try:
            token = str(raw_token, 'utf-8')
        except ValueError:
            raise Reject(f'{NaiveDigestMechanism.wire_name}: invalid challenge encoding')
        parts = token.split('\x00')
        if len(parts) != 3:
            raise Reject(f'{NaiveDigestMechanism.wire_name}: invalid challenge format')
        authzid, authcid, hashed = parts

        password = self.credstore.get_last(authcid, PLAIN)
        expected = None if password is None else squish(self.nonce, password)

        if expected is None or expected != hashed:
            raise invalid_credentials()

        self.authzid = authzid or None
        self.authcid = authcid
        return True, None
