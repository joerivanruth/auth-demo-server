from typing import Any, Optional, Tuple

from credentials import PLAIN, CredStore
from mechanisms import (
    ClientSide,
    Mechanism,
    Reject,
    ServerSide,
    Target,
)


class PlainMechanism(Mechanism):
    wire_name = 'PLAIN'
    client_first = True

    @staticmethod
    def start_client(target: Target):
        return PlainClient(target.user, target.password)

    @staticmethod
    def start_server(credstore: CredStore, opts: dict[str, Any]):
        return PlainServer(credstore)


class PlainClient(ClientSide):
    def __init__(self, user: str, password: str):
        self.user = user
        self.password = password

    def respond(self, token):
        assert token == b''
        packet = f'\x00{self.user or ""}\x00{self.password or ""}'
        return bytes(packet, 'utf-8')


class PlainServer(ServerSide):
    credstore: CredStore

    def __init__(self, credstore: CredStore):
        self.credstore = credstore

    def initial_challenge(self):
        return b''

    def next_challenge(self, token) -> Tuple[bool, Optional[bytes]]:
        packet = str(token, 'utf-8')
        parts = packet.split('\x00')
        if len(parts) != 3:
            raise Reject('invalid client response, found {len(parts)} parts, need 3')
        [authzid, authcid, password] = parts

        server_password = self.credstore.get_last(authcid, PLAIN)

        if password == server_password:
            self.authcid = authcid
            self.authzid = authzid or None
            return True, None
        else:
            raise Reject()
