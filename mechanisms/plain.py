from typing import Optional

from credentials import PLAIN, CredStore
from mechanisms import (
    ClientSide,
    Mechanism,
    ServerSide,
    Target,
    invalid_credentials,
)


class PlainMechanism(Mechanism):
    wire_name = 'PLAIN'
    client_first = True

    @staticmethod
    def start_client(target: Target):
        return PlainClient(target.password)

    @staticmethod
    def start_server(user, credstore: CredStore):
        return PlainServer(credstore.get_last(user, PLAIN))


class PlainClient(ClientSide):
    def __init__(self, password: str):
        self.password = password

    def respond(self, token):
        assert token == b''
        return bytes(self.password, 'utf-8')


class PlainServer(ServerSide):
    def __init__(self, password: Optional[str]):
        self.password = password

    def initial_challenge(self):
        return b''

    def next_challenge(self, token):
        password = str(token, 'utf-8')
        if password == self.password:
            return None
        else:
            raise invalid_credentials()
