import logging
from typing import Any, Optional, Tuple

import scramp  # type: ignore
import scramp.core  # type: ignore

from credentials import PLAIN, CredStore
from mechanisms import (
    ClientSide,
    Mechanism,
    Reject,
    ServerSide,
    Target,
)


class NaiveScramMechanism(Mechanism):
    wire_name = 'SCRAM-SHA-256'
    client_first = True

    @staticmethod
    def start_client(target: Target):
        return NaiveScramClient(target.user, target.password)

    @staticmethod
    def start_server(credstore: CredStore, opts: dict[str, Any]):
        return NaiveScramServer(credstore)


class NaiveScramClient(ClientSide):
    user: str
    password: str
    stage: int = 0  # 0 = init, 1 = first sent, 2 = final sent
    client: scramp.ScramClient

    def __init__(self, user, password):
        self.user = user
        self.password = password
        self.stage = 0
        try:
            self.client = scramp.ScramClient(['SCRAM-SHA-256'], self.user, self.password)
        except scramp.ScramException as e:
            raise Reject(f'SCRAM: {e}') from None

    def respond(self, raw_server_token: bytes) -> bytes:
        try:
            server_token = str(raw_server_token, 'utf-8')
        except ValueError:
            raise Reject('SCRAM: server token expected to be utf-8 text')

        try:
            if self.stage == 0:
                assert '' == server_token
                client_token = self.client.get_client_first()
                self.stage = 1
            elif self.stage == 1:
                assert '' != server_token
                self.client.set_server_first(server_token)
                client_token = self.client.get_client_final()
                self.stage = 2
                return bytes(client_token, 'utf-8')
            else:
                raise Reject(
                    'SCRAM: server sent unexpected additional challenge: {server_token}'
                )
        except scramp.ScramException as e:
            raise Reject(f'SCRAM: {e}') from None

        return bytes(client_token, 'utf-8')

    def wrap_up(self, raw_additional_data: Optional[bytes]):
        if self.stage != 2:
            raise Reject('SCRAM: server completed authentication too soon')
        if not raw_additional_data:
            raise Reject('SCRAM: server did not send server-final message')
        additional_data = str(raw_additional_data, 'utf-8')
        try:
            self.client.set_server_final(additional_data)
        except scramp.ScramException as e:
            raise Reject(f'SCRAM: {e}') from None

        return f'SCRAM auth as {self.user} succesful'


_mech = scramp.ScramMechanism('SCRAM-SHA-256')


class NaiveScramServer(ServerSide):
    credstore: CredStore
    server: scramp.core.ScramServer
    initial: bool

    def __init__(self, credstore: CredStore):
        self.credstore = credstore
        try:
            self.server = _mech.make_server(self.auth_fn)
        except scramp.ScramException as e:
            raise Reject(f'SCRAM: {e}') from None
        self.initial = True

    def initial_challenge(self):
        return b''

    def next_challenge(self, raw_client_token: bytes) -> Tuple[bool, Optional[bytes]]:
        try:
            client_token = str(raw_client_token, 'utf-8')
        except ValueError:
            raise Reject('SCRAM: client token must be utf-8 string')

        try:
            if self.initial:
                self.server.set_client_first(client_token)
                server_token = self.server.get_server_first()
                self.authzid = client_token.split(',', 2)[1] or None
                self.initial = False
                return False, bytes(server_token, 'utf-8')
            else:
                self.server.set_client_final(client_token)
                server_token = self.server.get_server_final()
                self.authcid = self.server.user
                return True, bytes(server_token, 'utf-8')
        except scramp.ScramException as e:
            raise Reject(f'SCRAM: {e}') from None

    def auth_fn(self, user: str) -> Tuple[bytes, bytes, bytes, int]:
        mechname = NaiveScramMechanism.wire_name
        scrampw = self.credstore.get_last(user, mechname)
        if scrampw is None:
            plainpw = self.credstore.get_last(user, PLAIN)
            if plainpw is None:
                raise Reject(f"User '{user}' unknown")
            scrampw = make_password_file_entry(plainpw)
            logging.debug(
                f"Invented '{mechname}' password based on '{PLAIN}' password: {scrampw}"
            )
            self.credstore.set(user, mechname, scrampw)
        return parse_password_file_entry(scrampw)


def make_password_file_entry(password: str) -> str:
    salt, stored_key, server_key, iteration_count = _mech.make_auth_info(password)
    return (
        f'{{{_mech.name}}}{iteration_count},{salt.hex()},{stored_key.hex()},{server_key.hex()}'
    )


def parse_password_file_entry(entry: str) -> Tuple[bytes, bytes, bytes, int]:
    prefix = f'{{{_mech.name}}}'
    if not entry.startswith(prefix):
        raise ValueError(f'password entry must start with {prefix}')
    itercount_part, salt_part, stored_part, server_part = entry[len(prefix) :].split(',', 3)
    return (
        bytes.fromhex(salt_part),
        bytes.fromhex(stored_part),
        bytes.fromhex(server_part),
        int(itercount_part),
    )
