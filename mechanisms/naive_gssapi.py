import socket
from typing import Any, Optional, Tuple

import gssapi
from gssapi.raw import GSSError
from pymonetdb.target import Target

from credentials import CredStore
from mechanisms import ClientSide, Mechanism, Reject, ServerSide


class NaiveGSSAPIMechanism(Mechanism):
    wire_name = 'NAIVE_GSSAPI'
    client_first = True
    authentication_id_type = 'kerberos'

    @staticmethod
    def start_client(target: Target):
        server_principal = determine_server_principal(target)
        return NaiveGSSAPIClient(server_principal)

    @staticmethod
    def start_server(credstore: CredStore, opts: dict[str, Any]):
        principal = opts.get('principal')
        if not principal:
            fqdn = socket.getfqdn()
            principal = f'monetdb@{fqdn}'
        server_name = parse_principal(principal)

        keytab = opts.get('keytab')
        assert keytab is None or isinstance(keytab, str)
        # This 'store layout' is probably specific to MIT Kerberos
        store: dict[bytes | str, bytes | str] | None = dict(keytab=keytab) if keytab else None
        acquire_result = gssapi.Credentials.acquire(
            usage='accept', name=server_name, store=store
        )
        server_creds = gssapi.Credentials(acquire_result.creds)

        return NaiveGSSAPIServer(server_creds, credstore)


def target_lookup(target: Target, key: str) -> Optional[Any]:
    try:
        return target.get(key)
    except KeyError:
        return ''


def determine_server_principal(target: Target) -> gssapi.Name:
    target.validate()
    princ = target_lookup(target, 'server_principal')
    if not princ:
        host = target.connect_tcp
        if not host or host == 'localhost':
            host = socket.getfqdn()
        princ = f'monetdb@{host}'
    return parse_principal(princ)


def parse_principal(princ: str) -> gssapi.Name:
    if '@' in princ and '/' in princ:
        name_type = gssapi.NameType.kerberos_principal
    else:
        name_type = gssapi.NameType.hostbased_service
    return gssapi.Name(princ, name_type).canonicalize(gssapi.MechType.kerberos)


class NaiveGSSAPIClient(ClientSide):
    server_name: gssapi.Name
    ctx: Optional[gssapi.SecurityContext]

    def __init__(self, server_principal: gssapi.Name):
        self.server_name = server_principal
        self.ctx = None

    def respond(self, server_token: bytes):
        try:
            if self.ctx is None:
                assert not server_token
                self.ctx = gssapi.SecurityContext(usage='initiate', name=self.server_name)
            assert not self.ctx.complete
            return self.ctx.step(server_token or None) or b''
        except GSSError as e:
            raise Reject(str(e)) from None

    def wrap_up(self, additional_data: Optional[bytes]) -> Optional[str]:
        assert self.ctx
        assert not self.ctx.complete
        try:
            tok = self.ctx.step(additional_data)
        except GSSError as e:
            raise Reject(str(e)) from None
        if not self.ctx.complete:
            raise Reject("Server done but we aren't")
        assert not tok

        our_name = self.ctx.initiator_name.canonicalize(gssapi.MechType.kerberos)
        their_name = self.ctx.target_name.canonicalize(gssapi.MechType.kerberos)
        return f'Authenticated {our_name} -> {their_name}'


class NaiveGSSAPIServer(ServerSide):
    server_creds: gssapi.Credentials
    credstore: CredStore
    ctx: Optional[gssapi.SecurityContext] = None

    def __init__(self, server_creds: gssapi.Credentials, credstore: CredStore):
        self.server_creds = server_creds
        self.credstore = credstore

    def initial_challenge(self):
        return b''

    def next_challenge(self, client_token: bytes) -> Tuple[bool, Optional[bytes]]:
        try:
            if self.ctx is None:
                self.ctx = gssapi.SecurityContext(usage='accept', creds=self.server_creds)
            assert not self.ctx.complete
            assert client_token
            server_token = self.ctx.step(client_token)
        except GSSError as e:
            raise Reject(str(e)) from None
        if self.ctx.complete:
            canonical_client = self.ctx.initiator_name.canonicalize(gssapi.MechType.kerberos)
            self.authcid = str(canonical_client)
            self.authzid = None
        return self.ctx.complete, server_token
