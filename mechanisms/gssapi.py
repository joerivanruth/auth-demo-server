from functools import reduce
import logging
import socket
from typing import Any, Optional, Tuple

import gssapi
from gssapi.raw import GSSError
from pymonetdb.target import Target

from credentials import UserCreds
from mechanisms import ClientSide, Mechanism, Reject, ServerSide, Style


class GSSAPIMechanism(Mechanism):
    """SASL GSSAPI Mechanism following RFC 4752"""

    wire_name = 'GSSAPI'
    client_first = True
    style = Style.KERBEROS

    @staticmethod
    def start_client(target: Target):
        server_principal = determine_server_principal(target)
        client_creds = determine_client_creds(target)
        return GSSAPIClient(server_principal, client_creds)

    @staticmethod
    def start_server(usercreds: UserCreds, opts: dict[str, Any]):
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

        return GSSAPIServer(server_creds, usercreds)


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


def determine_client_creds(target: Target) -> Optional[gssapi.Credentials]:
    principal = target_lookup(target, '_principal')
    keytab = target_lookup(target, '_keytab')
    assert principal is None or isinstance(principal, str)
    assert keytab is None or isinstance(keytab, str)

    if keytab:
        # See https://pythongssapi.github.io/python-gssapi/credstore.html for settings
        # we can put in this 'store'
        store: dict[bytes | str, bytes | str] = {}
        store['client_keytab'] = keytab
        store['ccache'] = 'MEMORY:'
        name = parse_principal(principal) if principal else None
        logging.debug(f'Trying to acquire {name=} from {store=}')
        acquire_result = gssapi.Credentials.acquire(usage='initiate', name=name, store=store)
        creds = gssapi.Credentials(acquire_result.creds)
    else:
        creds = gssapi.Credentials(usage='initiate')

    logging.debug(f'{creds.name=}')
    return creds


def parse_principal(princ: str) -> gssapi.Name:
    if '@' in princ and '/' in princ:
        name_type = gssapi.NameType.kerberos_principal
    else:
        name_type = gssapi.NameType.hostbased_service
    return gssapi.Name(princ, name_type).canonicalize(gssapi.MechType.kerberos)


MINIMAL_REQ_FLAGS = [
    gssapi.RequirementFlag.integrity,
    gssapi.RequirementFlag.mutual_authentication,
    gssapi.RequirementFlag.out_of_sequence_detection,
    gssapi.RequirementFlag.replay_detection,
]


def verify_flags(actual_flags: int, required_flags: list[gssapi.RequirementFlag]):
    missing = [flag.name for flag in required_flags if not (actual_flags & flag)]
    if missing:
        raise Reject(f'GSSAPI: security context lacks {", ".join(missing)}')


class GSSAPIClient(ClientSide):
    client_creds: Optional[gssapi.Credentials]
    server_name: gssapi.Name
    ctx: Optional[gssapi.SecurityContext]
    req_flags: list[gssapi.RequirementFlag]
    final_message_sent = False

    def __init__(
        self, server_principal: gssapi.Name, client_creds: Optional[gssapi.Credentials]
    ):
        self.client_creds = client_creds
        self.server_name = server_principal
        self.ctx = None
        # is there any reason not to enable mutual_authentication,
        # replay detection and out of sequence detection?
        self.req_flags = MINIMAL_REQ_FLAGS

    def respond(self, server_token: bytes):
        try:
            if self.ctx is None:
                assert not server_token
                flags = reduce(lambda x, y: x | y, self.req_flags, 0)
                self.ctx = gssapi.SecurityContext(
                    usage='initiate',
                    name=self.server_name,
                    flags=flags,
                    creds=self.client_creds,
                )
            if not self.ctx.complete:
                # GSSAPI negotiation ongoing
                client_token = self.ctx.step(server_token or None) or b''
                if self.ctx.complete:
                    # This was actually the last GSSAPI token
                    # Verify that the resulting context is acceptable.
                    verify_flags(self.ctx.actual_flags, self.req_flags)
                return client_token
            else:
                return self.negotiate_security_layer(server_token)
        except GSSError as e:
            raise Reject(str(e)) from None

    def negotiate_security_layer(self, server_token: bytes) -> bytes:
        assert self.ctx
        unwrap_result = self.ctx.unwrap(server_token)
        assert not unwrap_result.encrypted
        message = unwrap_result.message
        if len(message) != 4:
            raise Reject(f'Layer nego token is not 4 bytes long: {message!r}')
        supported_layers = message[0]
        max_message_size = 256**2 * message[1] + 256 * message[2] + message[3]
        logging.debug(f'GSSAPI: {supported_layers=} {max_message_size=}')
        if not supported_layers and max_message_size > 0:
            raise Reject(f'{max_message_size=} may only be 0 if security layers are supported')
        raw_response = b'\x00\x00\x00\x00'
        wrap_result = self.ctx.wrap(raw_response, False)
        self.final_message_sent = True
        return wrap_result.message

    def wrap_up(self, additional_data: Optional[bytes]) -> str:
        if not self.final_message_sent:
            raise Reject('GSSAPI: Server completes handshake too soon')
        assert self.ctx
        if additional_data is not None:
            raise Reject('GSSAPI: Server included additional data in completion message')

        our_name = self.ctx.initiator_name.canonicalize(gssapi.MechType.kerberos)
        their_name = self.ctx.target_name.canonicalize(gssapi.MechType.kerberos)
        return f'Authenticated {our_name} -> {their_name}'


class GSSAPIServer(ServerSide):
    server_creds: gssapi.Credentials
    usercreds: UserCreds
    ctx: Optional[gssapi.SecurityContext] = None
    final_message_sent = False

    def __init__(self, server_creds: gssapi.Credentials, usercreds: UserCreds):
        self.server_creds = server_creds
        self.usercreds = usercreds

    def initial_challenge(self):
        return b''

    def next_challenge(self, client_token: bytes) -> Tuple[bool, Optional[bytes]]:
        kerberos_mech = gssapi.MechType.kerberos
        try:
            if self.ctx is None:
                self.ctx = gssapi.SecurityContext(usage='accept', creds=self.server_creds)
            if not self.ctx.complete:
                server_token = self.ctx.step(client_token)
                if self.ctx.complete:
                    # Are we happy with the negotiated connection?
                    if self.ctx.mech != kerberos_mech:
                        raise Reject(
                            f'Client negotiated {self.ctx.mech}, need Kerberos {kerberos_mech}'
                        )
                    # Was the client really trying to reach us?
                    # (Only really necessary if our own credentials are anonymous)
                    our_canon_name = self.server_creds.name.canonicalize(kerberos_mech)
                    requested_canon_name = self.ctx.target_name.canonicalize(kerberos_mech)
                    if requested_canon_name != our_canon_name:
                        raise Reject(
                            f'Client wanted {requested_canon_name}, we are {our_canon_name}'
                        )
                    # Is the connection strong enough?
                    verify_flags(self.ctx.actual_flags, MINIMAL_REQ_FLAGS)
                    # Looks good. Send the final GSSAPI message, do not mark the conversion
                    # as completed because we still need to do the layer nego
                return False, server_token
            else:
                if not self.final_message_sent:
                    # Tell the client which security layer we support
                    server_message = b'\x00\x00\x00\x00'
                    wrapped_message = self.ctx.wrap(server_message, False).message
                    self.final_message_sent = True
                    return False, wrapped_message
                else:
                    client_message = self.ctx.unwrap(client_token).message
                    # Client MUST say it doesn't want security layer because we
                    # didn't offer one
                    client_nego = client_message[:4]
                    expected = b'\x00\x00\x00\x00'
                    if client_nego != expected:
                        raise Reject(
                            f'Unexpected client layer nego message {client_nego!r}, expected {expected!r}'
                        )
                    try:
                        authzid = str(client_message[4:], 'utf-8')
                    except UnicodeDecodeError:
                        raise Reject(
                            f'authzid sent by client is not UTF-8: {client_message[4:]!r}'
                        )
                    self.authzid = authzid
                    self.authcid = str(self.ctx.initiator_name)
                    return True, None
        except GSSError as e:
            raise Reject(str(e)) from None
