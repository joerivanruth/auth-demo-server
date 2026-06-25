import argparse
import logging
import secrets
from typing import Optional

from credentials import CredStore
import framing
import mechanisms
from mechanisms import ClassicMechanism, Mechanism, Reject, ServerSide


# ** [0] t=0.506s RECV HANDSHAKE (DATA) mapi_handshake(), line 469
# 	b'KkPabZ3W:mserver:9:RIPEMD160,SHA512,SHA384,SHA256,SHA224,SHA1:LIT:SHA512:sql=6:BINARY=1:OOBINTR=1:CLIENTINFO:',
#
# ** [0] t=0.506s HANDSHAKE SEND (DATA) mapi_handshake(), line 723
# 	b'LIT:monetdb:{RIPEMD160}786a66a7f1d35ee677117ffaaff162567bfeedde:sql:demo:FILETRANS:auto_commit=1,reply_size=1000,size_header=0,columnar_protocol=0,time_zone=7200:\n',
#
# ** [0] t=0.512s RECV (DATA) read_line(), line 2730
# 	b'',
#


class Handshake:
    obfuscation_algo = 'sha512'
    credstore: CredStore
    id: str
    conn: framing.Mapi
    args: argparse.Namespace
    dbname: str
    mech: Optional[Mechanism]
    server_side: Optional[ServerSide]
    effective_user: Optional[str]

    def __init__(self, conn, credstore: CredStore, args: argparse.Namespace):
        self.id = conn.id
        self.conn = conn
        self.args = args
        self.credstore = credstore

    def execute(self):
        ini_nonce = secrets.token_urlsafe(20)
        available_mechanisms = dict((m.wire_name, m) for m in mechanisms.MECHANISMS)
        challenge = f'{ini_nonce}:mserver:9:{",".join(available_mechanisms.keys())}:LIT:{self.obfuscation_algo.upper()}:sql=6:BINARY=1:OOBINTR=1:CLIENTINFO:'
        try:
            self.conn.send(challenge)
        except BrokenPipeError:
            raise Reject(f'{self.id}: Client closed the connection')

        response = self.conn.receive()
        if response is None:
            raise Reject(f'{self.id}: Client closed the connection')
        response_parts = response.rstrip('\n').split(':')
        if len(response_parts) < 5:
            raise Reject(f'{self.id}: Too few response components: {response}')
        user = response_parts[1]
        mech_and_payload = response_parts[2]
        self.dbname = response_parts[4]

        # parse {MECHNAME}PAYLOAD
        if not mech_and_payload.startswith('{') or '}' not in mech_and_payload:
            raise Reject(f'{self.id}: invalid mechanism selection')
        mech_name, payload = mech_and_payload[1:].split('}', 1)
        self.mech = available_mechanisms.get(mech_name)
        if not self.mech:
            raise Reject(f'{self.id}: unsupported auth mechanism')

        if isinstance(self.mech, mechanisms.ClassicMechanism):
            final_message = self.execute_classic(ini_nonce, user, payload)
        else:
            final_message = self.execute_modern(payload)
        assert (self.server_side)  # both set this

        authcid = self.server_side.authcid
        authzid = self.server_side.authzid
        mech = self.mech.wire_name
        logging.debug(f'{self.id}: Authenticated {mech}: {authcid=} {authzid=}')

        return final_message

    def execute_modern(self, payload: str) -> str:
        assert self.mech
        opts = {}
        if self.args.keytab:
            opts['keytab'] = self.args.keytab
        if self.args.principal:
            opts['principal'] = self.args.principal
        ctx = self.mech.start_server(credstore=self.credstore, opts=opts)

        # send initial challenge to client and await reply
        server_token = ctx.initial_challenge()
        if self.mech.client_first and payload:
            assert server_token == b''
            client_token_str = payload
        else:
            self.conn.send('+' + server_token.hex())
            client_token_str = self.conn.receive() or ''

        # process the reply and send a new challenge if necessary
        for i in range(10):
            if not client_token_str.startswith('+'):
                raise Reject('client unexpectedly stopped authenticating')
            client_token = bytes.fromhex(client_token_str[1:])
            server_done, challenge = ctx.next_challenge(client_token)
            if server_done:
                self.server_side = ctx
                if challenge is None:
                    return '*'
                else:
                    return '*+' + challenge.hex()
            else:
                assert challenge
                self.conn.send('+' + challenge.hex())
                client_token_str = self.conn.receive() or ''
        else:
            raise Reject('exchange takes too long')

    def execute_classic(self, nonce: str, user: str, reply: str) -> str:
        assert self.mech
        assert isinstance(self.mech, ClassicMechanism)
        ctx = self.mech.start_server(credstore=self.credstore, opts={})
        ctx.set_user(user)

        # make sure to use the nonce that was sent to the client
        bnonce = bytes(nonce, 'utf-8')
        ctx.set_nonce(bnonce)
        chal = ctx.initial_challenge()
        assert bnonce == chal


        done, nchal = ctx.next_challenge(bytes(reply, 'utf-8'))
        assert done
        assert nchal is None

        self.server_side = ctx
        return ''
