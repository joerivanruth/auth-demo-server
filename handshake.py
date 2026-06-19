import logging
import secrets
from typing import Optional

from credentials import CredStore
import framing
import mechanisms
from mechanisms import ClassicMechanism


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
    args = None
    user: str
    dbname: str

    def __init__(self, conn, args):
        self.id = conn.id
        self.conn = conn
        self.args = args
        self.credstore = CredStore.default()

    def execute(self) -> bool:
        ini_nonce = secrets.token_urlsafe(20)
        available_mechanisms = dict((m.wire_name, m) for m in mechanisms.MECHANISMS)
        challenge = f'{ini_nonce}:mserver:9:{",".join(available_mechanisms.keys())}:LIT:{self.obfuscation_algo.upper()}:sql=6:BINARY=1:OOBINTR=1:CLIENTINFO:'
        try:
            self.conn.send(challenge)
        except BrokenPipeError:
            logging.info(f'{self.id}: Client closed the connection')
            return False

        response = self.conn.receive()
        if response is None:
            logging.info(f'{self.id}: Client closed the connection')
            return False
        response_parts = response.rstrip('\n').split(':')
        if len(response_parts) < 5:
            logging.error(f'{self.id}: Too few response components: {response}')
            return False
        self.user = response_parts[1]
        mech_and_payload = response_parts[2]
        self.dbname = response_parts[4]

        # parse {MECHNAME}PAYLOAD
        if not mech_and_payload.startswith('{') or '}' not in mech_and_payload:
            logging.error(f'{self.id}: invalid mechanism selection')
            return False
        mech_name, payload = mech_and_payload[1:].split('}', 1)
        self.mech = available_mechanisms.get(mech_name)
        if not self.mech:
            logging.error(f'{self.id}: unsupported auth mechanism')
            return False

        if isinstance(self.mech, mechanisms.ClassicMechanism):
            err_msg = self.execute_classic(ini_nonce, payload)
        else:
            err_msg = 'external auth not implemented yet'

        if err_msg is not None:
            logging.error(f'{self.id}: {err_msg}')
            self.conn.send('!Authentication failed')
            return False
        else:
            return True

    def execute_classic(self, nonce: str, reply: str) -> Optional[str]:
        assert isinstance(self.mech, ClassicMechanism)
        ctx = self.mech.start_server(self.user, self.credstore, {})

        # make sure to use the nonce that was sent to the client
        bnonce = bytes(nonce, 'utf-8')
        ctx.set_nonce(bnonce)
        chal = ctx.initial_challenge()
        assert bnonce == chal
        try:
            done, nchal = ctx.next_challenge(bytes(reply, 'utf-8'))
            assert done
            assert nchal is None
        except mechanisms.Reject as e:
            return str(e)

        self.conn.send('')
        return None
