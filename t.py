#!/usr/bin/env python3

import os
import secrets
from typing import Any, Optional

from pymonetdb.target import Target

from credentials import CredStore
from mechanisms import Mechanism, Reject
import mechanisms
from mechanisms.classic import ClassicServer


def show(side: str, payload: Optional[bytes | str], modifier=None):
    maxlen = 36
    print(f'{side}', end='')
    if modifier:
        print(f': {modifier}', end='')
    if payload is None:
        print()
        return
    else:
        print(': ', end='')
    if isinstance(payload, str):
        print(payload)
    elif len(payload) <= maxlen:
        print(f'{payload!r}')
    else:
        n = maxlen // 2
        print(f'{payload[:n]!r} .. {payload[-n:]!r} ({len(payload)} bytes)')


def dialogue(
    mech: Mechanism,
    *,
    client_opts: Optional[dict[str, Any]] = None,
    server_opts: Optional[dict[str, Any]] = None,
):
    assert isinstance(mech, Mechanism), Mechanism
    client_opts = client_opts or {}
    adjusted_server_opts = dict(keytab=os.path.expanduser('~/monetdb.keytab'))
    adjusted_server_opts |= server_opts or {}

    target = Target()
    target.parse('monetdb://localhost.:55000/demo')
    for k, v in client_opts.items():
        target.set(k, v)
    target.validate()

    credstore = CredStore.default()
    credlist = list(credstore.list())
    print(f'Cred store has {len(credlist)} items')
    for cred in credlist:
        print(f'- user {cred.user} has {cred.kind}={cred.password}')

    try:
        client = mech.start_client(target=target)
    except Reject as e:
        show('C', str(e), modifier=f'{mech.wire_name} ERROR')
        return
    try:
        server = mech.start_server(usercreds=credstore['monetdb'], opts=adjusted_server_opts)
        if isinstance(server, ClassicServer):
            server.set_nonce(bytes(secrets.token_urlsafe(20), 'utf-8'))
            server.set_user(target.user)
        challenge: Optional[bytes] = server.initial_challenge()
        server_done = False
    except Reject as e:
        show('S', str(e), modifier=f'{mech.wire_name} ERROR')
        return

    # The main loop is based on server-first. For client-first we need to do some tweaking
    if mech.client_first:
        # with client-first, the initial challenge must be empty
        assert challenge == b'', (
            f'Initial {mech.__class__.__name__} challenge not empty: {challenge!r}'
        )
        try:
            response = client.respond(b'')
        except Reject as e:
            show('C', str(e), modifier=f'{mech.wire_name} ERROR')
            return
    else:
        response = None
    show('C', response, modifier=f"Request {mech.wire_name}'")
    if mech.client_first:
        try:
            server_done, challenge = server.next_challenge(response or b'')
        except Reject as e:
            show('S', str(e), modifier='ERROR')
            return

    for i in range(10):
        if server_done:
            authcid = server.authcid
            authzid = server.authzid
            show('S', challenge, modifier=f'OK {authcid=} {authzid=}')
            assert authcid is not None
            try:
                report = client.wrap_up(challenge)
            except Reject as e:
                show('C', str(e), modifier='ERROR')
                return
            show('C', report, modifier='HAPPY')
            print()
            break
        else:
            show('S', challenge)
        try:
            response = client.respond(challenge or b'')
        except Reject as e:
            show('C', str(e), modifier='ERROR')
            return
        show('C', response)
        try:
            server_done, challenge = server.next_challenge(response or b'')
        except Reject as e:
            show('S', str(e), modifier='ERROR')
    else:
        raise Exception('exchange takes too long')


dialogue(mechanisms.PlainMechanism())
dialogue(mechanisms.ClassicMechanism('sha256', 'sha512'))
dialogue(mechanisms.NaiveScramMechanism())  # type: ignore
dialogue(mechanisms.GSSAPIMechanism())  # type: ignore
