#!/usr/bin/env python3

import os
from typing import Any, Optional

from pymonetdb.target import Target

from credentials import CredStore
from mechanisms import Mechanism
import mechanisms


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
    adjusted_server_opts = dict(keytab=os.path.expanduser('~/monetdb.keytab')) | (
        server_opts or {}
    )

    target = Target()
    target.parse('monetdb://localhost.:55000/demo')
    for k, v in client_opts.items():
        target.set(k, v)
    target.validate()

    credstore = CredStore.default()
    credlist = list(credstore.list())
    print(f'Cred store has {len(credlist)} items')
    for cred in credlist:
        print(f'- {cred.user} {cred.kind}={cred.password}')

    client = mech.start_client(target)
    server = mech.start_server(target.user, credstore, adjusted_server_opts)

    challenge: Optional[bytes] = server.initial_challenge()
    done = False

    # The main loop is based on server-first. For client-first we need to do some tweaking
    if mech.client_first:
        # with client-first, the initial challenge must be empty
        assert challenge == b'', (
            f'Initial {mech.__class__.__name__} challenge not empty: {challenge!r}'
        )
        response = client.respond(b'')
    else:
        response = None
    show('C', response, modifier=f"Request {mech.wire_name} for user '{target.user}'")
    if mech.client_first:
        done, challenge = server.next_challenge(response or b'')

    for i in range(10):
        if done:
            show('S', challenge, modifier='OK')
            report = client.wrap_up(challenge)
            show('C', report, modifier='HAPPY')
            print()
            break
        else:
            show('S', challenge)
        response = client.respond(challenge or b'')
        show('C', response)
        done, challenge = server.next_challenge(response or b'')
    else:
        raise Exception('exchange takes too long')


dialogue(mechanisms.PlainMechanism())
dialogue(mechanisms.DigestMechanism())
dialogue(mechanisms.NaiveGSSAPIMechanism())
