#!/usr/bin/env python3

import os
from typing import Any, Optional

from pymonetdb.target import Target

from credentials import CredStore
from mechanisms import Mechanism
import mechanisms


def show(side: str, btext: Optional[bytes]):
    print(f'{side}: ', end='')
    if btext is None:
        print('None')
        return
    maxlen = 36
    if len(btext) <= maxlen:
        print(f'{btext!r}')
    else:
        n = maxlen // 2
        print(f'{btext[:n]!r} .. {btext[-n:]!r} ({len(btext)} bytes)')


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
    print(f'* {mech.wire_name}')

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
    print()

    client = mech.start_client(target)
    server = mech.start_server(target.user, credstore, adjusted_server_opts)

    challenge: Optional[bytes] = server.initial_challenge()
    if mech.client_first:
        assert challenge == b'', f'First client-first challenge not empty: {challenge!r}'
    for i in range(10):
        if not (mech.client_first and i == 0):
            show('S', challenge)
        assert challenge is not None
        response = client.respond(challenge)
        show('C', response)
        challenge = server.next_challenge(response)
        if challenge is None:
            print('S: OK')
            print()
            break
        print()
    else:
        raise Exception('exchange takes too long')


dialogue(mechanisms.PlainMechanism())
dialogue(mechanisms.DigestMechanism())
dialogue(mechanisms.NaiveGSSAPIMechanism())
