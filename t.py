#!/usr/bin/env python3

from typing import Any, Optional

from pymonetdb.target import Target

from credentials import CredStore
from mechanisms import Mechanism
import mechanisms


def dialogue(mech: Mechanism, client_opts: dict[str, Any]):
    assert isinstance(mech, Mechanism), Mechanism
    target = Target()
    target.parse('monetdb://localhost.:55000/demo')
    for k, v in client_opts.items():
        target.set(k, v)
    target.validate()

    print(f'* {mech.wire_name}')

    client = mech.start_client(target)
    server = mech.start_server(target.user, CredStore.default())

    challenge: Optional[bytes] = server.initial_challenge()
    if mech.client_first:
        assert challenge == b'', f'First client-first challenge not empty: {challenge!r}'
    for i in range(10):
        if not (mech.client_first and i == 0):
            print(f'S: {challenge!r}')
        assert challenge is not None
        response = client.respond(challenge)
        print(f'C: {response!r}')
        challenge = server.next_challenge(response)
        if challenge is None:
            print('S: OK')
            print()
            break
        print()
    else:
        raise Exception('exchange takes too long')


dialogue(mechanisms.PlainMechanism(), dict())
dialogue(mechanisms.DigestMechanism(), dict())
