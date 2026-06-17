from collections import defaultdict
from dataclasses import dataclass
import getpass
import importlib
from typing import Optional


PLAIN = 'plain'
PRINCIPAL = 'principal'


@dataclass
class Cred:
    user: str
    kind: str
    password: str


class CredStore:
    _creds: defaultdict[str, defaultdict[str, list[str]]]

    def __init__(self):
        self._creds = defaultdict(lambda: defaultdict(lambda: []))

    def add(self, user, kind, cred):
        self._creds[user][kind].append(cred)

    def set(self, user, kind, cred):
        self._creds[user][kind] = [cred]

    def get_all(self, user: str, kind: str) -> list[str]:
        return self._creds[user][kind][:]

    def get_last(self, user: str, kind: str) -> Optional[str]:
        answers = self.get_all(user, kind)
        if not answers:
            return None
        else:
            return answers[-1]

    def list(self):
        for u, kps in self._creds.items():
            for k, ps in kps.items():
                for p in ps:
                    yield Cred(u, k, p)

    @staticmethod
    def default() -> 'CredStore':
        creds = CredStore()
        creds.add('monetdb', PLAIN, 'monetdb')
        try:
            gs = importlib.import_module('gssapi')
            our_principal = gs.Name(getpass.getuser(), gs.NameType.user)
            our_principal = our_principal.canonicalize(gs.MechType.kerberos)
            creds.add('monetdb', PRINCIPAL, str(our_principal))
        except ModuleNotFoundError:
            pass
        return creds
