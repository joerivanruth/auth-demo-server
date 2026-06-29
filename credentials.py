from collections import defaultdict
from dataclasses import dataclass
import getpass
import importlib
from typing import Generator, Optional


PLAIN = 'plain'
PRINCIPAL = 'principal'


@dataclass
class Cred:
    user: str
    kind: str
    password: str


class UserCreds:
    _creds: defaultdict[str, list[str]]
    user: str

    def __init__(self, user: str):
        self.user = user
        self._creds = defaultdict(lambda: [])

    def add(self, kind, pw):
        self._creds[kind].append(pw)

    def set(self, kind, pw):
        self._creds[kind] = [pw]

    def get_all(self, kind) -> list[str]:
        creds = self._creds[kind][:]
        return creds

    def get_last(self, kind) -> Optional[str]:
        answers = self.get_all(kind)
        if not answers:
            return None
        else:
            return answers[-1]

    def list(self) -> Generator[Cred, None, None]:
        for k, ps in self._creds.items():
            for p in ps:
                yield Cred(self.user, k, p)


class CredStore:
    _creds: dict[str, UserCreds]

    def __init__(self):
        self._creds = defaultdict(UserCreds)

    def add(self, user, kind, pw):
        self[user].add(kind, pw)

    def set(self, user, kind, pw):
        self[user].set(kind, pw)

    def __getitem__(self, user):
        if user not in self._creds:
            self._creds[user] = UserCreds(user)
        return self._creds[user]

    def get_all(self, user: str, kind: str) -> list[str]:
        usercreds = self[user]
        return usercreds.get_all(kind)

    def get_last(self, user: str, kind: str) -> Optional[str]:
        usercreds = self[user]
        return usercreds.get_last(kind)

    def list(self) -> Generator[Cred, None, None]:
        for user, usercreds in self._creds.items():
            yield from usercreds.list()

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
