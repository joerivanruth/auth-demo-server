from collections import defaultdict
from typing import Optional


PLAIN = 'plain'


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

    @staticmethod
    def default() -> 'CredStore':
        creds = CredStore()
        creds.add('monetdb', PLAIN, 'monetdb')
        return creds
