import hashlib
import secrets
from uuid import UUID

from backend.crypto.credential_protocol import b64decode
from backend.ra.auth_service import AuthenticationDenied
from backend.ra.demo_credential_verifier import DemoCredentialVerifier
from backend.ra.login_rate_limit import LimitedDemoAuthentication
from backend.admin.store import AdminError


def token_digest(token):
    try:
        if type(token) is not str or not token.startswith("adm1."):raise ValueError()
        b64decode(token[5:],32)
        return hashlib.sha256(b"EVOTE-ADMIN-SESSION-v1\0"+token.encode("ascii")).digest()
    except (ValueError,UnicodeError):raise AdminError(401) from None


class AdminAuthentication:
    def __init__(self,store,admin_id,username,salt,digest):
        self.store,self.admin_id=store,UUID(str(admin_id))
        self.verifier=DemoCredentialVerifier(username=username,password_salt=salt,password_digest=digest,
            provider="local-admin",subject=str(self.admin_id),enable_demo=True)
        self.limited=LimitedDemoAuthentication(self)
    def login(self,username,password):
        if self.verifier.verify_credentials(username,password) is None:raise AuthenticationDenied()
        token="adm1."+secrets.token_urlsafe(32)
        result=self.store.call("login",self.admin_id,token_digest(token))
        self._identity(result)
        return token
    def _identity(self,result):
        try:
            if type(result) is not dict or set(result)!={"admin_id","role"} or result["role"]!="ELECTION_ADMIN" or UUID(result["admin_id"])!=self.admin_id:
                raise ValueError()
        except (ValueError,TypeError,AttributeError):raise AdminError(401) from None
        return result
    def identity(self,token):return self._identity(self.store.call("session",token_digest(token)))
    def logout(self,token):self.store.call("logout",token_digest(token))
