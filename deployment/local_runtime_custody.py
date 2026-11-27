"""Encrypted, create-once demo custody. Not a voting wire-format implementation.

Only the trusted controller unlocks the vault. Runtime receives one capability
package via a private pipe. This is software custody, not an HSM/zeroization or
protection against the VM root/operator. No imports generate or load keys.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pydantic import SecretStr

from backend.crypto.credential_protocol import b64encode, b64decode, strict_json
from deployment.local_demo_policy import ROOT, ROLE_DATABASE, SERVICES, fingerprint, require

HEADER = b'EVOTE-LOCAL-CUSTODY-v1\0'
KEYS = {'ra_signing','tally_decryption','manifest_signing','evidence_signing','publication_signing'}
SETUP = {'ra_bootstrap','voting_bootstrap','ra_migrator_login','voting_migrator_login','ra_service_login'}


def seal(plan, payload, password):
    require(isinstance(password,SecretStr) and len(password.get_secret_value()) >= 16, 'CONFIG')
    raw = json.dumps(payload,separators=(',',':'),allow_nan=False).encode()
    require(len(raw) <= 131072, 'CONFIG')
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = Scrypt(salt=salt,length=32,n=32768,r=8,p=1).derive(password.get_secret_value().encode())
    return HEADER+salt+nonce+AESGCM(key).encrypt(nonce,raw,HEADER+fingerprint(plan).encode())


def unseal(plan, blob, password):
    try:
        require(isinstance(password,SecretStr) and len(blob) <= 132000 and blob.startswith(HEADER), 'CONFIG')
        offset = len(HEADER); salt,nonce = blob[offset:offset+16],blob[offset+16:offset+28]
        key = Scrypt(salt=salt,length=32,n=32768,r=8,p=1).derive(password.get_secret_value().encode())
        return strict_json(AESGCM(key).decrypt(nonce,blob[offset+28:],HEADER+fingerprint(plan).encode()))
    except Exception:
        from deployment.local_demo_policy import ReviewRefused
        raise ReviewRefused('CONFIG') from None


def _materials(credentials):
    require(set(credentials) == {'admin','tally','voter_a','voter_b'}, 'CONFIG')
    require(all(isinstance(p,SecretStr) for p in credentials.values())
        and len({p.get_secret_value() for p in credentials.values()}) == 4, 'CONFIG')
    result = {'keys':{},'passwords':{},'setup':{},'verifiers':{},'recovery':b64encode(secrets.token_bytes(32))}
    for name,password in credentials.items():
        require(isinstance(password,SecretStr) and len(password.get_secret_value()) >= 16, 'CONFIG')
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.get_secret_value().encode(),salt=salt,n=16384,r=8,p=1,dklen=32)
        result['verifiers'][name] = dict(username='synthetic-'+name,salt=b64encode(salt),digest=b64encode(digest))
    for name in sorted(KEYS):
        private = rsa.generate_private_key(public_exponent=65537,key_size=3072) if name in {'ra_signing','tally_decryption'} else ed25519.Ed25519PrivateKey.generate()
        unlock = secrets.token_urlsafe(48)
        pem = private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(unlock.encode()))
        public = private.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        pin = private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw) if isinstance(private,ed25519.Ed25519PrivateKey) else public
        result['keys'][name] = dict(pem=pem.decode('ascii'),unlock=unlock,spki=b64encode(public),pin=b64encode(pin),fingerprint=hashlib.sha256(public).hexdigest())
    for login in sorted(ROLE_DATABASE): result['passwords'][login] = secrets.token_urlsafe(48)
    for name in sorted(SETUP): result['setup'][name] = secrets.token_urlsafe(48)
    return result


def validate_materials(value):
    require(type(value) is dict and set(value) == {'keys','passwords','setup','verifiers','recovery'}, 'CONFIG')
    require(set(value['setup']) == SETUP and all(type(v) is str and len(v) >= 48 for v in value['setup'].values()), 'ROLE')
    require(len(set(value['setup'].values())|set(value['passwords'].values())) == len(SETUP)+len(ROLE_DATABASE), 'ROLE')
    require(set(value['keys']) == KEYS and set(value['passwords']) == set(ROLE_DATABASE), 'ASSET_BOUNDARY')
    require(set(value['verifiers']) == {'admin','tally','voter_a','voter_b'}, 'CONFIG')
    for name,entry in value['verifiers'].items():
        require(set(entry) == {'username','salt','digest'} and entry['username'] == 'synthetic-'+name, 'CONFIG')
        b64decode(entry['salt'],16); b64decode(entry['digest'],32)
    require(all(type(p) is str and len(p) >= 48 for p in value['passwords'].values())
        and len(set(value['passwords'].values())) == len(ROLE_DATABASE), 'ROLE')
    b64decode(value['recovery'],32)
    fingerprints = set()
    for name, entry in value['keys'].items():
        require(set(entry) == {'pem','unlock','spki','pin','fingerprint'} and entry['pem'].startswith('-----BEGIN ENCRYPTED PRIVATE KEY-----'), 'CONFIG')
        private = serialization.load_pem_private_key(entry['pem'].encode(),password=entry['unlock'].encode())
        if name in {'ra_signing','tally_decryption'}:
            require(isinstance(private,rsa.RSAPrivateKey) and private.key_size == 3072
                and private.public_key().public_numbers().e == 65537, 'CONFIG')
        else: require(isinstance(private,ed25519.Ed25519PrivateKey), 'CONFIG')
        public = private.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        pin = private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw) if isinstance(private,ed25519.Ed25519PrivateKey) else public
        require(b64decode(entry['spki']) == public and b64decode(entry['pin']) == pin
            and entry['fingerprint'] == hashlib.sha256(public).hexdigest(), 'IDENTITY')
        fingerprints.add(entry['fingerprint'])
    require(len(fingerprints) == len(KEYS), 'IDENTITY')


class Custody:
    def __init__(self, directory, plan, approval):
        approval.check(plan)
        path = Path(directory)
        require(os.name == 'posix' and path.is_absolute() and path.name == 'evote-local-'+plan['identifiers']['profile'].replace('-',''), 'OWNERSHIP')
        require(not path.resolve().is_relative_to(ROOT), 'OWNERSHIP')
        for part in (path,*path.parents):
            if part.exists(): require(not part.is_symlink(), 'OWNERSHIP')
        for parent in path.parents:
            require(parent.stat().st_uid == 0 and not parent.stat().st_mode & 0o022, 'OWNERSHIP')
        self.path, self.plan = path, plan

    def _directory(self):
        status = self.path.lstat()
        require(stat.S_ISDIR(status.st_mode) and status.st_uid == os.geteuid() and stat.S_IMODE(status.st_mode) == 0o700, 'OWNERSHIP')

    def initialize(self, password, credentials, *, confirmation):
        require(confirmation == 'GENERATE DEMO KEYS '+fingerprint(self.plan), 'APPROVAL_REQUIRED')
        # No mkdir(exist_ok), truncation, overwrite, rotation or recovery reset.
        self.path.mkdir(mode=0o700)
        self._directory()
        payload = _materials(credentials)
        validate_materials(payload)
        fd = os.open(self.path/'custody.enc',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(seal(self.plan,payload,password)); stream.flush(); os.fsync(stream.fileno())
        directory_fd = os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
        return self.public_inventory(payload)

    def load(self, password):
        self._directory()
        fd = os.open(self.path/'custody.enc',os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            status = os.fstat(stream.fileno())
            require(stat.S_ISREG(status.st_mode) and status.st_uid == os.geteuid()
                and stat.S_IMODE(status.st_mode) == 0o600 and status.st_nlink == 1, 'OWNERSHIP')
            value = unseal(self.plan,stream.read(132001),password)
        validate_materials(value)
        return value

    @staticmethod
    def public_inventory(value):
        return {name:{field:entry[field] for field in ('spki','pin','fingerprint')} for name,entry in value['keys'].items()}


def service_package(value, service):
    require(service in SERVICES, 'ASSET_BOUNDARY')
    spec = SERVICES[service]
    package = dict(passwords={name:value['passwords'][name] for name in spec['roles']},
        keys={name:value['keys'][name] for name in spec['keys'] if name != 'ra_recovery'},
        verifiers={name:value['verifiers'][name] for name in spec['verifiers']},
        public=Custody.public_inventory(value))
    if 'ra_recovery' in spec['keys']: package['recovery'] = value['recovery']
    return package
