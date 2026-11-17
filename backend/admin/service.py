"""Durable single-election saga; no claim of cross-database atomicity."""
import hashlib
from uuid import UUID,uuid4
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend.crypto.credential_protocol import (
    PROFILE,MANIFEST_CONTEXT,b64decode,b64encode,canonical_manifest,key_id,public_rsa,strict_json,verify_manifest,
)
from backend.admin.auth import token_digest
from backend.admin.store import AdminError


class ManifestAuthority:
    def __init__(self,private,pin):
        if not isinstance(private,Ed25519PrivateKey) or private.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)!=pin:raise ValueError("Authority pin mismatch")
        self.private,self.pin=private,pin
    def sign(self,manifest):
        raw=canonical_manifest(manifest)
        return self.private.sign(MANIFEST_CONTEXT+raw)


class AdminService:
    def __init__(self,auth,voting,publisher,authority,keysets):
        self.auth,self.voting,self.publisher,self.authority=auth,voting,publisher,authority
        self.keysets=keysets
        if type(keysets) is not dict or not 1 <= len(keysets) <= 100:raise ValueError("Invalid key catalogue")
        fingerprints=set()
        for name,entry in keysets.items():
            if type(name) is not str or not name.strip() or len(name)>128 or type(entry) is not dict or set(entry)!={"ra_key","tally_key","private_key_reference"}:raise ValueError("Invalid key catalogue")
            reference=entry["private_key_reference"]
            if type(reference) is not str or not reference.strip() or len(reference)>255:raise ValueError("Invalid key reference")
            for field in ("ra_key","tally_key"):
                if type(entry[field]) is not dict or set(entry[field])!={"key_id","spki","fingerprint"}:raise ValueError("Invalid public key")
                key_id(entry[field]["key_id"])
                public_rsa(entry[field]["spki"])
                if hashlib.sha256(b64decode(entry[field]["spki"])).hexdigest()!=entry[field]["fingerprint"]:raise ValueError("Invalid key fingerprint")
            if entry["ra_key"]["fingerprint"]==entry["tally_key"]["fingerprint"] or entry["ra_key"]["fingerprint"] in fingerprints:raise ValueError("Distinct per-election RA keys required")
            fingerprints.add(entry["ra_key"]["fingerprint"])
    def _authorize(self,token):return self.auth.identity(token)
    def public(self,row):
        result=dict(row);raw=result.pop("manifest_hex",None);sig=result.pop("signature_hex",None)
        if raw and sig:
            bundle={"manifest":strict_json(bytes.fromhex(raw)),"signature":b64encode(bytes.fromhex(sig))}
            verify_manifest(bundle,self.authority.pin,row["election_id"]);result["bundle"]=bundle
        else:result["bundle"]=None
        return result
    def list(self,token):
        self._authorize(token)
        return [self.public(row) for row in self.voting.call("read",token_digest(token),None)]
    def detail(self,token,election):
        self._authorize(token)
        return self.public(self.voting.call("read",token_digest(token),election)[0])
    def keys(self,token):
        self._authorize(token)
        return [{"keyset_id":name,"ra_key":item["ra_key"],"tally_key":item["tally_key"]} for name,item in self.keysets.items()]
    def change(self,token,election,command,data):
        self._authorize(token)
        with self.voting.operation(token_digest(token),election) as operation:
            return self.public(operation.mutate(command,data))
    def create(self,token,data):return self.change(token,uuid4(),"create",data)
    def audit(self,token,election):
        self._authorize(token)
        return self.voting.call("audit",token_digest(token),election)
    def _bundle(self,row):
        raw=bytes.fromhex(row["manifest_hex"]);manifest=strict_json(raw)
        sig=bytes.fromhex(row["signature_hex"])
        verified,digest=verify_manifest({"manifest":manifest,"signature":b64encode(sig)},self.authority.pin,row["election_id"])
        if canonical_manifest(verified)!=raw or digest!=row["config_hash"]:raise AdminError(409)
        return raw,sig,verified,digest
    def _prepare_ra(self,row,actor):
        raw,sig,manifest,digest=self._bundle(row)
        entry=self.keysets.get(row["keyset_id"])
        if entry is None or manifest["ra_key"]!=entry["ra_key"] or manifest["tally_key"]!=entry["tally_key"]:raise AdminError(409)
        result=self.publisher.prepare(UUID(row["election_id"]),raw,sig,b64decode(entry["ra_key"]["spki"]),entry["private_key_reference"],UUID(actor))
        if result!={"config_hash":digest}:raise AdminError(503)
        return digest
    def finalize(self,token,election,revision,keyset):
        identity=self._authorize(token)
        with self.voting.operation(token_digest(token),election) as operation:
            row=operation.read()
            if row["phase"]=="DRAFT":
                entry=self.keysets.get(keyset)
                if entry is None:raise AdminError(422)
                manifest={"domain":"secure-evoting-election-manifest-v1","version":1,"election_id":str(election),
                    "opens_at":row["opens_at"],"closes_at":row["closes_at"],"candidates":row["candidates"],
                    "ra_key":entry["ra_key"],"tally_key":entry["tally_key"],"profile":PROFILE}
                raw=canonical_manifest(manifest)
                row=operation.mutate("reserve",{"revision":revision,"keyset_id":keyset,"manifest_hex":raw.hex()})
            elif row["keyset_id"]!=keyset or row["revision"]!=revision:raise AdminError(409)
            if row["phase"]=="FINALIZING":
                manifest=strict_json(bytes.fromhex(row["manifest_hex"]))
                sig=self.authority.sign(manifest)
                fingerprint=hashlib.sha256(self.authority.private.public_key().public_bytes(
                    serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
                row=operation.mutate("freeze",{"config_hash":row["config_hash"],"signature_hex":sig.hex(),"authority_fingerprint":fingerprint})
            if row["phase"] not in ("FROZEN","OPEN"):raise AdminError(409)
            self._prepare_ra(row,identity["admin_id"])
            return self.public(row)
    def transition(self,token,election,closed):
        identity=self._authorize(token)
        with self.voting.operation(token_digest(token),election) as operation:
            row=operation.read()
            if closed:
                # Stop acceptance FIRST, including when RA is unavailable.
                row=operation.mutate("close",{})
                digest=self._prepare_ra(row,identity["admin_id"])
            else:
                if row["phase"] not in ("FROZEN","OPEN"):raise AdminError(409)
                digest=self._prepare_ra(row,identity["admin_id"])
                row=operation.mutate("open",{"ra_hash":digest})
            reply=self.publisher.reconcile(election,bytes.fromhex(digest),closed,UUID(identity["admin_id"]))
            if reply!={"config_hash":digest,"enabled":not closed,"closed":closed}:raise AdminError(503)
            row=operation.mutate("ack",{"ra_hash":digest})
            return self.public(row)
