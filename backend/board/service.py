"""Separate publisher and read-only Board adapters; no RA or decryption access."""
import hashlib
from pathlib import Path

import rfc8785

from backend.admin.auth import token_digest
from backend.crypto.credential_protocol import b64decode, b64encode, uuid_string
from backend.board.verification import BoardError, MAX_BYTES, decode, from_input, publication_manifest, require, verify


class Store:
    QUERIES={"input":"SELECT voting_board.publication_input(%s::bytea,%s::uuid)",
        "finish":"SELECT voting_board.finish(%s::bytea,%s::uuid,%s::bytea,%s::bytea,%s::bytea)",
        "read":"SELECT voting_board.read_public(%s::uuid)",
        "list":"SELECT voting_board.catalogue(%s::uuid,%s::integer)"}
    def __init__(self,connect): self.connect=connect
    def call(self,name,*args):
        try:
            with self.connect() as conn:
                row=conn.execute(self.QUERIES[name],args).fetchone()
                if row is None or len(row)!=1: raise BoardError()
                result=row[0]
            return result  # Commit (including exceptions) precedes success.
        except BoardError: raise
        except Exception as error:
            status,code={"P6401":(401,"AUTHENTICATION"),"P6402":(403,"FORBIDDEN"),"P6403":(409,"CONFLICT"),
                "P6404":(404,"NOT_FOUND"),"P6405":(503,"INVALID"),"55P03":(409,"CONFLICT")}.get(getattr(error,"sqlstate",None),(503,"UNAVAILABLE"))
            raise BoardError(status,code) from None


class Publisher:
    def __init__(self,store,trust,sign,evidence_directory):
        trust.validate()
        self.store,self.trust,self.sign=store,trust,sign
        self.directory=Path(evidence_directory)

    def _evidence(self,bundle):
        # Original private Tally evidence is read-only. No Tally key is loaded.
        require(self.directory.is_dir() and not self.directory.is_symlink())
        snapshot=bundle["snapshot"]; meta=bundle["snapshot_evidence"]
        for name,expected in ((bundle["tally"]["report"]["snapshot_digest"]+".json",
                {"snapshot":snapshot,"manifest":meta["manifest"],"signature":meta["signature"]}),
            ("report-"+bundle["tally"]["report"]["snapshot_digest"]+".json",
                {"report":bundle["tally"]["report"],"signature":bundle["tally"]["signature"]})):
            path=self.directory/name
            require(not path.is_symlink())
            with path.open("rb") as stream: raw=stream.read(MAX_BYTES+1)
            require(raw==rfc8785.dumps(expected))

    def publish(self,token,election):
        uuid_string(election)
        try: digest=token_digest(token)
        except Exception: raise BoardError(401,"AUTHENTICATION") from None
        try:
            value=self.store.call("input",digest,election)
            if value["published_hex"] is not None:
                bundle=decode(bytes.fromhex(value["published_hex"]))
                verify(bundle,election,self.trust)
            else:
                bundle=from_input(value["input"],election)
                verify(bundle,election,self.trust,published=False)
                self._evidence(bundle)
                manifest=publication_manifest(bundle,self.trust)
                bundle["publication"]={"manifest":manifest,"signature":b64encode(self.sign(b"EVOTE-RESULTS-v1\0"+rfc8785.dumps(manifest)))}
                verify(bundle,election,self.trust)
                raw=rfc8785.dumps(bundle)
                committed=bytes(self.store.call("finish",digest,election,rfc8785.dumps(manifest),b64decode(bundle["publication"]["signature"],64),raw))
                require(committed==raw)
            return {"status":"PUBLISHED","election_id":election,"publication":bundle["publication"],
                "bundle_digest":hashlib.sha256(rfc8785.dumps(bundle)).hexdigest()}
        except BoardError: raise
        except (FileNotFoundError,PermissionError,OSError): raise BoardError(503,"UNAVAILABLE") from None
        except Exception: raise BoardError(503,"INVALID") from None


class Board:
    def __init__(self,store,trust): trust.validate();self.store,self.trust=store,trust
    def evidence(self,election):
        uuid_string(election)
        return verify(decode(bytes(self.store.call("read",election))),election,self.trust)
    def catalogue(self,cursor,limit):
        if cursor is not None: uuid_string(cursor)
        rows=self.store.call("list",cursor,limit+1)
        require(type(rows) is list and len(rows)<=limit+1)
        ids=[]
        for row in rows:
            require(set(row)=={"election_id","status"} and row["status"]=="PUBLISHED")
            uuid_string(row["election_id"]);ids.append(row["election_id"])
        require(ids==sorted(set(ids)) and (cursor is None or all(i>cursor for i in ids)))
        return {"elections":rows[:limit],"next_cursor":ids[limit-1] if len(rows)>limit else None}
