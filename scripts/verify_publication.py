"""Offline verification using an explicitly independently obtained public trust file."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.board.launcher import load_trust
from backend.board.verification import BoardError, MAX_BYTES, decode, verify, receipt_status


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle",type=Path,required=True)
    parser.add_argument("--trusted-keys",type=Path,required=True)
    parser.add_argument("--election-id",required=True)
    parser.add_argument("--receipt")
    args=parser.parse_args(argv)
    try:
        trust=load_trust(args.trusted_keys)
        with args.bundle.open("rb") as stream: raw=stream.read(MAX_BYTES+1)
        bundle=verify(decode(raw),args.election_id,trust)
        status="VERIFIED" if args.receipt is None else receipt_status(bundle,args.election_id,args.receipt,trust)
    except BoardError as error:status="UNVERIFIED" if error.code=="UNVERIFIED" else "INVALID"
    except OSError:status="UNAVAILABLE"
    except Exception:status="INVALID"
    print(json.dumps({"status":status}))
    return {"VERIFIED":0,"NOT_FOUND":3,"UNVERIFIED":2,"UNAVAILABLE":2,"INVALID":1}[status]


if __name__=="__main__":raise SystemExit(main())
