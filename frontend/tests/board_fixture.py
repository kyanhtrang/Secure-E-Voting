"""Synthetic UI-only store with real signatures. NOT PostgreSQL E2E evidence."""
import argparse
import logging
import os
from pathlib import Path
import signal
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
import rfc8785
from backend.board.http import create_board_app
from backend.board.service import Board
from backend.crypto.credential_protocol import b64encode
from scripts.real_voting_e2e import child,http_service
from tests.board_helpers import evidence


class SyntheticStore:
    def __init__(self,value):self.value=value
    def call(self,name,*args):
        if name=='list':return [{'election_id':self.value.election,'status':'PUBLISHED'}] if args[0] is None else []
        if name=='read' and args[0]==self.value.election:return rfc8785.dumps(self.value.bundle)
        from backend.board.verification import BoardError
        raise BoardError(404,'NOT_FOUND')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-board-only',action='store_true',required=True);parser.parse_args()
    logging.disable(logging.CRITICAL)
    def stop(_signal,_frame):raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,stop)
    try:
        with tempfile.TemporaryDirectory(prefix='evote-board-ui-') as directory:
            value=evidence(Path(directory));trust=value.trust
            with http_service(create_board_app(Board(SyntheticStore(value),trust))) as origin:
                env=dict(os.environ,VITE_ENABLE_BOARD='true',BOARD_DEMO_TARGET=origin,VITE_MANIFEST_AUTHORITY_PIN=b64encode(trust.authority),
                    VITE_EVIDENCE_PIN=b64encode(trust.evidence),VITE_EVIDENCE_KEY_ID=trust.evidence_key_id,
                    VITE_PUBLICATION_PIN=b64encode(trust.publication),VITE_PUBLICATION_KEY_ID=trust.publication_key_id)
                with child(['node',str(ROOT/'frontend/node_modules/vite/bin/vite.js'),'--mode','local-demo','--host','127.0.0.1','--port','5191','--strictPort'],env=env,cwd=ROOT/'frontend') as process:
                    if process.wait()!=0:raise RuntimeError()
    except KeyboardInterrupt:pass
    except BaseException:raise SystemExit('Synthetic Board UI fixture failed') from None


if __name__=='__main__':main()
