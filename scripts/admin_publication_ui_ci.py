"""Hosted-only real Admin UI publication, reusing the complete two-voter gate."""
import argparse
from contextlib import contextmanager
import json
import logging
import os
from pathlib import Path
import re
import signal
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import httpx
from scripts import full_election_e2e as gate

check,real = gate.check,gate.real
BROWSER_FIELDS = {'origin','username','password','election_id','receipts'}


def browser_configuration(value):
    check(type(value) is dict and set(value) == BROWSER_FIELDS,"Restricted browser configuration required")
    check(re.fullmatch(r'http://127\.0\.0\.1:[0-9]{1,5}',value['origin']) is not None,"Loopback browser origin required")
    from backend.crypto.credential_protocol import uuid_string
    uuid_string(value['election_id'])
    check(type(value['receipts']) is list and len(value['receipts']) == 2 and len(set(value['receipts'])) == 2
        and all(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) is not None for v in value['receipts']),"Two distinct public receipts required")
    check(all(type(value[k]) is str and 0 < len(value[k]) <= 255 for k in ('username','password')),"Synthetic browser identity required")


@contextmanager
def frontend(node,admin,publisher,board,trust):
    gate.require_ci()
    for value in (admin,publisher,board):check(re.fullmatch(r'http://127\.0\.0\.1:[0-9]{1,5}',value) is not None,"Loopback upstream required")
    gate.trust_value(trust)
    with real.socket.socket() as reserved:
        reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1]
    env=dict(os.environ,VITE_ENABLE_ADMIN='true',ADMIN_DEMO_TARGET=admin,VITE_ENABLE_PUBLICATION='true',PUBLICATION_DEMO_TARGET=publisher,
        VITE_ENABLE_BOARD='true',BOARD_DEMO_TARGET=board,VITE_MANIFEST_AUTHORITY_PIN=trust['authority'],VITE_EVIDENCE_PIN=trust['evidence'],
        VITE_EVIDENCE_KEY_ID=trust['evidence_key_id'],VITE_PUBLICATION_PIN=trust['publication'],VITE_PUBLICATION_KEY_ID=trust['publication_key_id'])
    with real.child([str(node),str(ROOT/'frontend/node_modules/vite/bin/vite.js'),'--mode','local-demo','--host','127.0.0.1',
        '--port',str(port),'--strictPort'],env=env,cwd=ROOT/'frontend') as process:
        origin='http://127.0.0.1:'+str(port);deadline=real.time.monotonic()+30
        with httpx.Client(trust_env=False,follow_redirects=False,timeout=1) as client:
            while True:
                check(process.poll() is None and real.time.monotonic()<deadline,'Frontend readiness failed')
                try:
                    check(client.get(origin).status_code==200,'Frontend readiness failed');break
                except httpx.TransportError:real.time.sleep(.1)
        yield origin


class UIPublication(gate.Publication):
    def __init__(self,stage,node):super().__init__(stage);self.node=node

    @contextmanager
    def services(self,owned,passwords,db,directory,evidence,pin,snapshot_pin,principal,admin_origin,admin_config,admin_password,election,tally_token):
        with super().services(owned,passwords,db,directory,evidence,pin,snapshot_pin,principal,admin_origin,admin_config,admin_password,election,tally_token):
            self.browser_admin=(admin_origin,admin_config['username'],admin_password)
            yield self

    def before_publication(self,receipts):
        # Rollback has completed; no HTTP caller has yet published this election.
        gate.board_ci.aggregate_rows(self.db.voting_fixture,self.election,'TALLIED')
        admin,username,password=self.browser_admin
        with frontend(self.node,admin,self.pub_origin,self.board_origin,self.trust_config) as origin:
            config=dict(origin=origin,username=username,password=password,election_id=str(self.election),receipts=receipts)
            browser_configuration(config)
            with real.child([str(self.node),str(ROOT/'frontend/tests/real-admin-publication.mjs'),'--real-services-only']) as process:
                gate.journey.send(process,config)
                event=gate.journey.read_line(process,timeout=120)
                if type(event) is dict and set(event)=={'event','stage'} and event['event']=='failure':
                    allowed={'preflight','login','selection','confirmation','publication','public_verification'}
                    if event['stage'] in allowed:print('FAIL: admin_publication_ui browser_stage='+event['stage'],flush=True)
                check(event=={'event':'published_and_verified'} and process.wait(timeout=15)==0,'Real publication browser failed')
        gate.board_ci.aggregate_rows(self.db.voting_fixture,self.election,'PUBLISHED')
        print('PASS: admin_publication_ui checkpoint=published_and_public_verified',flush=True)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-ephemeral-ci-databases',action='store_true',required=True)
    parser.add_argument('--node',type=Path,required=True)
    parser.add_argument('--signer-binary',type=Path,required=True)
    args=parser.parse_args(argv);stage=['preflight']
    try:
        root=gate.require_ci();logging.disable(logging.CRITICAL)
        def terminate(_signal,_frame):raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM,terminate)
        real.vote_ci.verify_dependencies()
        check(args.node.is_file() and args.signer_binary.is_file() and not args.signer_binary.is_symlink()
            and args.signer_binary.resolve().is_relative_to(root),'Reviewed executables required')
        gate.journey.run(args.node,args.signer_binary,stage,publication=UIPublication(stage,args.node))
        print('PASS: admin_publication_ui checkpoint=cleanup',flush=True)
    except BaseException as error:raise SystemExit(gate.failure(stage[0],error).replace('full_election_e2e','admin_publication_ui')) from None


if __name__=='__main__':main()
