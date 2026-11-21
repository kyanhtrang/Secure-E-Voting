"""Hosted-only PostgreSQL 18 publication/Board gate. No selectable DB targets."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import logging
from pathlib import Path
import re
import secrets
import signal
import sys
import tempfile
from uuid import UUID,uuid4

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
import httpx
import psycopg
from pydantic import SecretStr
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import rfc8785

from backend.admin.auth import AdminAuthentication,token_digest
from backend.admin.store import VotingAdminStore
from backend.board.http import create_board_app,create_publication_app
from backend.board.launcher import EncryptedPublicationSigner
from backend.board.service import Board,Publisher,Store
from backend.board.verification import Trust,BoardError,from_input,publication_manifest,verify,receipt_status
from backend.crypto.credential_protocol import b64decode,b64encode
from backend.tally.runtime import TallyAuthentication,TallyStore,TallyService
from backend.tally.launcher import EncryptedTallyKey
from backend.tally.verification import EvidenceVault
from backend.voting.ballot_service import BallotService
from backend.voting.postgres_ballot_store import PostgreSQLBallotStore
from scripts import tally_postgres_ci as tally,admin_voter_e2e as guard
from tests.tally_helpers import material,ballot

HEAD='f8b31c2d970a'
STAGES={'preflight','provision','migrations','authorization','before_tally','tally','missing_evidence','rollback','concurrent_publish',
    'public_verification','tampering','immutability','acl','cleanup'}
check=guard.check


def runtime(owned,role,password):
    check(role in {'voting_publication_login','voting_board_login'},'Restricted Board runtime required')
    def connect():
        owned.verify()
        conn=psycopg.connect(host='127.0.0.1',port=owned.target.port,dbname=owned.target.database,user=role,
            password=password.get_secret_value(),connect_timeout=5,sslmode='disable',options='-c statement_timeout=30000 -c lock_timeout=3000')
        try:
            if role=='voting_board_login':conn.execute('SET TRANSACTION READ ONLY')
            return conn
        except BaseException:conn.close();raise
    return guard.real.guarded(connect,owned.target,'voting_owner',role)


def migrate(target,password):
    config=Config()
    config.set_main_option('script_location',str(ROOT/'scripts/ci_voting_migrations'))
    config.set_main_option('version_locations',' '.join(str(ROOT/f'migrations/{folder}/versions') for folder in ('voting','admin_voting','tally','board')))
    config.set_main_option('path_separator','space')
    graph=ScriptDirectory.from_config(config)
    check(graph.get_heads()==[HEAD] and len(list(graph.walk_revisions()))==6,'Unexpected Board migration graph')
    engine=create_engine('postgresql+psycopg://',creator=lambda:guard.real.vote_ci.connect(target,'voting_migrator_login',password),poolclass=NullPool,echo=False,hide_parameters=True)
    try:
        with engine.begin() as conn:
            config.attributes.update(connection=conn,disposable_database=target.database,disposable_marker=target.marker)
            command.upgrade(config,HEAD)
    finally:engine.dispose()


def aggregate_rows(fixture,election,expected):
    with fixture() as conn:
        check(conn.execute('SELECT status FROM voting.elections WHERE election_id=%s',(election,)).fetchone()==(expected,),'Lifecycle mismatch')
        count=1 if expected=='PUBLISHED' else 0
        for table in ('publications','voting_audit_events'):
            query='SELECT count(*) FROM voting.'+table+' WHERE election_id=%s'+(" AND event_type='ELECTION_PUBLISHED'" if table=='voting_audit_events' else '')
            check(conn.execute(query,(election,)).fetchone()==(count,),'Publication/audit count mismatch')


def harness(owned,passwords,directory,stage):
    fixture=guard.connection(owned,'voting_migrator_login',passwords['voting_migrator_login'],fixture=True)
    admin=guard.connection(owned,'voting_admin_login',passwords['voting_admin_login'])
    voting=guard.connection(owned,'voting_ballot_login',passwords['voting_ballot_login'])
    tally_runtime=tally.runtime(owned,passwords['voting_tally_login'])
    publisher=runtime(owned,'voting_publication_login',passwords['voting_publication_login'])
    reader=runtime(owned,'voting_board_login',passwords['voting_board_login'])
    principal,outsider,operator=uuid4(),uuid4(),uuid4()
    with fixture() as conn:
        for identity in (principal,outsider):conn.execute("INSERT INTO voting_admin.principals(admin_id,role,is_active) VALUES(%s,'ELECTION_ADMIN',true)",(identity,))
        conn.execute('INSERT INTO voting_board.publishers(admin_id,is_active) VALUES(%s,true)',(principal,))
        conn.execute("INSERT INTO voting_tally.principals(operator_id,role,is_active) VALUES(%s,'TALLY_OPERATOR',true)",(operator,))
    def authentication(cls,store,identity):
        password,salt=secrets.token_urlsafe(48),secrets.token_bytes(16)
        service=cls(store,identity,'synthetic-operator',salt,hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32))
        return service,service.login('synthetic-operator',password)
    admin_auth,token=authentication(AdminAuthentication,VotingAdminStore(admin),principal)
    _,other=authentication(AdminAuthentication,VotingAdminStore(admin),outsider)
    tally_auth,tally_token=authentication(TallyAuthentication,TallyStore(tally_runtime),operator)
    value=material();election=UUID(value.manifest['election_id'])
    tally.seed(fixture,value)
    snapshot_private,publication_private=ed25519.Ed25519PrivateKey.generate(),ed25519.Ed25519PrivateKey.generate()
    rawpin=lambda key:key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    trust=Trust(value.pin,rawpin(snapshot_private),'ci-evidence',rawpin(publication_private),'ci-publication')
    evidence=directory/'evidence';evidence.mkdir(mode=0o700)
    tally_path=directory/'test-tally.encrypted.pem';tally_unlock=guard.write_key(tally_path,value.tally)
    pub_path=directory/'test-publication.encrypted.pem';pub_unlock=guard.write_key(pub_path,publication_private)
    del publication_private
    tally_service=TallyService(tally_auth,TallyStore(tally_runtime),trust.authority,
        EvidenceVault(evidence,snapshot_private,trust.evidence,trust.evidence_key_id),EncryptedTallyKey(tally_path,tally_unlock,value.manifest['tally_key']['key_id']))
    pub_service=Publisher(Store(publisher),trust,EncryptedPublicationSigner(pub_path,pub_unlock,trust.publication),evidence)
    board_service=Board(Store(reader),trust)
    with guard.real.http_service(create_publication_app(pub_service)) as pub_origin,guard.real.http_service(create_board_app(board_service)) as board_origin:
        def publish(status,credential=token):
            with httpx.Client(trust_env=False,follow_redirects=False,timeout=45) as http:
                result=http.post(pub_origin+'/api/v1/publication/elections/'+str(election)+'/publish',json={},headers={'Authorization':'Bearer '+credential})
                check(result.status_code==status and result.headers.get('Cache-Control')=='no-store','Unexpected publication status')
                return result.json() if status==200 else None
        def get(path,status=200):
            with httpx.Client(trust_env=False,follow_redirects=False,timeout=30) as http:
                result=http.get(board_origin+'/api/v1/board'+path)
                check(result.status_code==status and result.headers.get('Cache-Control')=='no-store','Unexpected Board status')
                return result.json() if status==200 else None
        stage[0]='authorization';publish(401,tally_token);publish(403,other)
        stage[0]='before_tally';publish(409);get('/'+str(election)+'/results',404)
        accepted=[ballot(value),ballot(value,candidate=value.manifest['candidates'][1]['candidate_id']),ballot(value,invalid='aead')]
        voting_service=BallotService(PostgreSQLBallotStore(voting),value.pin)
        receipts=[voting_service.submit(payload) for payload in accepted]
        tally.close(fixture,election)
        stage[0]='tally';signed=tally_service.run(tally_token,election)
        check(signed['report']['accepted_total']==3 and signed['report']['valid_total']==2 and signed['report']['invalid_total']==1,'Unexpected real tally')
        check([row['vote_count'] for row in signed['report']['candidate_counts']]==[1,1],'Unexpected candidate counts')
        source=Store(publisher).call('input',token_digest(token),election)['input']
        stage[0]='missing_evidence'
        original=evidence/(signed['report']['snapshot_digest']+'.json');temporarily_hidden=evidence/'temporarily-unavailable.json'
        original.rename(temporarily_hidden)
        try:publish(503);aggregate_rows(fixture,election,'TALLIED')
        finally:temporarily_hidden.rename(original)
        bundle=from_input(source,str(election));manifest=publication_manifest(bundle,trust)
        signature=pub_service.sign(b'EVOTE-RESULTS-v1\0'+rfc8785.dumps(manifest))
        bundle['publication']={'manifest':manifest,'signature':b64encode(signature)}
        raw=rfc8785.dumps(bundle)
        args=(token_digest(token),election,rfc8785.dumps(manifest),signature,raw)
        stage[0]='rollback'
        with publisher() as conn:
            check(bytes(conn.execute(Store.QUERIES['finish'],args).fetchone()[0])==raw,'Pending publication mismatch')
            get('/'+str(election)+'/results',404)  # Another connection cannot observe uncommitted publication.
            conn.rollback()
        aggregate_rows(fixture,election,'TALLIED')
        stage[0]='concurrent_publish'
        with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda _:publish(200),range(4)))
        check(all(result==results[0] for result in results),'Concurrent publication conflict')
        check(publish(200)==results[0],'Idempotent publication changed')
        aggregate_rows(fixture,election,'PUBLISHED')
        stage[0]='public_verification'
        public=get('/'+str(election)+'/evidence');verify(public,str(election),trust)
        check(public['tally']=={k:signed[k] for k in ('report','report_digest','signature','signing_key_id')},'Published totals differ')
        check(get('/'+str(election)+'/results')['tally']==public['tally'],'Results endpoint differs')
        check(get('/'+str(election)+'/snapshots/final')==public['snapshot'] and get('/'+str(election)+'/snapshots/final/manifest')==public['snapshot_evidence'], 'Snapshot endpoints differ')
        check(get('/'+str(election)+'/configuration')==public['configuration'],'Configuration endpoint differs')
        public_text=rfc8785.dumps(public).decode()
        check(all(secret not in public_text for secret in (token,other,tally_token,str(principal),str(operator),*(p.get_secret_value() for p in passwords.values()))),'Identity/credential leaked into public artifacts')
        for receipt in receipts:
            check(receipt_status(public,str(election),receipt,trust)=='VERIFIED','Receipt inclusion failed')
            check(get('/'+str(election)+'/receipts/'+receipt)['record']['receipt_hash']==receipt,'Receipt endpoint mismatch')
        get('/'+str(election)+'/receipts/'+'0'*64,404)
        check(receipt_status(public,str(election),'0'*64,trust)=='NOT_FOUND','Unknown receipt result incorrect')
        page=get('/'+str(election)+'/ballots?limit=2');next_page=get('/'+str(election)+'/ballots?limit=2&cursor='+page['next_cursor'])
        check(len(page['records'])==2 and len(next_page['records'])==1 and next_page['next_cursor'] is None,'Pagination mismatch')
        check(get('')['elections']==[{'election_id':str(election),'status':'PUBLISHED'}],'Published catalogue mismatch')
        check(voting_service.recover(accepted[0])==receipts[0],'Original receipt recovery changed')
        stage[0]='tampering'
        import copy
        for field in ('snapshot','snapshot_evidence','tally','publication'):
            bad=copy.deepcopy(public)
            if field=='snapshot':bad[field]['ballots']=[]
            else:bad[field]['signature']='A'*86
            try:verify(bad,str(election),trust)
            except BoardError:pass
            else:raise AssertionError('Tampered evidence accepted')
        conflicting=copy.deepcopy(bundle);conflicting['publication']['signature']=b64encode(bytes(64))
        try:
            with publisher() as conn:conn.execute(Store.QUERIES['finish'],(*args[:3],bytes(64),rfc8785.dumps(conflicting)))
        except psycopg.Error as error:check(error.sqlstate=='P6403','Unexpected conflict classification')
        else:raise AssertionError('Conflicting publication accepted')
        stage[0]='immutability'
        for query,state in (("UPDATE voting.elections SET status='TALLIED' WHERE election_id=%s",'P6403'),
            ('UPDATE voting.publications SET manifest_bytes=manifest_bytes WHERE election_id=%s','P6405'),
            ('UPDATE voting.final_snapshots SET manifest_bytes=manifest_bytes WHERE election_id=%s','P5303'),
            ('UPDATE voting.tally_reports SET report_bytes=report_bytes WHERE election_id=%s','P5303'),
            ("DELETE FROM voting.voting_audit_events WHERE election_id=%s AND event_type='ELECTION_PUBLISHED'",'P6405')):
            try:
                with fixture() as conn:conn.execute(query,(election,))
            except psycopg.Error as error:check(error.sqlstate==state,'Unexpected immutability rejection')
            else:raise AssertionError('Immutable evidence changed')
        stage[0]='acl'
        for factory,expected in ((reader,{'read_public','catalogue'}),(publisher,{'publication_input','finish'}),(admin,set()),(tally_runtime,set()),(voting,set())):
            with factory() as conn:
                rows=conn.execute("SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='voting_board' AND has_function_privilege(current_user,p.oid,'EXECUTE')").fetchall()
                check({r[0] for r in rows}==expected,'Unexpected Board execution surface')
            for query in ('SELECT * FROM voting.accepted_ballots','DELETE FROM voting.publications','SELECT * FROM voting_board.evidence','SET ROLE voting_owner'):
                guard.real.deny(factory,query)
        with fixture() as conn:
            check(conn.execute("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname='voting_board' AND a.grantee=0").fetchone()==(0,),'PUBLIC execution allowed')
            check(conn.execute('SELECT count(*) FROM voting.accepted_ballots WHERE election_id=%s',(election,)).fetchone()==(3,),'Public reads modified ballots')
        admin_auth.logout(token)
        publish(401)
        print('PASS: board_postgres_ci checkpoints=authorization,tally,rollback,concurrent_publish,public_verification,tampering,immutability,acl',flush=True)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-ephemeral-ci-database',action='store_true',required=True)
    parser.parse_args(argv);stage=['preflight']
    try:
        root=guard.require_ci()
        logging.disable(logging.CRITICAL)
        def terminate(_signal,_frame):raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM,terminate)
        guard.real.vote_ci.verify_dependencies()
        with ExitStack() as resources:
            stage[0]='provision'
            target,bootstrap=resources.enter_context(guard.real.vote_ci.ephemeral_postgres())
            owned=guard.discover('voting',target)
            passwords={role:SecretStr(secrets.token_urlsafe(48)) for role in (*guard.real.vote_ci.LOGINS,'voting_admin_login','voting_tally_login','voting_publication_login','voting_board_login')}
            guard.real.vote_ci.bootstrap_database(target,bootstrap,{role:passwords[role] for role in guard.real.vote_ci.LOGINS})
            for role in ('voting_admin_login','voting_tally_login','voting_publication_login','voting_board_login'):
                guard.admin_ci.provision_role(guard.real.vote_ci,target,bootstrap,role,passwords[role])
            stage[0]='migrations';migrate(target,passwords['voting_migrator_login'])
            directory=Path(resources.enter_context(tempfile.TemporaryDirectory(prefix='evote-board-ci-',dir=root)))
            harness(owned,passwords,directory,stage)
            stage[0]='cleanup'
        check(not directory.exists() and owned.container_id not in guard.real.vote_ci.docker('ps','--all','--no-trunc','--format','{{.ID}}').splitlines(),'Owned cleanup incomplete')
        print('PASS: board_postgres_ci owned_container=removed')
    except BaseException as error:
        label=stage[0] if stage[0] in STAGES else 'preflight'
        root_error=getattr(error,'orig',None) or error;state=getattr(root_error,'sqlstate',None)
        if not isinstance(state,str) or re.fullmatch(r'[0-9A-Z]{5}',state) is None:state='unavailable'
        category='assertion' if isinstance(error,AssertionError) else 'database' if isinstance(root_error,psycopg.Error) else 'unavailable'
        raise SystemExit(f'FAIL: board_postgres_ci stage={label} category={category} sqlstate={state}') from None


if __name__=='__main__':main()
