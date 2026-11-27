"""Hosted-only validation of local DB adapters; NEVER a local VM deployer.

Fresh named/marked containers exercise the real local-name/port contract. This
does not fabricate VM or Windows SSH evidence. All resources/keys are CI-owned;
only this test coordinator removes its own resources in finally.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import timedelta
import hashlib
import logging
from pathlib import Path
import secrets
import sys
import time
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import psycopg
from pydantic import SecretStr
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from backend.admin.store import RAPublisherStore
from backend.crypto.credential_protocol import b64encode, b64decode, verify_credential
from backend.ra.credential_recovery import CredentialRecovery
from backend.ra.credential_service import CredentialIssuanceService
from backend.ra.credential_signer import LocalCIRCLSigner
from backend.ra.postgres_credential_store import PostgreSQLCredentialStore
from backend.ra.demo_session_service import DemoSessionService
from crypto_interop.gate import Peer, make_manifest, signed_bundle
from deployment.local_demo_policy import ROLE_DATABASE, SERVICES, database_spec, fingerprint, labels, new_plan, require
from deployment.local_runtime_apps import key_ids, public_keyset, ra_app
from deployment.local_runtime_boundary import OwnedContainers, PG_COMMAND
from deployment.local_runtime_custody import _materials, service_package
from deployment.local_runtime_database import IDENTITY_SQL, connection_factory
from deployment.local_runtime_migrations import migrate
from deployment.local_runtime_setup import bootstrap, install_operators
from deployment.local_runtime_voters import install
from scripts import voting_postgres_ci as ci
from scripts.local_demo_runtime import bind_election

STAGES = {'preflight','containers','bootstrap','migrations','voters','runtime_acl','authentication','issuance','restart','denials','cleanup'}


class HostedApproval:
    """Independent CI authorization, not a forged local VM approval."""
    def __init__(self, plan): self.digest = fingerprint(plan)
    def check(self, plan):
        ci.require_ci(); require(fingerprint(plan) == self.digest, 'IDENTITY')


def raw_connect(plan,kind,login,password,*,maintenance=False):
    ci.require_ci()
    spec = database_spec(plan,kind)
    require(login in {r for r,k in ROLE_DATABASE.items() if k == kind}|{kind+'_migrator_login','postgres','ra_service_login'}, 'ROLE')
    require(not maintenance or login == 'postgres', 'ROLE')
    conn = psycopg.connect(host='127.0.0.1',hostaddr='127.0.0.1',port=spec['port'],
        dbname='postgres' if maintenance else spec['name'],user=login,password=password.get_secret_value(),
        service='',passfile='/dev/null',sslmode='disable',connect_timeout=2,autocommit=maintenance,
        options='-c statement_timeout=30000 -c lock_timeout=3000')
    try:
        row = conn.execute(IDENTITY_SQL).fetchone()
        # initdb owns the maintenance DB's descriptive comment; it is not the
        # independent marker of the not-yet-created disposable application DB.
        expected = ('postgres','postgres','postgres','postgres') if maintenance else (spec['name'],login,login,spec['owner'],spec['marker'])
        require(row[:len(expected)] == expected and type(row[5]) is int and 180000 <= row[5] < 190000, 'IDENTITY')
        return conn
    except BaseException: conn.close(); raise


def run(node, signer, state):
    ci.require_ci(); ci.verify_dependencies()
    require(node.is_absolute() and signer.is_absolute() and node.is_file() and signer.is_file(), 'SOURCE')
    plan = new_plan(); approval = HostedApproval(plan)
    ids,volumes = {},[]; network_created = False
    passwords = {r:SecretStr(secrets.token_urlsafe(48)) for r in ROLE_DATABASE}
    passwords.update({r:SecretStr(secrets.token_urlsafe(48)) for r in ('ra_migrator_login','voting_migrator_login','ra_service_login')})
    boot = {kind:SecretStr(secrets.token_urlsafe(48)) for kind in ('ra','voting')}
    def checkpoint(stage):
        require(stage in STAGES); state[0] = stage
        print('PASS guarded_local_runtime checkpoint='+stage,flush=True)
    def setup(kind):
        def connect():
            owned.verify_container(kind)
            return raw_connect(plan,kind,kind+'_migrator_login',passwords[kind+'_migrator_login'])
        return connect
    try:
        state[0] = 'containers'
        ci.docker('pull',plan['postgres_image'],timeout=180)
        args = ['network','create','--internal','--driver','bridge','--label','secure-evoting-local-demo='+plan['identifiers']['profile'],
            '--label','secure-evoting-purpose=synthetic-only',plan['network']]
        ci.docker(*args); network_created = True
        for kind in ('ra','voting'):
            spec = database_spec(plan,kind)
            label_args = [item for key,value in labels(plan,kind).items() for item in ('--label',key+'='+value)]
            ci.docker('volume','create',*label_args,spec['volume']); volumes.append(kind)
            ids[kind] = ci.docker('run','--detach','--name',spec['container'],*label_args,'--network',plan['network'],
                '--publish','127.0.0.1:'+str(spec['port'])+':5432','--mount','type=volume,src='+spec['volume']+',dst=/var/lib/postgresql',
                '--tmpfs','/run/evote-secrets:rw,noexec,nosuid,nodev,mode=0755',
                '--env','POSTGRES_PASSWORD_FILE=/run/evote-secrets/bootstrap-password',
                '--env','POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer',
                '--entrypoint','/bin/sh',plan['postgres_image'],*PG_COMMAND)
            ci.docker('exec','--interactive',ids[kind],'/bin/sh','-ec',
                'umask 077; cat > /run/evote-secrets/bootstrap-password.tmp; chown postgres:postgres /run/evote-secrets/bootstrap-password.tmp; mv /run/evote-secrets/bootstrap-password.tmp /run/evote-secrets/bootstrap-password',
                input_text=boot[kind].get_secret_value())
        owned = OwnedContainers(plan,approval,ids)
        for kind in ('ra','voting'): owned.verify_container(kind)
        checkpoint('containers')
        state[0] = 'bootstrap'
        for kind in ('ra','voting'):
            for attempt in range(90):
                try:
                    with raw_connect(plan,kind,'postgres',boot[kind],maintenance=True): pass
                    break
                except psycopg.OperationalError:
                    require(attempt < 89,'LIFECYCLE'); time.sleep(0.5)
            bootstrap(plan,approval,kind,lambda kind=kind:raw_connect(plan,kind,'postgres',boot[kind],maintenance=True),
                {r:p for r,p in passwords.items() if r.startswith(kind+'_')},boundary=lambda kind=kind:owned.verify_container(kind),
                confirmation='BOOTSTRAP FRESH DEMO '+fingerprint(plan))
            with raw_connect(plan,kind,'postgres',boot[kind]) as conn:
                conn.execute('REVOKE ALL ON SCHEMA public FROM PUBLIC')
                conn.execute('CREATE SCHEMA '+kind+' AUTHORIZATION '+kind+'_owner')
        checkpoint('bootstrap'); state[0] = 'migrations'
        for kind in ('ra','voting'):
            migrate(plan,approval,kind,setup(kind),boundary=lambda kind=kind:owned.verify_container(kind),
                confirmation='MIGRATE OWNED DEMO '+fingerprint(plan))
        checkpoint('migrations'); state[0] = 'voters'
        identities = install(plan,approval,setup('ra'),boundary=lambda:owned.verify_container('ra'),
            confirmation='INSTALL TWO SYNTHETIC VOTERS '+fingerprint(plan))
        require(identities == install(plan,approval,setup('ra'),boundary=lambda:owned.verify_container('ra'),
            confirmation='INSTALL TWO SYNTHETIC VOTERS '+fingerprint(plan)))
        install_operators(plan,approval,setup('voting'),boundary=lambda:owned.verify_container('voting'),
            confirmation='ENROLL SYNTHETIC ADMIN TALLY PUBLISHER '+fingerprint(plan))
        checkpoint('voters'); state[0] = 'runtime_acl'
        factories = {}
        for service,spec in SERVICES.items():
            for login in spec['roles']:
                kind = ROLE_DATABASE[login]
                factories[login] = connection_factory(plan,service,login,passwords[login],boundary=lambda kind=kind:owned.verify_container(kind))
                with factories[login](): pass
        checkpoint('runtime_acl')
        credentials = {name:SecretStr(secrets.token_urlsafe(32)) for name in ('admin','tally','voter_a','voter_b')}
        payload = _materials(credentials)
        for login in ROLE_DATABASE: payload['passwords'][login] = passwords[login].get_secret_value()
        public = public_keyset(plan,{name:{k:v for k,v in entry.items() if k in {'spki','pin','fingerprint'}} for name,entry in payload['keys'].items()})['synthetic-local']
        manifest = make_manifest(public['ra_key'],public['tally_key'])
        manifest['election_id'] = str(uuid4()); manifest['ra_key'] = public['ra_key']; manifest['tally_key'] = public['tally_key']
        with setup('ra')() as conn: now = conn.execute('SELECT clock_timestamp()').fetchone()[0].replace(microsecond=0)
        manifest['opens_at'] = (now-timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
        manifest['closes_at'] = (now+timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        def key(name):
            entry = payload['keys'][name]
            return serialization.load_pem_private_key(entry['pem'].encode(),password=entry['unlock'].encode())
        bundle = signed_bundle(manifest,key('manifest_signing'))
        pin = b64decode(payload['keys']['manifest_signing']['pin'],32)
        import rfc8785
        raw = rfc8785.dumps(manifest); election = UUID(manifest['election_id'])
        publisher = RAPublisherStore(factories['ra_election_publisher_login'])
        publisher.prepare(election,raw,b64decode(bundle['signature'],64),b64decode(public['ra_key']['spki']),
            public['private_key_reference'],UUID(plan['identifiers']['admin']))
        bind_election(plan,payload,bundle,setup('ra'))
        publisher.reconcile(election,hashlib.sha256(raw).digest(),False,UUID(plan['identifiers']['admin']))
        state[0] = 'authentication'
        with ExitStack() as resources:
            native = LocalCIRCLSigner(signer,key('ra_signing'),key_ids(plan)['ra']); resources.callback(native.close)
            clients,tokens = [],[]
            for name,voter in (('ra_a','voter_a'),('ra_b','voter_b')):
                app = ra_app(plan,name,service_package(payload,name),factories,native,bundle)
                client = resources.enter_context(TestClient(app,base_url='http://127.0.0.1',client=('127.0.0.1',44000)))
                login = client.post('/api/v1/ra/auth/login',json={'username':'synthetic-'+voter,'password':credentials[voter].get_secret_value()})
                require(login.status_code == 200,'IDENTITY'); token = login.json()['access_token']
                require(client.get('/api/v1/ra/auth/me',headers={'Authorization':'Bearer '+token}).json() == {'voter_id':plan['identifiers'][voter]},'IDENTITY')
                clients.append(client); tokens.append(token)
            require(tokens[0] != tokens[1],'IDENTITY')
            for i,client in enumerate(clients):
                require(client.get('/api/v1/ra/auth/me',headers={'Authorization':'Bearer '+tokens[1-i]}).status_code == 401,'IDENTITY')
                extra = client.post('/api/v1/ra/auth/login',json={'username':'synthetic-'+('voter_a','voter_b')[i],
                    'password':credentials[('voter_a','voter_b')[i]].get_secret_value()})
                require(extra.status_code == 200,'IDENTITY'); expired_token = extra.json()['access_token']
                with setup('ra')() as conn:
                    conn.execute('SET LOCAL ROLE ra_owner')
                    row = conn.execute('SELECT voter_id,expires_at-created_at,created_at<=clock_timestamp(),expires_at>clock_timestamp() FROM ra.ra_sessions WHERE token_digest=%s',
                        (DemoSessionService._digest(tokens[i]),)).fetchone()
                    require(row == (UUID(plan['identifiers'][('voter_a','voter_b')[i]]),timedelta(minutes=15),True,True),'IDENTITY')
                    require(conn.execute("UPDATE ra.ra_sessions SET created_at=clock_timestamp()-interval '16 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE token_digest=%s AND voter_id=%s",
                        (DemoSessionService._digest(expired_token),UUID(plan['identifiers'][('voter_a','voter_b')[i]]))).rowcount == 1, 'IDENTITY')
                require(client.get('/api/v1/ra/auth/me',headers={'Authorization':'Bearer '+expired_token}).status_code == 401, 'IDENTITY')
            with factories['ra_auth_login']() as conn:
                third = uuid4(); digest = DemoSessionService._digest(secrets.token_urlsafe(32))
                require(conn.execute("SELECT ra_e2e_auth.find_voter(%s,'demo-local','demo-voter-003')",(third,)).fetchone() == (None,), 'IDENTITY')
                require(conn.execute('SELECT ra_e2e_auth.issue_session(%s,%s)',(third,digest)).fetchone() == (False,), 'IDENTITY')
                require(conn.execute('SELECT * FROM ra_e2e_auth.find_session(%s,%s)',(third,digest)).fetchall() == [], 'IDENTITY')
                require(conn.execute('SELECT ra_e2e_auth.revoke_session(%s,%s)',(third,digest)).fetchone() == (False,), 'IDENTITY')
                require(conn.execute("SELECT ra_demo.find_active_demo_voter_id('demo-local','demo-voter-002')").fetchone() == (None,), 'IDENTITY')
            checkpoint('authentication'); state[0] = 'issuance'
            peer = Peer([str(node),str(ROOT/'crypto_interop/dist/client.js')],'TS client'); resources.callback(peer.close)
            def prepare(): return peer.call(dict(op='prepare',bundle=bundle,pinned_root=b64encode(pin),expected_election=str(election),envelope_hash='a'*64))
            for i,client in enumerate(clients):
                prepared = prepare(); request = dict(election_id=str(election),request_id=str(uuid4()),blinded_msg=prepared['blinded_msg'])
                headers = {'Authorization':'Bearer '+tokens[i]}
                if i == 0:
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        responses = list(pool.map(lambda _:client.post('/api/v1/ra/credentials/issue',json=request,headers=headers),range(2)))
                    require(sorted(r.status_code for r in responses) == [200,201], 'IDENTITY')
                    response = next(r for r in responses if r.status_code == 201)
                else:
                    response = client.post('/api/v1/ra/credentials/issue',json=request,headers=headers)
                    require(response.status_code == 201,'IDENTITY')
                retry = client.post('/api/v1/ra/credentials/issue',json=request,headers=headers)
                require(retry.status_code == 200 and retry.json()['blind_sig'] == response.json()['blind_sig'],'IDENTITY')
                proof = peer.call(dict(op='finalize',handle=prepared['handle'],blind_sig=response.json()['blind_sig']))
                verify_credential(proof,bundle,pin,str(election),'a'*64)
                restarted = resources.enter_context(TestClient(ra_app(plan,('ra_a','ra_b')[i],service_package(payload,('ra_a','ra_b')[i]),
                    factories,native,bundle),base_url='http://127.0.0.1',client=('127.0.0.1',44001)))
                recovered = restarted.post('/api/v1/ra/credentials/issue',json=request,headers=headers)
                require(recovered.status_code == 200 and recovered.json()['blind_sig'] == response.json()['blind_sig'], 'IDENTITY')
                request['request_id'] = str(uuid4())
                require(client.post('/api/v1/ra/credentials/issue',json=request,headers=headers).status_code == 409,'IDENTITY')
            checkpoint('issuance'); state[0] = 'restart'
            install(plan,approval,setup('ra'),boundary=lambda:owned.verify_container('ra'),confirmation='INSTALL TWO SYNTHETIC VOTERS '+fingerprint(plan))
            with setup('ra')() as conn:
                conn.execute('SET LOCAL ROLE ra_owner')
                require(conn.execute('SELECT count(*) FROM ra.blind_issuances').fetchone() == (2,),'IDENTITY')
                require(conn.execute('SELECT count(*) FROM ra.credential_reservations').fetchone() == (2,),'IDENTITY')
            checkpoint('restart'); state[0] = 'denials'
            for login,factory in factories.items():
                kind = ROLE_DATABASE[login]
                try:
                    with factory() as conn: conn.execute('SELECT * FROM '+kind+'.'+('voters' if kind == 'ra' else 'accepted_ballots'))
                except psycopg.errors.InsufficientPrivilege as error: require(error.sqlstate == '42501','ROLE')
                else: require(False,'ROLE')
            for login in ('ra_issuance_login','ra_election_publisher_login'):
                try:
                    with factories[login]() as conn:
                        conn.execute("SELECT ra_e2e_auth.find_voter(%s,'demo-local','demo-voter-001')",(UUID(plan['identifiers']['voter_a']),))
                except psycopg.errors.InsufficientPrivilege as error: require(error.sqlstate == '42501','ROLE')
                else: require(False,'ROLE')
            with setup('ra')() as conn:
                conn.execute('SET LOCAL ROLE ra_owner')
                for login in ('ra_issuance_login','ra_election_publisher_login','ra_service_login','ra_recovery_worker','ra_audit_reader'):
                    require(conn.execute("SELECT bool_or(has_function_privilege(%s,p.oid,'EXECUTE')) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='ra_e2e_auth'",(login,)).fetchone() == (False,), 'ROLE')
            for i,client in enumerate(clients):
                require(client.post('/api/v1/ra/auth/logout',headers={'Authorization':'Bearer '+tokens[i]}).status_code == 204,'IDENTITY')
                require(client.get('/api/v1/ra/auth/me',headers={'Authorization':'Bearer '+tokens[i]}).status_code == 401,'IDENTITY')
            checkpoint('denials')
    finally:
        failed_stage = state[0] if sys.exc_info()[0] is not None else None
        state[0] = 'cleanup'
        # CI-only removal. Never called by local_runtime.py. Refuse every resource
        # whose creation ID, immutable image or exact labels no longer match.
        for kind,identifier in reversed(tuple(ids.items())):
            info = __import__('json').loads(ci.docker('inspect',identifier))[0]
            image = __import__('json').loads(ci.docker('image','inspect',plan['postgres_image']))[0]
            expected_labels = dict(image['Config'].get('Labels') or {}); expected_labels.update(labels(plan,kind))
            require(info['Id'] == identifier and info['Name'] == '/'+database_spec(plan,kind)['container']
                and info['Config']['Labels'] == expected_labels and info['Config']['Image'] == plan['postgres_image'],'OWNERSHIP')
            ci.docker('rm','--force',identifier)
        for kind in reversed(volumes):
            spec = database_spec(plan,kind)
            info = __import__('json').loads(ci.docker('volume','inspect',spec['volume']))[0]
            require(info['Labels'] == labels(plan,kind),'OWNERSHIP')
            ci.docker('volume','rm',spec['volume'])
        if network_created:
            info = __import__('json').loads(ci.docker('network','inspect',plan['network']))[0]
            require(info['Labels'] == {'secure-evoting-local-demo':plan['identifiers']['profile'],'secure-evoting-purpose':'synthetic-only'}
                and not info['Containers'],'OWNERSHIP')
            ci.docker('network','rm',plan['network'])
        checkpoint('cleanup')
        if failed_stage is not None: state[0] = failed_stage


def main():
    from scripts.local_demo_preflight import PublicArgumentParser
    parser = PublicArgumentParser(description=__doc__)
    parser.add_argument('--node',required=True,type=Path); parser.add_argument('--signer',required=True,type=Path)
    state = ['preflight']
    try:
        args = parser.parse_args(); logging.disable(logging.CRITICAL)
        run(args.node,args.signer,state); return 0
    except BaseException as error:
        state_label = state[0] if state[0] in STAGES else 'preflight'
        category = 'database_error' if isinstance(error,psycopg.Error) else 'assertion_error'
        sqlstate = getattr(error,'sqlstate',None)
        sqlstate = sqlstate if sqlstate in {'42501','28P01','3D000','23505','P4101','P4103'} else 'unavailable'
        print(f'FAIL guarded_local_runtime stage={state_label} category={category} sqlstate={sqlstate}',flush=True)
        return 1


if __name__ == '__main__': raise SystemExit(main())
