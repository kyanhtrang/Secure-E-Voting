"""Explicit guarded Ubuntu-VM controller. No implicit provisioning or discovery.

This file is NOT executed by the offline preflight or by importing the project.
Every mutation requires its own interactive plan-bound confirmation. Container,
volume, VM and SSH creation/removal are deliberately outside this controller.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import sys
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import psycopg
from pydantic import SecretStr

from backend.admin.launcher import prompt
from backend.crypto.credential_protocol import strict_json, b64decode, verify_manifest
from deployment.local_demo_policy import SERVICES, ReviewRefused, database_spec, fingerprint, require, safe_environment
from deployment.local_runtime_apps import key_ids, public_keyset
from deployment.local_runtime_boundary import Approval, OwnedContainers, verify_vm
from deployment.local_runtime_custody import Custody, service_package
from deployment.local_runtime_database import IDENTITY_SQL
from deployment.local_runtime_migrations import migrate, setup_identity
from deployment.local_runtime_processes import Supervisor
from deployment.local_runtime_voters import install
from deployment.local_runtime_setup import bootstrap, install_operators
from scripts.local_demo_preflight import PublicArgumentParser, load_public_plan

FIELDS = {'approval','containers','accounts','custody_directory','registry_directory','tally_evidence','publisher_evidence',
          'python','python_digest','node','node_digest','signer','signer_digest'}


def contract(path, plan):
    path = Path(path)
    require(path.name == 'evote-local-runtime.json' and path.is_absolute(), 'CONFIG')
    for part in (path,*path.parents): require(not part.is_symlink(), 'OWNERSHIP')
    require(os.name == 'posix' and path.stat().st_uid == 0 and not path.stat().st_mode & 0o022, 'OWNERSHIP')
    for parent in path.parents: require(parent.stat().st_uid == 0 and not parent.stat().st_mode & 0o022, 'OWNERSHIP')
    with path.open('rb') as stream: raw = stream.read(32769)
    require(len(raw) <= 32768, 'CONFIG')
    value = strict_json(raw)
    require(type(value) is dict and set(value) == FIELDS and set(value['accounts']) == set(SERVICES), 'CONFIG')
    approval = Approval(**value['approval']); approval.check(plan)
    require(set(value['containers']) == {'ra','voting'}, 'OWNERSHIP')
    for account in value['accounts'].values():
        require(type(account) is list and len(account) == 2 and all(type(v) is int and v > 0 for v in account), 'OWNERSHIP')
    for name in ('custody_directory','registry_directory','tally_evidence','publisher_evidence','python','node','signer'):
        require(type(value[name]) is str and Path(value[name]).is_absolute(), 'CONFIG')
    return value,approval


def setup_factory(plan, kind, containers, password):
    """Trusted operator-only credential, never part of service_package()."""
    spec = database_spec(plan,kind)
    def connect():
        safe_environment(); containers.verify(kind)
        conn = psycopg.connect(host='127.0.0.1',hostaddr='127.0.0.1',port=spec['port'],dbname=spec['name'],
            user=kind+'_migrator_login',password=password.get_secret_value(),service='',passfile='/dev/null',
            sslmode='disable',connect_timeout=5,options='-c statement_timeout=30000 -c lock_timeout=3000')
        try: setup_identity(conn,plan,kind); return conn
        except BaseException: conn.close(); raise
    return connect


def confirm(action, plan):
    require(sys.stdin.isatty(), 'APPROVAL_REQUIRED')
    expected = action+' '+fingerprint(plan)
    require(input('Type '+expected+': ') == expected, 'APPROVAL_REQUIRED')
    return expected


def controller_lock(directory):
    import fcntl
    path = Path(directory)
    for part in (path,*path.parents): require(not part.is_symlink(), 'OWNERSHIP')
    require(path.stat().st_uid == 0 and stat.S_IMODE(path.stat().st_mode) == 0o700, 'OWNERSHIP')
    fd = os.open(path/'controller.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        status = os.fstat(fd)
        require(status.st_uid == 0 and status.st_nlink == 1 and stat.S_IMODE(status.st_mode) == 0o600, 'OWNERSHIP')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return fd
    except BaseException: os.close(fd); raise


def mirror_evidence(source, destination, tally_uid, publisher_gid):
    """Copy immutable encrypted/signed artifacts, never keys or plaintext votes.

    Root-owned read-only mirror compensates for the original EvidenceVault's
    private 0600 files without changing its permissions or production behavior.
    Publisher verifies each byte against committed signed DB evidence as before.
    """
    import re
    require(os.geteuid() == 0, 'OWNERSHIP')
    source,destination = Path(source),Path(destination)
    for path in (source,destination):
        for part in (path,*path.parents): require(not part.is_symlink(), 'OWNERSHIP')
    require(source.stat().st_uid == tally_uid and stat.S_IMODE(source.stat().st_mode) == 0o700
        and destination.stat().st_uid == 0 and destination.stat().st_gid == publisher_gid
        and stat.S_IMODE(destination.stat().st_mode) == 0o750, 'OWNERSHIP')
    for path in source.iterdir():
        require(re.fullmatch(r'(?:report-)?[a-f0-9]{64}\.json',path.name) is not None and not path.is_symlink(), 'SOURCE')
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            status = os.fstat(stream.fileno())
            require(stat.S_ISREG(status.st_mode) and status.st_uid == tally_uid and status.st_nlink == 1
                and stat.S_IMODE(status.st_mode) == 0o600, 'OWNERSHIP')
            raw = stream.read(16*1024*1024+1)
            require(len(raw) <= 16*1024*1024, 'CONFIG')
        target = destination/path.name
        if target.exists():
            require(not target.is_symlink() and target.stat().st_uid == 0 and target.stat().st_gid == publisher_gid
                and stat.S_IMODE(target.stat().st_mode) == 0o640 and target.read_bytes() == raw, 'IDENTITY')
            continue
        fd = os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
        with os.fdopen(fd,'wb') as stream:
            os.fchown(stream.fileno(),0,publisher_gid); os.fchmod(stream.fileno(),0o640)
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def bind_election(plan, payload, bundle, setup):
    """Separate trusted fixture operation; no election/accepted ballot is seeded."""
    manifest,_ = verify_manifest(bundle,b64decode(payload['keys']['manifest_signing']['pin'],32),bundle['manifest']['election_id'])
    approved = public_keyset(plan,Custody.public_inventory(payload))['synthetic-local']
    require(manifest['ra_key'] == approved['ra_key'] and manifest['tally_key'] == approved['tally_key'], 'IDENTITY')
    election = UUID(manifest['election_id'])
    with setup() as conn:
        conn.execute('SET LOCAL ROLE ra_owner')
        row = conn.execute('SELECT manifest_bytes,signature FROM ra_admin.publications WHERE election_id=%s AND NOT closed',(election,)).fetchone()
        import rfc8785
        require(row is not None and bytes(row[0]) == rfc8785.dumps(manifest) and bytes(row[1]) == b64decode(bundle['signature'],64), 'IDENTITY')
        for key in ('voter_a','voter_b'):
            require(conn.execute('SELECT ra.set_voter_eligibility(%s,%s,true,%s)',
                (UUID(plan['identifiers'][key]),election,UUID(plan['identifiers']['admin']))).fetchone() == (True,), 'IDENTITY')
    return election


def run(plan, config, approval, containers, payload):
    registry = Path(config['registry_directory'])/('processes-'+uuid4().hex+'.jsonl')
    supervisor = Supervisor(plan,approval,containers,config['accounts'],registry,config['python'],config['python_digest'])
    def start(service, **extra):
        supervisor.start(service,dict(service=service,plan=plan,package=service_package(payload,service),**extra))
    try:
        start('voting'); start('admin'); start('tally',evidence_directory=config['tally_evidence'])
        start('publisher',evidence_directory=config['publisher_evidence']); start('board')
        start('web_admin',node=config['node'],node_digest=config['node_digest'])
        print('READY core; create/finalize the synthetic election in Admin UI',flush=True)
        # Only a public signed bundle path is accepted, never bearer/payload/DSN.
        bundle_path = Path(input('Absolute reviewed public election bundle (.json): '))
        require(bundle_path.is_absolute() and bundle_path.name == 'local-election-bundle.json' and not bundle_path.is_symlink(), 'CONFIG')
        with bundle_path.open('rb') as stream: raw = stream.read(32769)
        require(len(raw) <= 32768, 'CONFIG'); bundle = strict_json(raw)
        supervisor.check_ready()
        confirm('AUTHORIZE TWO SYNTHETIC VOTERS',plan)
        operator_material = Custody(config['custody_directory'],plan,approval).load(SecretStr(prompt('Custody passphrase for separate eligibility setup: ')))
        setup = setup_factory(plan,'ra',containers,SecretStr(operator_material['setup']['ra_migrator_login']))
        del operator_material
        bind_election(plan,payload,bundle,setup); del setup
        supervisor.ledger.bind_verified_election()
        for service in ('ra_a','ra_b'):
            start(service,signer=config['signer'],signer_digest=config['signer_digest'],election_bundle=bundle)
        for service in ('web_a','web_b'): start(service,node=config['node'],node_digest=config['node_digest'])
        print('READY voters; open/reconcile through Admin UI',flush=True)
        while True:
            action = input('Type sync-evidence after Tally, or stop: ')
            if action == 'stop': break
            require(action == 'sync-evidence', 'CONFIG')
            supervisor.check_ready()
            mirror_evidence(config['tally_evidence'],config['publisher_evidence'],
                config['accounts']['tally'][0],config['accounts']['publisher'][1])
            print('READY evidence mirror; publication still requires authorized Admin confirmation',flush=True)
    finally:
        refused = supervisor.stop()
        supervisor.registry.close()
        require(not refused, 'OWNERSHIP')
        print('STOPPED owned applications; databases/volumes/keys/evidence preserved',flush=True)


def main(argv=None):
    parser = PublicArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('inspect','generate-keys','export-public-pins','create-containers','start-containers','stop-containers',
        'migrate-ra','migrate-voting','install-voters','install-operators','bootstrap-ra','bootstrap-voting','run'))
    parser.add_argument('--public-plan',required=True,type=Path)
    parser.add_argument('--public-runtime',required=True,type=Path)
    control_fd = None
    try:
        args = parser.parse_args(argv); safe_environment()
        plan = load_public_plan(args.public_plan); config,approval = contract(args.public_runtime,plan)
        verify_vm(plan,approval)
        require(os.geteuid() == 0, 'OWNERSHIP')
        control_fd = controller_lock(config['registry_directory'])
        if args.action == 'generate-keys':
            confirmation = confirm('GENERATE DEMO KEYS',plan)
            credentials = {name:SecretStr(prompt('New synthetic '+name+' password (16+ characters): ')) for name in ('admin','tally','voter_a','voter_b')}
            Custody(config['custody_directory'],plan,approval).initialize(SecretStr(prompt('New custody passphrase (16+ characters): ')),
                credentials,confirmation=confirmation)
            print('CREATED encrypted custody; no private material printed'); return 0
        if args.action == 'export-public-pins':
            confirm('EXPORT DEMO PUBLIC PINS',plan)
            payload = Custody(config['custody_directory'],plan,approval).load(SecretStr(prompt('Custody passphrase: ')))
            public = Custody.public_inventory(payload); ids = key_ids(plan)
            import rfc8785
            values = {'public-trust.json':dict(authority=public['manifest_signing']['pin'],evidence=public['evidence_signing']['pin'],
                evidence_key_id=ids['evidence'],publication=public['publication_signing']['pin'],publication_key_id=ids['publication']),
                'public-key-fingerprints.json':public}
            for name,value in values.items():
                path = Path(config['registry_directory'])/name; raw = rfc8785.dumps(value)
                if path.exists(): require(not path.is_symlink() and path.stat().st_uid == 0 and path.read_bytes() == raw, 'IDENTITY')
                else:
                    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(fd,'wb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            print('EXPORTED public-only pins/fingerprints for independent review'); return 0
        if args.action == 'create-containers':
            from deployment.local_runtime_containers import create
            confirmation = confirm('CREATE OWNED DEMO CONTAINERS',plan)
            payload = Custody(config['custody_directory'],plan,approval).load(SecretStr(prompt('Custody passphrase: ')))
            identifiers = create(plan,approval,config['registry_directory'],
                {kind:SecretStr(payload['setup'][kind+'_bootstrap']) for kind in ('ra','voting')},confirmation=confirmation)
            # Public creation IDs only, for separately reviewed runtime contract.
            import json
            print(json.dumps({'containers':identifiers},sort_keys=True)); return 0
        containers = OwnedContainers(plan,approval,config['containers'])
        if args.action in {'start-containers','stop-containers'}:
            from deployment.local_runtime_containers import transition
            action = args.action.split('-')[0]
            confirmation = confirm(action.upper()+' OWNED DEMO CONTAINERS',plan)
            # Refuse DB lifecycle changes while any application listener remains,
            # including an orphan from a controller crash. Never adopt/kill it.
            for name in ('tcp','tcp6'):
                for line in Path('/proc/net/'+name).read_text().splitlines()[1:]:
                    fields = line.split()
                    require(fields[3] != '0A' or int(fields[1].split(':')[1],16) not in {s['port'] for s in SERVICES.values()}, 'LIFECYCLE')
            payload = Custody(config['custody_directory'],plan,approval).load(SecretStr(prompt('Custody passphrase: ')))
            transition(containers,action,{kind:SecretStr(payload['setup'][kind+'_bootstrap']) for kind in ('ra','voting')},confirmation=confirmation)
            print('PRESERVED owned containers/volumes/keys/evidence'); return 0
        for kind in ('ra','voting'): containers.verify(kind)
        if args.action == 'inspect': print('LIVE_GUEST_AND_CONTAINERS_VALIDATED; host controls require independent review'); return 0
        if args.action.startswith('bootstrap-'):
            from deployment.local_demo_policy import ROLE_DATABASE
            import secrets
            kind = args.action.split('-')[1]; spec = database_spec(plan,kind)
            confirmation = confirm('BOOTSTRAP FRESH DEMO',plan)
            payload = Custody(config['custody_directory'],plan,approval).load(SecretStr(prompt('Custody passphrase: ')))
            credentials = {r:SecretStr(p) for r,p in payload['passwords'].items() if ROLE_DATABASE[r] == kind}
            credentials[kind+'_migrator_login'] = SecretStr(payload['setup'][kind+'_migrator_login'])
            if kind == 'ra': credentials['ra_service_login'] = SecretStr(payload['setup']['ra_service_login'])
            bootstrap_password = SecretStr(payload['setup'][kind+'_bootstrap'])
            def maintenance():
                containers.verify(kind)
                return psycopg.connect(host='127.0.0.1',hostaddr='127.0.0.1',port=spec['port'],dbname='postgres',user='postgres',
                    password=bootstrap_password.get_secret_value(),service='',passfile='/dev/null',sslmode='disable',
                    connect_timeout=5,autocommit=True,options='-c statement_timeout=30000 -c lock_timeout=3000')
            bootstrap(plan,approval,kind,maintenance,credentials,boundary=lambda:containers.verify(kind),confirmation=confirmation)
            conn = psycopg.connect(host='127.0.0.1',hostaddr='127.0.0.1',port=spec['port'],dbname=spec['name'],user='postgres',
                password=bootstrap_password.get_secret_value(),service='',passfile='/dev/null',sslmode='disable',connect_timeout=5,
                options='-c statement_timeout=30000 -c lock_timeout=3000')
            with conn:
                row = conn.execute(IDENTITY_SQL).fetchone()
                require(row[:5] == (spec['name'],'postgres','postgres',spec['owner'],spec['marker']) and 180000 <= row[5] < 190000, 'IDENTITY')
                conn.execute('REVOKE ALL ON SCHEMA public FROM PUBLIC')
                conn.execute('CREATE SCHEMA '+kind+' AUTHORIZATION '+spec['owner'])
        elif args.action.startswith('migrate-'):
            confirmation = confirm('MIGRATE OWNED DEMO',plan); kind = args.action.split('-')[1]
            payload = Custody(config['custody_directory'],plan,approval).load(SecretStr(prompt('Custody passphrase: ')))
            setup = setup_factory(plan,kind,containers,SecretStr(payload['setup'][kind+'_migrator_login']))
            migrate(plan,approval,kind,setup,boundary=lambda:containers.verify(kind),confirmation=confirmation)
        elif args.action == 'install-voters':
            confirmation = confirm('INSTALL TWO SYNTHETIC VOTERS',plan)
            payload = Custody(config['custody_directory'],plan,approval).load(SecretStr(prompt('Custody passphrase: ')))
            setup = setup_factory(plan,'ra',containers,SecretStr(payload['setup']['ra_migrator_login']))
            install(plan,approval,setup,boundary=lambda:containers.verify('ra'),confirmation=confirmation)
        elif args.action == 'install-operators':
            confirmation = confirm('ENROLL SYNTHETIC ADMIN TALLY PUBLISHER',plan)
            payload = Custody(config['custody_directory'],plan,approval).load(SecretStr(prompt('Custody passphrase: ')))
            setup = setup_factory(plan,'voting',containers,SecretStr(payload['setup']['voting_migrator_login']))
            install_operators(plan,approval,setup,boundary=lambda:containers.verify('voting'),confirmation=confirmation)
        else:
            vault = Custody(config['custody_directory'],plan,approval)
            confirm('START GUARDED DEMO',plan)
            payload = vault.load(SecretStr(prompt('Custody passphrase: ')))
            # Discard setup credentials before service creation. Eligibility
            # setup below uses a separate explicit operator unlock.
            payload.pop('setup')
            run(plan,config,approval,containers,payload)
        return 0
    except BaseException as error:
        code = error.code if isinstance(error,ReviewRefused) else 'CONFIG'
        print('REFUSED local_runtime code='+code,file=sys.stderr); return 2
    finally:
        if control_fd is not None: os.close(control_fd)


if __name__ == '__main__': raise SystemExit(main())
