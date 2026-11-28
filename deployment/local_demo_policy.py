"""Offline local-demo review contract. No DB, Docker, sockets, keys or shell I/O.

Observation validators are predicates for a future approved collector. Supplied
JSON is never evidence of a live deployment, nor authorization to execute one.
"""
import ast
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
from uuid import UUID, uuid4

BASE = 'bd15d7dd659208bb9a8df18806d32b2322da1666'
ROOT = Path(__file__).resolve().parents[1]
CODES = {'CONFIG','ENVIRONMENT','SOURCE','IDENTITY','OWNERSHIP','ROLE','ASSET_BOUNDARY','LIFECYCLE','APPROVAL_REQUIRED'}
CONTAINER_POLICY_PREDICATES = frozenset({
    'policy_kind','policy_created_id','policy_database_spec','policy_observation','policy_network_name',
    'policy_container_id','policy_container_name','policy_image_reference','policy_labels',
    'policy_privileged','policy_network_mode','policy_pid_namespace','policy_ipc_namespace','policy_autoremove',
    'policy_configured_ports','policy_effective_ports','policy_persistent_mount','policy_environment',
})


class ReviewRefused(Exception):
    def __init__(self, code='CONFIG'):
        self.code = code if code in CODES else 'CONFIG'
        super().__init__('Local demo review refused')


def require(condition, code='CONFIG'):
    if not condition: raise ReviewRefused(code)


@contextmanager
def container_policy_check(identifier):
    """Fixed diagnostics only; this stdlib-only module performs no observation IO."""
    require(identifier in CONTAINER_POLICY_PREDICATES)
    try: yield
    except (KeyError,TypeError):
        error = ReviewRefused('OWNERSHIP')
        error.container_predicate = identifier
        raise error from None
    except ReviewRefused as error:
        error.container_predicate = identifier
        raise


def canonical(value):
    # Deployment fingerprint only, not a voting/signature wire-format function.
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def uuid4_string(value):
    try:
        parsed = UUID(value)
        require(type(value) is str and str(parsed) == value and parsed.version == 4)
        return value
    except (TypeError,ValueError,AttributeError): raise ReviewRefused() from None


def safe_environment(environment=None):
    environment = os.environ if environment is None else environment
    require(not any(k.upper().startswith(('PG','RA_DEMO_','VOTING_DEMO_','ADMIN_DEMO_','TALLY_DEMO_','BOARD_DEMO_',
        'PUBLICATION_DEMO_','VITE_','DOCKER_')) for k in environment),'ENVIRONMENT')


SOURCE_FILES = (
    'backend/main.py','backend/ra/demo_launcher.py','backend/ra/credential_launcher.py','backend/ra/demo_auth_runtime.py',
    'backend/ra/credential_service.py','backend/ra/credential_signer.py','backend/ra/credential_recovery.py',
    'backend/voting/local_launcher.py','backend/voting/ballot_service.py','backend/admin/launcher.py','backend/admin/service.py',
    'backend/tally/launcher.py','backend/tally/runtime.py','backend/tally/verification.py','backend/board/launcher.py',
    'backend/board/http.py','backend/board/service.py','backend/board/verification.py','backend/crypto/credential_protocol.py',
    'frontend/vite.config.ts','frontend/package-lock.json','crypto_interop/package-lock.json','crypto_interop/signer/go.mod',
    'crypto_interop/signer/go.sum','crypto_interop/signer/cmd/ra-credential-signer/main.go',
    'backend/voting/requirements.lock.txt','scripts/voting_postgres_ci.py','scripts/voting_tally_auth.py',
    'scripts/full_election_e2e.py','scripts/admin_publication_ui_ci.py','deployment/local_demo_policy.py',
    'deployment/local_demo_lifecycle.py','scripts/local_demo_preflight.py',
    'deployment/local_runtime_database.py','deployment/local_runtime_boundary.py','deployment/local_runtime_voters.py',
    'deployment/local_runtime_custody.py','deployment/local_runtime_processes.py','deployment/local_runtime_apps.py',
    'deployment/local_runtime_worker.py','deployment/local_runtime_migrations.py','deployment/local_migrations/env.py',
    'deployment/local_runtime_setup.py','deployment/local_runtime_containers.py','scripts/local_demo_runtime.py','scripts/guarded_local_runtime_ci.py',
    '.github/workflows/guarded-local-runtime.yml')
MIGRATION_FOLDERS = ('ra','admin_ra','voting','admin_voting','tally','board')


def source_fingerprint(root=ROOT):
    root = Path(root).resolve()
    files = [root/name for name in SOURCE_FILES]
    counts = dict(ra=14,admin_ra=1,voting=3,admin_voting=1,tally=1,board=1)
    for folder in MIGRATION_FOLDERS:
        migrations = sorted((root/'migrations'/folder/'versions').glob('*.py'))
        require(len(migrations) == counts[folder],'SOURCE'); files.extend(migrations)
    digest = hashlib.sha256(b'EVOTE-LOCAL-SOURCE-v1\0')
    for path in files:
        require(not path.is_symlink() and path.resolve().is_relative_to(root) and path.is_file(),'SOURCE')
        raw = path.read_bytes().replace(b'\r\n',b'\n'); require(len(raw) <= 2_000_000,'SOURCE')
        digest.update(canonical([path.relative_to(root).as_posix(),hashlib.sha256(raw).hexdigest()]))
    return digest.hexdigest()


def postgres_image(root=ROOT):
    # Reuse the exact reviewed CI image pin; no floating image or duplicated pin.
    tree = ast.parse((Path(root)/'scripts/voting_postgres_ci.py').read_text(encoding='utf8'))
    value = next(n.value.value for n in tree.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id == 'POSTGRES_IMAGE' for t in n.targets))
    require(type(value) is str and value.startswith('postgres:18-bookworm@sha256:') and len(value.rsplit(':',1)[1]) == 64,'SOURCE')
    return value


# Roles/assets are names only. No credential, passphrase, verifier digest or key
# contents are legal in this public review plan. Existing services enforce auth.
SERVICES = {
    'admin': dict(port=8002,roles=['voting_admin_login','ra_election_publisher_login'],keys=['manifest_signing'],verifiers=['admin'],evidence='none'),
    'voting': dict(port=8001,roles=['voting_ballot_login'],keys=[],verifiers=[],evidence='none'),
    'tally': dict(port=8005,roles=['voting_tally_login'],keys=['tally_decryption','evidence_signing'],verifiers=['tally'],evidence='read-write'),
    'publisher': dict(port=8007,roles=['voting_publication_login'],keys=['publication_signing'],verifiers=[],evidence='read-only'),
    'board': dict(port=8006,roles=['voting_board_login'],keys=[],verifiers=[],evidence='none'),
    'ra_a': dict(port=8000,roles=['ra_auth_login','ra_issuance_login'],keys=['ra_signing','ra_recovery'],verifiers=['voter_a'],evidence='none'),
    'ra_b': dict(port=8003,roles=['ra_auth_login','ra_issuance_login'],keys=['ra_signing','ra_recovery'],verifiers=['voter_b'],evidence='none'),
    'web_admin': dict(port=5173,roles=[],keys=[],verifiers=[],evidence='none'),
    'web_a': dict(port=5174,roles=[],keys=[],verifiers=[],evidence='none'),
    'web_b': dict(port=5175,roles=[],keys=[],verifiers=[],evidence='none')}
ROLE_DATABASE = {role:('ra' if role.startswith('ra_') else 'voting') for spec in SERVICES.values() for role in spec['roles']}
IDENTIFIERS = {'profile','ra_marker','voting_marker','voter_a','voter_b','admin','tally'}


def build_plan(identifiers, root=ROOT):
    require(type(identifiers) is dict and set(identifiers) == IDENTIFIERS)
    for value in identifiers.values(): uuid4_string(value)
    require(len(set(identifiers.values())) == len(IDENTIFIERS))
    suffix = UUID(identifiers['profile']).hex
    databases = {kind:dict(name=kind+'_demo_local_'+suffix,owner=kind+'_owner',host='127.0.0.1',
        port=55432+index,container='evote-local-'+suffix+'-'+kind,volume='evote-local-'+suffix+'-'+kind+'-data',
        marker='secure-evoting-local-disposable:'+identifiers[kind+'_marker']) for index,kind in enumerate(('ra','voting'))}
    return dict(version=1,purpose='synthetic-only',mode='review-only',execution_ready=False,reviewed_base=BASE,
        source_digest=source_fingerprint(root),identifiers=dict(identifiers),
        platform='windows11-dedicated-ubuntu24.04-vm',postgres_image=postgres_image(root),databases=databases,
        network='evote-local-'+suffix,vm_requirements=dict(host_shares=False,host_database_forwarding=False,docker_socket_to_apps=False),
        services=json.loads(canonical(SERVICES)),database_storage='owned-named-volume-preserve-on-stop',
        web_targets=dict(web_admin=dict(admin='http://127.0.0.1:8002',tally='http://127.0.0.1:8005',
            publisher='http://127.0.0.1:8007',board='http://127.0.0.1:8006'),
            web_a=dict(ra='http://127.0.0.1:8000',voting='http://127.0.0.1:8001'),
            web_b=dict(ra='http://127.0.0.1:8003',voting='http://127.0.0.1:8001')),
        windows_forward=dict(bind='127.0.0.1',ports=[5173,5174,5175],transport='host-key-pinned-ssh-local-forward'),
        keys='generate-fresh-only-after-approval',voters=['demo-local/demo-voter-001','demo-local/demo-voter-002'],
        migration_heads=dict(ra='bf932d0f8702',voting='f8b31c2d970a'))


def new_plan(root=ROOT): return build_plan({name:str(uuid4()) for name in sorted(IDENTIFIERS)},root)


def validate_plan(value, root=ROOT):
    require(type(value) is dict and 'identifiers' in value)
    require(canonical(value) == canonical(build_plan(value['identifiers'],root)))
    return value


def fingerprint(plan): return hashlib.sha256(b'EVOTE-LOCAL-PLAN-v1\0'+canonical(plan)).hexdigest()


def validate_assets(service, roles, keys, verifiers, evidence):
    require(service in SERVICES,'ASSET_BOUNDARY')
    spec = SERVICES[service]
    require(list(roles) == spec['roles'] and list(keys) == spec['keys'] and list(verifiers) == spec['verifiers']
        and evidence == spec['evidence'],'ASSET_BOUNDARY')


def database_spec(plan, kind):
    require(kind in ('ra','voting'),'IDENTITY')
    profile = uuid4_string(plan['identifiers']['profile']); marker = uuid4_string(plan['identifiers'][kind+'_marker'])
    suffix = UUID(profile).hex
    expected = dict(name=kind+'_demo_local_'+suffix,owner=kind+'_owner',host='127.0.0.1',port=55432+('ra','voting').index(kind),
        container='evote-local-'+suffix+'-'+kind,volume='evote-local-'+suffix+'-'+kind+'-data',
        marker='secure-evoting-local-disposable:'+marker)
    require(plan['databases'][kind] == expected,'IDENTITY')
    return expected


def validate_database_identity(plan, service, login, row):
    require(service in SERVICES and login in SERVICES[service]['roles'],'ROLE')
    spec = database_spec(plan,ROLE_DATABASE[login])
    # Fresh trusted-collector projection of current_database/session_user/
    # current_user/db owner/independent DB comment/server_version_num.
    require(type(row) is tuple and len(row) == 6 and row[:5] ==
        (spec['name'],login,login,spec['owner'],spec['marker']) and type(row[5]) is int and 180000 <= row[5] < 190000,'IDENTITY')


def labels(plan, kind):
    return {'secure-evoting-local-demo':plan['identifiers']['profile'],'secure-evoting-purpose':'synthetic-only',
        'secure-evoting-kind':kind,'secure-evoting-marker':database_spec(plan,kind)['marker']}


def validate_container(plan, kind, created_id, observed):
    """Check a normalized trusted-collector projection, not raw inspect JSON.

    Env must include EVERY actual override/addition relative to the inspected
    pinned image's defaults. Mounts must retain EVERY actual mount. A future
    collector must be reviewed/tested; these predicates cannot authenticate it.
    """
    import re
    with container_policy_check('policy_kind'):
        require(kind in ('ra','voting'),'OWNERSHIP')
    with container_policy_check('policy_created_id'):
        require(type(created_id) is str and re.fullmatch('[0-9a-f]{64}',created_id) is not None,'OWNERSHIP')
    with container_policy_check('policy_database_spec'):
        spec = database_spec(plan,kind)
    with container_policy_check('policy_observation'):
        config,host = observed['Config'],observed['HostConfig']
    with container_policy_check('policy_network_name'):
        require(plan['network'] == 'evote-local-'+UUID(plan['identifiers']['profile']).hex,'OWNERSHIP')
    with container_policy_check('policy_container_id'):
        require(observed['Id'] == created_id,'OWNERSHIP')
    with container_policy_check('policy_container_name'):
        require(observed['Name'] == '/'+spec['container'],'OWNERSHIP')
    with container_policy_check('policy_image_reference'):
        require(config['Image'] == plan['postgres_image'],'OWNERSHIP')
    with container_policy_check('policy_labels'):
        require(config['Labels'] == labels(plan,kind),'OWNERSHIP')
    with container_policy_check('policy_privileged'):
        require(host['Privileged'] is False,'OWNERSHIP')
    with container_policy_check('policy_network_mode'):
        require(host['NetworkMode'] == plan['network'],'OWNERSHIP')
    with container_policy_check('policy_pid_namespace'):
        require(host['PidMode'] != 'host','OWNERSHIP')
    with container_policy_check('policy_ipc_namespace'):
        require(host['IpcMode'] != 'host','OWNERSHIP')
    with container_policy_check('policy_autoremove'):
        require(host['AutoRemove'] is False,'OWNERSHIP')
    with container_policy_check('policy_configured_ports'):
        expected = {'5432/tcp':[{'HostIp':'127.0.0.1','HostPort':str(spec['port'])}]}
        require(host['PortBindings'] == expected,'OWNERSHIP')
    with container_policy_check('policy_effective_ports'):
        require(observed['NetworkSettings']['Ports'] == expected,'OWNERSHIP')
    with container_policy_check('policy_persistent_mount'):
        # DB storage survives stop. No bind mounts/Windows paths/Docker socket.
        require(observed['Mounts'] == [dict(Type='volume',Name=spec['volume'],Destination='/var/lib/postgresql',RW=True)],'OWNERSHIP')
    with container_policy_check('policy_environment'):
        require(config['Env'] == ['POSTGRES_PASSWORD_FILE=/run/evote-secrets/bootstrap-password',
            'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer'],'OWNERSHIP')


def validate_volume(plan, kind, observed):
    require(kind in ('ra','voting'),'OWNERSHIP')
    require(type(observed) is dict and {'Name','Driver','Options','Labels'} <= set(observed),'OWNERSHIP')
    require(observed.get('Name') == database_spec(plan,kind)['volume'] and observed.get('Driver') == 'local'
        and observed.get('Options') in (None,{}) and observed.get('Labels') == labels(plan,kind),'OWNERSHIP')


def validate_network(plan, observed):
    require(plan['network'] == 'evote-local-'+UUID(uuid4_string(plan['identifiers']['profile'])).hex,'OWNERSHIP')
    require(observed == dict(Name=plan['network'],Driver='bridge',Internal=True,
        Labels={'secure-evoting-local-demo':plan['identifiers']['profile'],'secure-evoting-purpose':'synthetic-only'}),'OWNERSHIP')


def removal_review(plan, containers, volumes, confirmation):
    """Return exact identifiers for human review; NEVER remove/stop anything."""
    validate_plan(plan)
    require(confirmation == 'REMOVE '+fingerprint(plan),'APPROVAL_REQUIRED')
    require(set(containers) == set(volumes) == {'ra','voting'},'OWNERSHIP')
    for kind in ('ra','voting'):
        created_id, observed = containers[kind]
        validate_container(plan,kind,created_id,observed); validate_volume(plan,kind,volumes[kind])
    return tuple((containers[kind][0],plan['databases'][kind]['volume']) for kind in ('ra','voting'))
