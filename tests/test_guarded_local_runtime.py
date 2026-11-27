"""Offline guard regressions. SQL doubles are NOT PostgreSQL/VM evidence."""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace
from unittest.mock import Mock, MagicMock
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr

from deployment import local_demo_policy as policy
from deployment import local_runtime_database as db
from deployment import local_runtime_boundary as boundary
from deployment import local_runtime_custody as custody
from deployment import local_runtime_apps as apps
from deployment import local_runtime_voters as voters
from deployment import local_runtime_processes as processes
from deployment import local_runtime_worker as worker
from scripts import local_demo_runtime as cli


@pytest.fixture
def plan(): return policy.new_plan()


def approval(plan):
    return boundary.Approval(policy.fingerprint(plan),'a'*32,str(uuid4()),str(uuid4()),
        'APPROVED dedicated VM; no shares; no host DB forwarding; dedicated pinned SSH')


def acl_connection(login):
    kind = policy.ROLE_DATABASE[login]
    rows = [(s,True,kind+'_owner',['search_path='+db.expected_path(s,kind)]) for s in sorted(db.RPCS[login])]
    schema = {'ra_auth_login':['ra_demo','ra_e2e_auth'],'ra_issuance_login':['ra_credential'],
        'ra_election_publisher_login':['ra_admin'],'voting_ballot_login':['voting'],'voting_admin_login':['voting_admin'],
        'voting_tally_login':['voting_tally'],'voting_publication_login':['voting_board'],'voting_board_login':['voting_board']}[login]
    answers = {'flags':(True,login == 'voting_ballot_login',False),
        'membership':[('voting_ballot_service',login,False,True,False)] if login == 'voting_ballot_login' else [],
        'capability':(True,True),'usage':[(s,) for s in schema], 'create':(False,), 'tables':(False,), 'functions':rows,'public':(False,)}
    conn = MagicMock(); conn.__enter__.return_value = conn
    def execute(sql, params=None):
        if 'SELECT rolcanlogin' in sql: key = 'flags'
        elif 'SELECT parent.rolname' in sql: key = 'membership'
        elif 'SELECT NOT(rolcanlogin' in sql: key = 'capability'
        elif 'SELECT nspname FROM' in sql: key = 'usage'
        elif 'has_database_privilege' in sql: key = 'create'
        elif 'pg_catalog.pg_class c' in sql: key = 'tables'
        elif 'p.prosecdef' in sql: key = 'functions'
        elif 'aclexplode' in sql: key = 'public'
        else: raise AssertionError('Unexpected guard query')
        return Mock(fetchone=lambda:answers[key],fetchall=lambda:answers[key])
    conn.execute.side_effect = execute
    return conn,answers


@pytest.mark.parametrize('login',list(db.RPCS))
def test_exact_reviewed_runtime_capabilities_pass_offline(login):
    conn,_ = acl_connection(login)
    db.check_acl(conn,login,policy.ROLE_DATABASE[login])


@pytest.mark.parametrize('field,value',[('flags',(True,False,True)),('membership',[('ra_owner','ra_auth_login',False,False,True)]),
    ('usage',[('ra_demo',),('ra_e2e_auth',),('public',)]),('create',(True,)),('tables',(True,)),('public',(True,))])
def test_unsafe_privilege_mutations_fail_closed(field,value):
    conn,answers = acl_connection('ra_auth_login'); answers[field] = value
    with pytest.raises(policy.ReviewRefused): db.check_acl(conn,'ra_auth_login','ra')


@pytest.mark.parametrize('field,value',[(1,False),(2,'postgres'),(3,['search_path=public,ra,pg_temp']),
    (3,['search_path=pg_catalog,ra_e2e_auth,ra,pg_temp','role=ra_owner'])])
def test_definer_metadata_cannot_be_relaxed(field,value):
    conn,answers = acl_connection('ra_auth_login')
    row = list(answers['functions'][0]); row[field] = value; answers['functions'][0] = tuple(row)
    with pytest.raises(policy.ReviewRefused): db.check_acl(conn,'ra_auth_login','ra')


def test_extra_overload_or_missing_function_fails():
    for extra in (True,False):
        conn,answers = acl_connection('ra_auth_login')
        if extra: answers['functions'].append(('ra_e2e_auth.find_voter(text,text,text)',True,'ra_owner',['search_path=pg_catalog,ra_e2e_auth,ra,pg_temp']))
        else: answers['functions'].pop()
        with pytest.raises(policy.ReviewRefused): db.check_acl(conn,'ra_auth_login','ra')


def test_sequence_and_table_privileges_have_case_guards_for_mixed_pg_class_types():
    conn,_ = acl_connection('voting_ballot_login'); db.check_acl(conn,'voting_ballot_login','voting')
    sql = next(call.args[0] for call in conn.execute.call_args_list if 'pg_catalog.pg_class c' in call.args[0])
    assert "CASE WHEN c.relkind IN ('r','p','v','m','f') THEN" in sql
    assert "WHEN c.relkind='S' THEN pg_catalog.has_sequence_privilege" in sql and 'ELSE false END' in sql


@pytest.mark.parametrize('field,value',[(0,'ra_db'),(1,'postgres'),(2,'ra_owner'),(3,'postgres'),(4,'unowned'),(5,170000),(5,190000)])
def test_connection_identity_is_rechecked_before_runtime_sql(plan,monkeypatch,field,value):
    spec = plan['databases']['ra']; row = [spec['name'],'ra_auth_login','ra_auth_login','ra_owner',spec['marker'],180000]
    row[field] = value
    conn = MagicMock(); conn.execute.return_value.fetchone.return_value = tuple(row)
    connect = Mock(return_value=conn); monkeypatch.setattr(db.psycopg,'connect',connect)
    factory = db.connection_factory(plan,'ra_a','ra_auth_login',SecretStr('synthetic-test-only'),boundary=Mock())
    with pytest.raises(policy.ReviewRefused): factory()
    conn.close.assert_called_once(); assert len(conn.execute.call_args_list) == 1


def test_no_ambient_libpq_discovery_and_every_connection_has_live_boundary(plan,monkeypatch):
    spec = plan['databases']['voting']
    conn = MagicMock(); conn.execute.return_value.fetchone.return_value = (spec['name'],'voting_ballot_login','voting_ballot_login','voting_owner',spec['marker'],180000)
    connect = Mock(return_value=conn); check = Mock()
    monkeypatch.setattr(db.psycopg,'connect',connect); monkeypatch.setattr(db,'check_acl',check)
    live = Mock(); factory = db.connection_factory(plan,'voting','voting_ballot_login',SecretStr('synthetic-test-only'),boundary=live)
    assert factory() is conn and factory() is conn
    assert live.call_count == check.call_count == 2
    assert connect.call_args.args == () and connect.call_args.kwargs['passfile'] == '/dev/null' and connect.call_args.kwargs['service'] == ''
    monkeypatch.setenv('PGSERVICE','SECRET_CANARY')
    with pytest.raises(policy.ReviewRefused) as caught: factory()
    assert connect.call_count == 2 and 'SECRET_CANARY' not in str(caught.value)


@pytest.mark.parametrize('role',['postgres','ra_owner','ra_migrator_login','voting_tally_login'])
def test_ra_factory_never_accepts_privileged_or_other_service_credentials(plan,role):
    with pytest.raises(policy.ReviewRefused): db.connection_factory(plan,'ra_a',role,SecretStr('synthetic-test-only'),boundary=Mock())


def test_offline_approval_is_not_live_vm_evidence(plan,monkeypatch):
    value = approval(plan); value.check(plan)
    monkeypatch.setattr(boundary.sys,'platform','win32')
    command = Mock(); monkeypatch.setattr(boundary,'command',command)
    with pytest.raises(policy.ReviewRefused): boundary.verify_vm(plan,value)
    command.assert_not_called()


def test_ssh_has_only_explicit_demo_key_pinned_host_and_three_loopback_forwards(tmp_path):
    args = boundary.ssh_arguments(tmp_path/'ssh', 'demo-vm.example', 'demooperator',tmp_path/'demo-only',tmp_path/'known-hosts')
    for control in ('IdentityAgent=none','ForwardAgent=no','IdentitiesOnly=yes','StrictHostKeyChecking=yes',
                    'ExitOnForwardFailure=yes','ProxyCommand=none','ProxyJump=none','GlobalKnownHostsFile=none'):
        assert control in args
    assert [args[i+1] for i,a in enumerate(args) if a == '-L'] == ['127.0.0.1:'+str(p)+':127.0.0.1:'+str(p) for p in (5173,5174,5175)]
    assert '-R' not in args and '-A' not in args and not any('5432' in a for a in args)
    with pytest.raises(policy.ReviewRefused): boundary.ssh_arguments(tmp_path/'ssh','-oUnsafe','demo',tmp_path/'key',tmp_path/'pin')


def test_custody_authenticated_encryption_binds_profile_and_never_contains_plaintext(plan):
    secret = SecretStr('generated-test-custody-passphrase')
    blob = custody.seal(plan,{'recovery':'TEST_ONLY_SECRET_CANARY'},secret)
    assert b'TEST_ONLY_SECRET_CANARY' not in blob
    assert custody.unseal(plan,blob,secret) == {'recovery':'TEST_ONLY_SECRET_CANARY'}
    for altered,password in ((blob[:-1]+bytes([blob[-1]^1]),secret),(blob,SecretStr('incorrect-test-unlock'))):
        with pytest.raises(policy.ReviewRefused) as caught: custody.unseal(plan,altered,password)
        assert 'TEST_ONLY_SECRET_CANARY' not in str(caught.value)
    other = policy.new_plan()
    with pytest.raises(policy.ReviewRefused): custody.unseal(other,blob,secret)


@pytest.fixture(scope='module')
def materials():
    return custody._materials({name:SecretStr('synthetic-private-'+name+'-test-only') for name in ('admin','tally','voter_a','voter_b')})


def test_matching_original_keys_and_recovery_are_retained_and_scoped(materials,plan):
    custody.validate_materials(materials)
    raw = custody.seal(plan,materials,SecretStr('generated-test-custody-passphrase'))
    loaded = custody.unseal(plan,raw,SecretStr('generated-test-custody-passphrase'))
    assert loaded == materials
    for service,spec in policy.SERVICES.items():
        package = custody.service_package(loaded,service); apps.validate_package(service,package)
        assert set(package['passwords']) == set(spec['roles'])
        assert ('recovery' in package) == (service in {'ra_a','ra_b'})
        assert set(package['keys']) == set(spec['keys'])-{'ra_recovery'}
    assert loaded['verifiers']['voter_a'] != loaded['verifiers']['voter_b']
    package = custody.service_package(loaded,'tally')
    package['keys']['tally_decryption'] = loaded['keys']['ra_signing']
    with pytest.raises(policy.ReviewRefused): apps.private_key(package,'tally_decryption')


def test_cross_service_asset_injection_fails_before_database_access(materials,plan):
    package = custody.service_package(materials,'board')
    package['passwords']['ra_auth_login'] = 'SYNTHETIC_CANARY'
    with pytest.raises(policy.ReviewRefused): apps.create_app(plan,'board',package,{},ExitStack())


@pytest.mark.parametrize('service',['web_admin','web_a','web_b'])
def test_web_only_gets_public_env_and_exact_reviewed_origins(service,materials,plan):
    env = worker.web_environment(plan,service,custody.Custody.public_inventory(materials))
    serialized = json.dumps(env)
    assert all(p not in serialized for p in materials['passwords'].values())
    assert materials['recovery'] not in serialized and 'PRIVATE KEY' not in serialized
    if service != 'web_admin': assert env['RA_DEMO_TARGET'] == plan['web_targets'][service]['ra']
    else: assert env['PUBLICATION_DEMO_TARGET'] == 'http://127.0.0.1:8007'


def install_connection(plan):
    conn = MagicMock(); conn.__enter__.return_value = conn
    def execute(sql, params=None):
        if sql == db.IDENTITY_SQL:
            spec = plan['databases']['ra']; one = (spec['name'],'ra_migrator_login','ra_migrator_login','ra_owner',spec['marker'],180000); many = []
        elif 'version_num' in sql: one,many = None,[('bf932d0f8702',)]
        elif 'SELECT voter_id,auth_provider' in sql: one,many = None,[]
        elif 'to_regnamespace' in sql: one,many = (None,),[]
        elif 'p.proname,p.prosecdef' in sql:
            one,many = None,[(s.split('(')[0],True,True,['search_path=pg_catalog,ra_e2e_auth,ra,pg_temp']) for s in voters.SIGNATURES]
        else: one,many = (0,),[]
        return Mock(fetchone=lambda:one,fetchall=lambda:many)
    conn.execute.side_effect = execute
    return conn


def test_voter_install_is_approved_guarded_active_and_atomic_without_existing_demo_sql_changes(plan):
    conn = install_connection(plan); live = Mock(); setup = Mock(return_value=conn)
    with pytest.raises(policy.ReviewRefused): voters.install(plan,approval(plan),setup,boundary=live,confirmation='wrong')
    setup.assert_not_called(); live.assert_not_called()
    result = voters.install(plan,approval(plan),setup,boundary=live,confirmation='INSTALL TWO SYNTHETIC VOTERS '+policy.fingerprint(plan))
    assert len(set(result.values())) == 2 and live.call_count == 1
    sql = [c.args[0] for c in conn.execute.call_args_list]
    assert sql.index('SET LOCAL ROLE ra_owner') < sql.index('LOCK TABLE ra.voters IN SHARE ROW EXCLUSIVE MODE') < sql.index(voters.DDL)
    assert sum("INSERT INTO ra.voters" in s and 'true' in s for s in sql) == 2
    assert all('DELETE ' not in s and 'UPDATE ra.voters' not in s and 'CREATE OR REPLACE' not in s for s in sql)
    assert 'ra.create_session(digest,found_voter,created,created+interval \'15 minutes\')' in voters.DDL
    assert 's.voter_id=a.voter_id AND s.token_digest=digest' in voters.DDL
    assert voters.DDL == __import__('scripts.voting_tally_auth',fromlist=['DDL']).DDL


def test_failed_installer_identity_does_not_run_ddl(plan):
    conn = install_connection(plan)
    conn.execute.side_effect = None; conn.execute.return_value.fetchone.return_value = ('ra_db',)*6
    with pytest.raises(policy.ReviewRefused): voters.install(plan,approval(plan),lambda:conn,boundary=Mock(),
        confirmation='INSTALL TWO SYNTHETIC VOTERS '+policy.fingerprint(plan))
    assert [c.args[0] for c in conn.execute.call_args_list] == [db.IDENTITY_SQL]


def test_cli_refuses_windows_and_does_not_echo_arbitrary_arguments(capsys):
    assert cli.main(['--password','SYNTHETIC_SECRET_CANARY']) == 2
    output = capsys.readouterr()
    assert 'SYNTHETIC_SECRET_CANARY' not in output.out+output.err and 'REFUSED' in output.err


def test_physical_stop_uses_verified_pidfds_and_preserves_all_database_assets():
    supervisor = object.__new__(processes.Supervisor)
    supervisor.ledger = SimpleNamespace(closed=False,profile=str(uuid4()))
    supervisor.children = {}; supervisor._record = Mock()
    # Source contract complements actual Linux pidfd tests below; it cannot
    # substitute for an Ubuntu VM application lifecycle run.
    source = Path(processes.__file__).read_text()
    assert 'signal.pidfd_send_signal(pidfd,signal.SIGTERM)' in source
    assert 'os.kill(' not in source and 'SIGKILL' not in source.replace('# No SIGKILL','')
    assert supervisor.stop() == () and supervisor.ledger.closed


def test_pid_identity_mismatch_prevents_signal_and_leaves_owned_registry_entry(monkeypatch):
    supervisor = object.__new__(processes.Supervisor)
    ref = processes.ProcessRef(str(uuid4()),'voting',str(uuid4()),100,99,1000)
    process = Mock(); process.poll.return_value = None
    supervisor.ledger = SimpleNamespace(closed=False,profile=ref.profile)
    supervisor.children = {'voting':(process,10,ref)}; supervisor._record = Mock()
    monkeypatch.setattr(processes,'observe',Mock(return_value=None))
    signal_mock = Mock(); monkeypatch.setattr(processes.signal,'pidfd_send_signal',signal_mock,raising=False)
    assert supervisor.stop() == ('voting',) and 'voting' in supervisor.children
    signal_mock.assert_not_called(); supervisor._record.assert_not_called()


def test_new_ci_is_hosted_scoped_explicit_and_does_not_claim_vm_evidence():
    import yaml
    source = (policy.ROOT/'.github/workflows/guarded-local-runtime.yml').read_text()
    workflow = yaml.safe_load(source)
    assert workflow['on'] == {'push':{'branches':['feat/guarded-local-runtime']},'workflow_dispatch':None}
    assert workflow['permissions'] == {'contents':'read'}
    assert workflow['jobs']['guarded-local-runtime']['runs-on'] == 'ubuntu-24.04'
    for banned in ('secrets.','continue-on-error','upload-artifact','DOCKER_HOST:','GITHUB_ACTIONS:'):
        assert banned not in source


def test_function_contracts_match_unmodified_applied_migrations_and_reviewed_voter_ddl():
    sql = '\n'.join(p.read_text(encoding='utf8') for p in (policy.ROOT/'migrations').rglob('*.py'))+'\n'+voters.DDL
    found = {}
    for match in re.finditer(r'CREATE (?:OR REPLACE )?FUNCTION ([a-z0-9_.]+)\s*\((.*?)\)\s*RETURNS(.*?)AS \$',sql,re.S|re.I):
        name,args,body = match.groups()
        signature = name+'('+','.join(a.strip().split()[-1] for a in args.split(',') if a.strip())+')'
        path = re.search(r'SET search_path\s*=\s*([a-z0-9_, ]+)',body,re.I)
        if path: found[signature] = path[1].strip().replace(' ','')
    for login,signatures in db.RPCS.items():
        for signature in signatures:
            if signature.startswith(('ra_credential.reserve_request','ra_credential.lock_request')):
                migration = (policy.ROOT/'migrations/ra/versions/7b2d91a6c840_ra_credential_reservations.py').read_text()
                assert 'for name, create in' in migration or 'for name' in migration
                assert 'p_digest text,p_election uuid,p_request uuid,p_hash bytea,p_config bytea' in migration
                continue
            assert found[signature] == db.expected_path(signature,policy.ROLE_DATABASE[login])


def raw_container_fixture(plan,kind='ra'):
    from tests.test_local_demo_policy import observation
    actual = observation(plan,kind)
    actual.update(State={'Running':True},Image='sha256:'+'c'*64)
    actual['Config'].update(Entrypoint=['/bin/sh'],Cmd=boundary.PG_COMMAND)
    actual['Config']['Env'] = ['PATH=/usr/bin']+actual['Config']['Env']
    actual['HostConfig']['Tmpfs'] = {'/run/evote-secrets':'rw,noexec,nosuid,nodev,mode=0755'}
    actual['NetworkSettings']['Networks'] = {plan['network']:{}}
    image = {'Id':actual['Image'],'Config':{'Env':['PATH=/usr/bin'],'Labels':{'immutable-image-label':'public-metadata'}}}
    actual['Config']['Labels']['immutable-image-label'] = 'public-metadata'
    volume = dict(Name=plan['databases'][kind]['volume'],Driver='local',Options=None,Labels=policy.labels(plan,kind))
    network = dict(Name=plan['network'],Driver='bridge',Internal=True,
        Labels={'secure-evoting-local-demo':plan['identifiers']['profile'],'secure-evoting-purpose':'synthetic-only'})
    return actual,image,volume,network


def mock_secret_metadata(monkeypatch):
    def read(argv):
        if argv[-2:] == ['/bin/cat','/proc/self/mountinfo']:
            return b'37 24 0:30 / /run/evote-secrets rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,mode=755\n'
        if argv[-2:] == ['--','/run/evote-secrets']: return b'directory|755\n'
        if argv[-2:] == ['--','/run/evote-secrets/bootstrap-password']: return b'regular file|600|postgres|postgres|1|64\n'
        raise AssertionError('Unexpected metadata command')
    monkeypatch.setattr(boundary,'command',read)


@pytest.mark.parametrize('mutation',[None,'extra_environment','extra_mount','mutable_image','lan','unowned_volume','unsafe_logs','extra_network'])
def test_raw_docker_collector_retains_all_mounts_env_overrides_and_image_identity(plan,mutation,monkeypatch):
    mock_secret_metadata(monkeypatch)
    actual,image,volume,network = raw_container_fixture(plan)
    if mutation == 'extra_environment': actual['Config']['Env'].append('POSTGRES_PASSWORD=SYNTHETIC_CANARY')
    if mutation == 'extra_mount': actual['Mounts'].append({'Type':'bind','Destination':'/var/run/docker.sock'})
    if mutation == 'mutable_image': actual['Image'] = 'sha256:'+'d'*64
    if mutation == 'lan': actual['HostConfig']['PortBindings']['5432/tcp'][0]['HostIp'] = '0.0.0.0'
    if mutation == 'unowned_volume': volume['Options'] = {'device':'host-share'}
    if mutation == 'unsafe_logs': actual['Config']['Cmd'] = ['postgres','-c','log_statement=all']
    if mutation == 'extra_network': actual['NetworkSettings']['Networks']['host'] = {}
    owned = boundary.OwnedContainers(plan,approval(plan),{'ra':'a'*64,'voting':'b'*64})
    def inspect(*args):
        if args[0] == '--type=image': return image
        if args[0] == '--type=volume': return volume
        if args[0] == '--type=network': return network
        return actual
    monkeypatch.setattr(owned,'inspect',inspect)
    if mutation is None: assert len(owned.verify_container('ra')) == 64
    else:
        with pytest.raises(policy.ReviewRefused): owned.verify_container('ra')


@pytest.mark.parametrize('mutation',[None,'version','machine','boot','share','lan_listener','host_database_forward'])
def test_vm_probe_uses_observed_identity_mounts_and_listeners(plan,mutation,monkeypatch):
    value = approval(plan)
    observations = {'/etc/os-release':'ID=ubuntu\nVERSION_ID="24.04"',
        '/etc/machine-id':value.machine_id,'/sys/class/dmi/id/product_uuid':value.product_uuid,
        '/proc/sys/kernel/random/boot_id':value.boot_id,
        '/proc/self/mountinfo':'1 2 3 / / rw - ext4 /dev/demo rw',
        '/proc/net/tcp':'header\n','/proc/net/tcp6':'header\n'}
    if mutation == 'version': observations['/etc/os-release'] = 'ID=ubuntu\nVERSION_ID="22.04"'
    if mutation == 'machine': observations['/etc/machine-id'] = 'b'*32
    if mutation == 'boot': observations['/proc/sys/kernel/random/boot_id'] = str(uuid4())
    if mutation == 'share': observations['/proc/self/mountinfo'] = '1 2 3 / /share rw - virtiofs host rw'
    if mutation == 'lan_listener': observations['/proc/net/tcp'] += '0: 00000000:1F40 00000000:0000 0A\n'
    if mutation == 'host_database_forward': observations['/proc/net/tcp'] += '0: 0100007F:1538 00000000:0000 0A\n'  # 5432
    monkeypatch.setattr(boundary.sys,'platform','linux')
    monkeypatch.setattr(boundary.os,'pidfd_open',Mock(),raising=False)
    monkeypatch.setattr(boundary.os,'readlink',lambda _: 'net:[test]')
    monkeypatch.setattr(boundary,'command',lambda _:b'kvm\n')
    original = Path.read_text
    monkeypatch.setattr(Path,'read_text',lambda path,*a,**k:observations[path.as_posix()] if path.as_posix() in observations else original(path,*a,**k))
    if mutation is None: boundary.verify_vm(plan,value)
    else:
        with pytest.raises(policy.ReviewRefused): boundary.verify_vm(plan,value)


def test_shutdown_is_reverse_order_and_never_signals_changed_processes(monkeypatch):
    supervisor = object.__new__(processes.Supervisor)
    supervisor.ledger = SimpleNamespace(closed=False,profile=str(uuid4()))
    supervisor.children = {}; supervisor._record = Mock()
    refs = {}
    for i,name in enumerate(('voting','admin','tally')):
        ref = processes.ProcessRef(supervisor.ledger.profile,name,str(uuid4()),100+i,99+i,1000+i)
        process = Mock(); process.poll.return_value = None
        supervisor.children[name] = (process,10+i,ref); refs[name] = ref
    monkeypatch.setattr(processes,'observe',lambda _profile,name,_pid:refs[name])
    signal_mock = Mock(); monkeypatch.setattr(processes.signal,'pidfd_send_signal',signal_mock,raising=False)
    close = Mock(); monkeypatch.setattr(processes.os,'close',close)
    assert supervisor.stop() == () and not supervisor.children
    assert [call.args[0] for call in signal_mock.call_args_list] == [12,11,10]
    assert [call.args[1].service for call in supervisor._record.call_args_list] == ['tally','admin','voting']


def test_create_once_custody_never_overwrites_or_regenerates(plan,monkeypatch,tmp_path):
    vault = object.__new__(custody.Custody); vault.plan = plan; vault.path = tmp_path
    generate = Mock(); monkeypatch.setattr(custody,'_materials',generate)
    with pytest.raises(FileExistsError): vault.initialize(SecretStr('synthetic-test-passphrase'),{},confirmation='GENERATE DEMO KEYS '+policy.fingerprint(plan))
    generate.assert_not_called()


def test_containers_have_no_automatic_deletion_or_cleanup_on_failure():
    from deployment import local_runtime_containers as containers
    source = Path(containers.__file__).read_text()
    assert 'os.O_EXCL' in source and 'os.fsync' in source
    assert "docker('rm'" not in source and "docker('volume','rm'" not in source and 'finally:' not in source
    assert "'--mount','type=volume" in source and 'bootstrap_passwords[kind]' in source


@pytest.mark.parametrize('ready',[True,False])
def test_start_records_before_readiness_and_private_config_is_not_in_argv_or_env(plan,monkeypatch,ready):
    import sys
    monkeypatch.setattr(processes,'verify_vm',Mock())
    monkeypatch.setitem(sys.modules,'grp',SimpleNamespace(getgrall=lambda:[]))
    supervisor = object.__new__(processes.Supervisor)
    supervisor.plan,supervisor.approval = plan,approval(plan)
    supervisor.containers = Mock(); supervisor.accounts = {'voting':(1001,1001)}
    supervisor.python = Path('/approved/python'); supervisor.ledger = processes.StartupLedger(plan['identifiers']['profile'])
    supervisor.children = {}; supervisor._record = Mock()
    process = MagicMock(); process.pid = 123
    process.poll.return_value = None; process.stdout.readline.return_value = b'READY\n' if ready else b''
    launch = Mock(return_value=process); monkeypatch.setattr(processes.subprocess,'Popen',launch)
    monkeypatch.setattr(processes.os,'pidfd_open',lambda _:10,raising=False)
    monkeypatch.setattr(processes.os,'close',Mock())
    monkeypatch.setattr(processes.signal,'pidfd_send_signal',Mock(),raising=False)
    ref = processes.ProcessRef(supervisor.ledger.profile,'voting',str(uuid4()),123,345,1001)
    monkeypatch.setattr(processes,'observe',lambda *args:ref)
    config = {'service':'voting','private_test_canary':'SYNTHETIC_PRIVATE_PIPE_CANARY'}
    if ready: supervisor.start('voting',config)
    else:
        with pytest.raises(policy.ReviewRefused): supervisor.start('voting',config)
    assert 'voting' in supervisor.children and supervisor._record.call_args_list[0].args == ('started',ref)
    args,kwargs = launch.call_args
    assert 'SYNTHETIC_PRIVATE_PIPE_CANARY' not in str(args)+str(kwargs)
    assert b'SYNTHETIC_PRIVATE_PIPE_CANARY' in process.stdin.write.call_args.args[0]
    assert kwargs['user'] == 1001 and kwargs['group'] == 1001 and kwargs['extra_groups'] == [] and kwargs['start_new_session'] is True
    assert supervisor.ledger.ready == ({'voting'} if ready else set())
    assert supervisor.stop() == ()


def test_material_generation_rejects_reused_user_passwords_before_creating_keys(monkeypatch):
    generate = Mock(); monkeypatch.setattr(custody.rsa,'generate_private_key',generate)
    with pytest.raises(policy.ReviewRefused): custody._materials({name:SecretStr('same-synthetic-test-password') for name in ('admin','tally','voter_a','voter_b')})
    generate.assert_not_called()


@pytest.mark.parametrize('kind',['ra','voting','public'])
def test_guarded_migration_env_preserves_baseline_creation_schema_and_rejects_arbitrary_context(kind,plan,monkeypatch):
    import runpy
    from alembic import context
    conn = MagicMock()
    database = plan['databases'].get(kind,{'name':'unsafe'})['name']
    conn.exec_driver_sql.return_value.one.return_value = (database,kind+'_migrator_login',kind+'_owner',kind)
    monkeypatch.setattr(context,'config',SimpleNamespace(attributes=dict(connection=conn,owner=kind+'_owner',schema=kind,database=database)),raising=False)
    monkeypatch.setattr(context,'is_offline_mode',lambda:False)
    monkeypatch.setattr(context,'configure',Mock())
    monkeypatch.setattr(context,'begin_transaction',MagicMock())
    migrations = Mock(); monkeypatch.setattr(context,'run_migrations',migrations)
    if kind == 'public':
        with pytest.raises(policy.ReviewRefused): runpy.run_path(str(policy.ROOT/'deployment/local_migrations/env.py'))
        conn.exec_driver_sql.assert_not_called(); migrations.assert_not_called()
    else:
        runpy.run_path(str(policy.ROOT/'deployment/local_migrations/env.py'))
        assert conn.exec_driver_sql.call_args_list[1].args == ('SET LOCAL search_path TO '+kind+',pg_catalog',)
        migrations.assert_called_once()


@pytest.mark.skipif(__import__('sys').platform != 'linux',reason='Linux /proc listener identity requires Linux')
def test_actual_listener_readiness_checks_socket_ownership_not_only_http_response():
    import os
    import socket
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0)); listener.listen()
        port = listener.getsockname()[1]
        assert worker.owns_listener(os.getpid(),port)
        assert not worker.owns_listener(os.getpid(),0)


@pytest.mark.skipif(__import__('sys').platform != 'linux',reason='Actual pidfd process identity requires Linux')
def test_actual_linux_pidfd_binds_and_stops_only_the_owned_nonroot_test_child():
    import os
    import signal
    import subprocess
    import sys
    if os.geteuid() == 0: pytest.skip('Runtime identity must be non-root')
    process = subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    fd = os.pidfd_open(process.pid)
    try:
        ref = processes.observe(str(uuid4()),'voting',process.pid)
        assert ref.uid == os.geteuid() and ref.pid == process.pid
        signal.pidfd_send_signal(fd,signal.SIGTERM)
        assert process.wait(timeout=5) == -signal.SIGTERM
    finally:
        if process.poll() is None: signal.pidfd_send_signal(fd,signal.SIGTERM); process.wait(timeout=5)
        os.close(fd)
