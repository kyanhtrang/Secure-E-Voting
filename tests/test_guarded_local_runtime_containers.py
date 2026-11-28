"""Docker-shape and failure regressions only; never invoke Docker/PostgreSQL.

Legacy --tmpfs is HostConfig.Tmpfs, not a Mounts entry (Moby's TmpfsMounts
versus GetMountPoints). Real engine/filesystem evidence awaits the Ubuntu gate.
"""
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from deployment import local_demo_policy as policy, local_runtime_boundary as boundary
from scripts import guarded_local_runtime_ci as gate
from tests.test_guarded_local_runtime import approval, raw_container_fixture

MOUNTINFO = b'37 24 0:30 / /run/evote-secrets rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,mode=755\n'


@pytest.fixture
def plan(): return policy.new_plan()


def evidence(plan, monkeypatch, actual=None, *, mountinfo=MOUNTINFO, metadata=b'regular file|600|postgres|postgres|1|64\n'):
    fixture,image,volume,network = raw_container_fixture(plan)
    actual = fixture if actual is None else actual
    owned = boundary.OwnedContainers(plan,approval(plan),{'ra':'a'*64,'voting':'b'*64})
    def inspect(*args):
        if args[0] == '--type=image': return image
        if args[0] == '--type=volume': return volume
        if args[0] == '--type=network': return network
        return actual
    commands = []
    def command(argv):
        commands.append(argv)
        if argv[-2:] == ['/bin/cat','/proc/self/mountinfo']: return mountinfo
        if argv[-2:] == ['--','/run/evote-secrets']: return b'directory|755\n'
        if argv[-2:] == ['--','/run/evote-secrets/bootstrap-password']: return metadata
        raise AssertionError('Unexpected metadata command')
    monkeypatch.setattr(owned,'inspect',inspect)
    monkeypatch.setattr(boundary,'command',command)
    return owned,commands


def test_legacy_tmpfs_and_single_named_volume_pass_with_effective_filesystem_evidence(plan,monkeypatch):
    owned,commands = evidence(plan,monkeypatch)
    assert len(owned.verify_container('ra')) == 64
    assert len(commands) == 3
    assert all(argv[:len(boundary.DOCKER_PREFIX)] == boundary.DOCKER_PREFIX for argv in commands)
    assert all(argv[len(boundary.DOCKER_PREFIX)] == 'exec' and argv[len(boundary.DOCKER_PREFIX)+1] == 'a'*64 for argv in commands)
    assert [argv[len(boundary.DOCKER_PREFIX)+2:] for argv in commands] == [
        ['/bin/cat','/proc/self/mountinfo'],
        ['/usr/bin/stat','-c','%F|%a','--','/run/evote-secrets'],
        ['/usr/bin/stat','-c','%F|%a|%U|%G|%h|%s','--','/run/evote-secrets/bootstrap-password'],
    ]


@pytest.mark.parametrize('mutation,predicate',[
    ('missing_tmpfs','secret_tmpfs'),('extra_tmpfs','secret_tmpfs'),('unsafe_tmpfs_options','secret_tmpfs'),
    ('extra_volume','persistent_mount'),('bind','persistent_mount'),('docker_socket','persistent_mount'),
    ('wrong_volume','persistent_mount'),('legacy_wrong_mock','persistent_mount'),
    ('wrong_image','image_identity'),('wrong_image_reference','policy_image_reference'),
    ('wrong_network','network_identity'),('wrong_network_mode','policy_network_mode'),
    ('environment','environment_overrides'),('wrong_ownership','ownership_labels'),
    ('wrong_id','policy_container_id'),('wrong_name','policy_container_name'),
    ('privileged','policy_privileged'),('lan','policy_configured_ports'),('extra_port','policy_configured_ports'),
    ('not_running','running_state'),('host_bind','running_state'),
])
def test_mount_and_existing_isolation_guards_remain_strict(plan,monkeypatch,mutation,predicate):
    actual,*_ = raw_container_fixture(plan)
    if mutation == 'missing_tmpfs': actual['HostConfig']['Tmpfs'] = {}
    elif mutation == 'extra_tmpfs': actual['HostConfig']['Tmpfs']['/extra'] = 'rw'
    elif mutation == 'unsafe_tmpfs_options': actual['HostConfig']['Tmpfs']['/run/evote-secrets'] = 'rw,nosuid,nodev,mode=0755'
    elif mutation == 'extra_volume': actual['Mounts'].append(deepcopy(actual['Mounts'][0]))
    elif mutation in {'bind','docker_socket'}:
        actual['Mounts'].append(dict(Type='bind',Source='/var/run/docker.sock' if mutation == 'docker_socket' else '/host',Destination='/extra',RW=True))
    elif mutation == 'wrong_volume': actual['Mounts'][0]['Name'] = 'unowned-volume'
    elif mutation == 'legacy_wrong_mock': actual['Mounts'].append(dict(Type='tmpfs',Destination='/run/evote-secrets',RW=True))
    elif mutation == 'wrong_image': actual['Image'] = 'sha256:'+'d'*64
    elif mutation == 'wrong_image_reference': actual['Config']['Image'] = 'postgres:latest'
    elif mutation == 'wrong_network': actual['NetworkSettings']['Networks'] = {'other':{}}
    elif mutation == 'wrong_network_mode': actual['HostConfig']['NetworkMode'] = 'host'
    elif mutation == 'environment': actual['Config']['Env'].append('POSTGRES_PASSWORD=SECRET_CANARY')
    elif mutation == 'wrong_ownership': actual['Config']['Labels']['secure-evoting-local-demo'] = 'wrong-profile'
    elif mutation == 'wrong_id': actual['Id'] = 'b'*64
    elif mutation == 'wrong_name': actual['Name'] = '/unowned-container'
    elif mutation == 'privileged': actual['HostConfig']['Privileged'] = True
    elif mutation == 'lan': actual['HostConfig']['PortBindings']['5432/tcp'][0]['HostIp'] = '0.0.0.0'
    elif mutation == 'extra_port': actual['HostConfig']['PortBindings']['9999/tcp'] = [{'HostIp':'127.0.0.1','HostPort':'9999'}]
    elif mutation == 'not_running': actual['State']['Running'] = False
    elif mutation == 'host_bind': actual['HostConfig']['Binds'] = ['/host:/extra']
    owned,commands = evidence(plan,monkeypatch,actual)
    with pytest.raises(policy.ReviewRefused) as caught: owned.verify_container('ra')
    assert caught.value.container_predicate == predicate
    assert commands == []  # Never exec into an unverified container.
    assert 'SECRET_CANARY' not in gate.failure(['container_ra_inspect'],caught.value)


@pytest.mark.parametrize('mountinfo',[b'',MOUNTINFO.replace(b'tmpfs tmpfs',b'ext4 /dev/demo'),
    MOUNTINFO.replace(b',noexec',b''),MOUNTINFO+MOUNTINFO,b'malformed'])
def test_effective_secret_mount_must_be_unique_tmpfs_with_required_flags(plan,monkeypatch,mountinfo):
    owned,_ = evidence(plan,monkeypatch,mountinfo=mountinfo)
    with pytest.raises(Exception) as caught: owned.verify_container('ra')
    assert caught.value.container_predicate == 'secret_filesystem'


@pytest.mark.parametrize('metadata',[
    b'symbolic link|777|postgres|postgres|1|64\n',b'regular file|644|postgres|postgres|1|64\n',
    b'regular file|600|root|root|1|64\n',b'regular file|600|postgres|postgres|2|64\n',
    b'regular file|600|postgres|postgres|1|0\n',b'malformed\n'])
def test_secret_readiness_checks_metadata_without_reading_credentials(plan,monkeypatch,metadata):
    owned,_ = evidence(plan,monkeypatch,metadata=metadata)
    with pytest.raises(policy.ReviewRefused) as caught: owned.verify_container('ra')
    assert caught.value.container_predicate == 'secret_file_ready'


def test_stopped_inspection_does_not_invent_live_filesystem_evidence(plan,monkeypatch):
    actual,*_ = raw_container_fixture(plan)
    actual['State']['Running'] = False; actual['NetworkSettings']['Ports'] = {}
    owned,commands = evidence(plan,monkeypatch,actual)
    assert len(owned.verify_container('ra',running=False)) == 64 and commands == []


@pytest.mark.parametrize('predicate',['arbitrary SECRET_CANARY',None,{},['secret_tmpfs']])
def test_untrusted_diagnostic_attributes_and_exception_text_are_never_emitted(predicate):
    error = RuntimeError('SECRET_CANARY password token private key')
    error.container_predicate = predicate
    assert gate.failure(['container_ra_inspect'],error) == 'FAIL guarded_local_runtime stage=container_ra_inspect predicate=unavailable category=assertion_error'
    assert 'SECRET_CANARY' not in gate.failure(['arbitrary SECRET_CANARY'],error)


def test_nested_check_preserves_exact_failure_and_only_allowlisted_predicate():
    error = RuntimeError('SECRET_CANARY')
    with pytest.raises(RuntimeError) as caught:
        with boundary.container_check('container_inspect'):
            with boundary.container_check('secret_filesystem'): raise error
    assert caught.value is error and caught.value.container_predicate == 'secret_filesystem'
    assert 'SECRET_CANARY' not in gate.failure(['container_ra_inspect'],error)


@pytest.mark.parametrize('fail_at,predicate',[
    ('container_image','image_pull'),('container_network','network_create'),
    ('container_ra_created','container_start'),('container_ra_secret','secret_injection'),
    ('container_voting_created','container_start'),('container_voting_secret','secret_injection'),
    ('container_ra_inspect','persistent_mount'),('container_voting_inspect','persistent_mount'),
    ('container_ra_inspect','policy_effective_ports'),('container_voting_inspect','policy_effective_ports')])
def test_coordinator_pinpoints_failures_and_cleanup_preserves_original_stage(plan,monkeypatch,tmp_path,capsys,fail_at,predicate):
    monkeypatch.setattr(gate.ci,'require_ci',Mock()); monkeypatch.setattr(gate.ci,'verify_dependencies',Mock())
    monkeypatch.setattr(gate,'new_plan',lambda:plan)
    connect = Mock(side_effect=AssertionError('Unexpected database access')); monkeypatch.setattr(gate.psycopg,'connect',connect)
    node,signer = tmp_path/'node',tmp_path/'signer'
    node.touch(); signer.touch()
    fixtures = {kind:raw_container_fixture(plan,kind) for kind in ('ra','voting')}
    for kind in ('ra','voting'):
        if fail_at == 'container_'+kind+'_inspect':
            if predicate == 'policy_effective_ports': fixtures[kind][0]['NetworkSettings']['Ports'] = {'5432/tcp':None}
            else: fixtures[kind][0]['Mounts'].append(dict(Type='tmpfs',Destination='/run/evote-secrets',RW=True))
    stage = ['preflight']; operations = []
    def docker(*args,**kwargs):
        operations.append(args[:2])
        if args[0] == 'pull' and fail_at == 'container_image': raise RuntimeError('SECRET_CANARY')
        if args[:2] == ('network','create') and fail_at == 'container_network': raise RuntimeError('SECRET_CANARY')
        if args[0] == 'run':
            kind = 'ra' if args[args.index('--name')+1] == plan['databases']['ra']['container'] else 'voting'
            if fail_at == 'container_'+kind+'_created': raise RuntimeError('SECRET_CANARY')
            return fixtures[kind][0]['Id']
        if args[:2] == ('exec','--interactive'):
            kind = 'ra' if args[2] == 'a'*64 else 'voting'
            if fail_at == 'container_'+kind+'_secret': raise RuntimeError('SECRET_CANARY')
            assert kwargs['input_text'] not in str(args)
        if args[0] == 'inspect': return json.dumps([fixtures['ra' if args[1] == 'a'*64 else 'voting'][0]])
        if args[:2] == ('image','inspect'): return json.dumps([fixtures['ra'][1]])
        if args[:2] == ('volume','inspect'):
            return json.dumps([fixtures['ra' if args[2] == plan['databases']['ra']['volume'] else 'voting'][2]])
        if args[:2] == ('network','inspect'): return json.dumps([dict(fixtures['ra'][3],Containers={})])
        return ''
    monkeypatch.setattr(gate.ci,'docker',docker)
    def command(argv):
        args = argv[len(boundary.DOCKER_PREFIX):]
        if args[0] == 'inspect':
            if args[1] == '--type=image': return json.dumps([fixtures['ra'][1]]).encode()
            if args[1] == '--type=volume': return json.dumps([fixtures['ra' if args[2] == plan['databases']['ra']['volume'] else 'voting'][2]]).encode()
            if args[1] == '--type=network': return json.dumps([fixtures['ra'][3]]).encode()
            return json.dumps([fixtures['ra' if args[1] == 'a'*64 else 'voting'][0]]).encode()
        if args[-2:] == ['/bin/cat','/proc/self/mountinfo']: return MOUNTINFO
        if args[-2:] == ['--','/run/evote-secrets']: return b'directory|755\n'
        if args[-2:] == ['--','/run/evote-secrets/bootstrap-password']: return b'regular file|600|postgres|postgres|1|64\n'
        raise AssertionError('Unexpected Docker command')
    monkeypatch.setattr(boundary,'command',command)
    with pytest.raises(Exception) as caught: gate.run(node,signer,stage)
    assert stage == [fail_at] and caught.value.container_predicate == predicate
    output = capsys.readouterr().out
    assert 'PASS guarded_local_runtime checkpoint=cleanup' in output and 'SECRET_CANARY' not in output
    assert 'checkpoint=containers\n' not in output
    assert gate.failure(stage,caught.value) == f'FAIL guarded_local_runtime stage={fail_at} predicate={predicate} category=assertion_error'
    connect.assert_not_called()


def test_offline_source_policy_remains_review_only(plan):
    assert policy.validate_plan(plan) == plan and plan['execution_ready'] is False


def test_policy_diagnostics_pass_positive_contract_without_claiming_engine_compatibility(plan):
    # This is a policy-contract observation, not evidence that --internal creates
    # published host ports. The separate negative tests retain that distinction.
    from tests.test_local_demo_policy import observation
    policy.validate_container(plan,'ra','a'*64,observation(plan))
    assert policy.CONTAINER_POLICY_PREDICATES <= boundary.CONTAINER_PREDICATES


@pytest.mark.parametrize('predicate',sorted(policy.CONTAINER_POLICY_PREDICATES))
def test_each_pure_policy_guard_has_its_own_fixed_failure_id(plan,predicate):
    from tests.test_local_demo_policy import observation
    observed = observation(plan); kind,identifier = 'ra','a'*64
    if predicate == 'policy_kind': kind = 'other'
    elif predicate == 'policy_created_id': identifier = 'malformed'
    elif predicate == 'policy_database_spec': plan['databases']['ra']['name'] = 'ra_db'
    elif predicate == 'policy_observation': observed = None
    elif predicate == 'policy_network_name': plan['network'] = 'unowned-network'
    elif predicate == 'policy_container_id': observed['Id'] = 'b'*64
    elif predicate == 'policy_container_name': observed['Name'] = '/unowned'
    elif predicate == 'policy_image_reference': observed['Config']['Image'] = 'postgres:latest'
    elif predicate == 'policy_labels': observed['Config']['Labels'] = {}
    elif predicate == 'policy_privileged': observed['HostConfig']['Privileged'] = True
    elif predicate == 'policy_network_mode': observed['HostConfig']['NetworkMode'] = 'host'
    elif predicate == 'policy_pid_namespace': observed['HostConfig']['PidMode'] = 'host'
    elif predicate == 'policy_ipc_namespace': observed['HostConfig']['IpcMode'] = 'host'
    elif predicate == 'policy_autoremove': observed['HostConfig']['AutoRemove'] = True
    elif predicate == 'policy_configured_ports': observed['HostConfig']['PortBindings'] = {}
    elif predicate == 'policy_effective_ports': observed['NetworkSettings']['Ports'] = {'5432/tcp':None}
    elif predicate == 'policy_persistent_mount': observed['Mounts'] = []
    elif predicate == 'policy_environment': observed['Config']['Env'].append('POSTGRES_PASSWORD=SECRET_CANARY')
    else: raise AssertionError('Uncovered policy diagnostic')
    with pytest.raises(policy.ReviewRefused) as caught: policy.validate_container(plan,kind,identifier,observed)
    assert caught.value.container_predicate == predicate
    # The boundary's outer generic context must retain the more precise label.
    with pytest.raises(policy.ReviewRefused) as annotated:
        with boundary.container_check('container_policy'): raise caught.value
    assert annotated.value is caught.value and annotated.value.container_predicate == predicate
    assert gate.failure(['container_ra_inspect'],caught.value) == f'FAIL guarded_local_runtime stage=container_ra_inspect predicate={predicate} category=assertion_error'


@pytest.mark.parametrize('ports',[{},None,{'5432/tcp':None},{'5432/tcp':[]},
    {'5432/tcp':[{'HostIp':'0.0.0.0','HostPort':'55432'}]},
    {'5432/tcp':[{'HostIp':'127.0.0.1','HostPort':'55433'}]}])
def test_configured_bindings_do_not_prove_effective_published_ports(plan,monkeypatch,ports):
    actual,*_ = raw_container_fixture(plan)
    actual['NetworkSettings']['Ports'] = ports
    owned,commands = evidence(plan,monkeypatch,actual)
    with pytest.raises(policy.ReviewRefused) as caught: owned.verify_container('ra')
    assert caught.value.container_predicate == 'policy_effective_ports' and commands == []


@pytest.mark.parametrize('field,predicate',[
    ('Privileged','policy_privileged'),('NetworkMode','policy_network_mode'),('PidMode','policy_pid_namespace'),
    ('IpcMode','policy_ipc_namespace'),('AutoRemove','policy_autoremove'),('PortBindings','policy_configured_ports')])
def test_missing_inspect_fields_fail_with_precise_sanitized_identifiers(plan,field,predicate):
    from tests.test_local_demo_policy import observation
    observed = observation(plan); del observed['HostConfig'][field]
    with pytest.raises(policy.ReviewRefused) as caught: policy.validate_container(plan,'ra','a'*64,observed)
    assert caught.value.container_predicate == predicate and str(caught.value) == 'Local demo review refused'


def test_invalid_stopped_port_metadata_has_a_separate_predicate(plan,monkeypatch):
    actual,*_ = raw_container_fixture(plan)
    actual['State']['Running'] = False
    owned,commands = evidence(plan,monkeypatch,actual)
    with pytest.raises(policy.ReviewRefused) as caught: owned.verify_container('ra',running=False)
    assert caught.value.container_predicate == 'container_stopped_ports' and commands == []
