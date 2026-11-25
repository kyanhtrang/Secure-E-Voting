"""Offline policy tests. No database, Docker, keys, migration or deployment I/O."""
from copy import deepcopy
import io
import json
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest
from deployment import local_demo_policy as policy
from scripts import local_demo_preflight as cli


@pytest.fixture
def plan(): return policy.new_plan()


def test_fresh_public_plan_is_strict_review_only_and_bound_to_reviewed_sources(plan):
    assert policy.validate_plan(plan) == plan
    assert plan['execution_ready'] is False and plan['mode'] == 'review-only'
    assert len(set(plan['identifiers'].values())) == 7
    assert plan['postgres_image'] == policy.postgres_image()
    assert plan['source_digest'] == policy.source_fingerprint()
    assert policy.new_plan()['identifiers'] != plan['identifiers']


@pytest.mark.parametrize('name',['ra_db','voting_db','postgres','ra_demo_test_ci_existing','voting_demo_local_unowned'])
def test_unsafe_database_names_cannot_be_accepted_even_with_matching_claimed_rows(plan,name):
    plan['databases']['ra']['name'] = name
    with pytest.raises(policy.ReviewRefused):policy.validate_plan(plan)
    row=(name,'ra_auth_login','ra_auth_login','ra_owner',plan['databases']['ra']['marker'],180000)
    with pytest.raises(policy.ReviewRefused):policy.validate_database_identity(plan,'ra_a','ra_auth_login',row)


@pytest.mark.parametrize('field,value',[('execution_ready',True),('execution_ready',0),('version',True),('mode','enabled'),
    ('platform','windows-native'),('postgres_image','postgres:18'),('source_digest','0'*64),('password','SECRET_CANARY'),
    ('dsn','SECRET_CANARY'),('private_key','SECRET_CANARY'),('token','SECRET_CANARY')])
def test_unexpected_fields_types_or_source_changes_fail_closed(plan,field,value):
    plan[field]=value
    with pytest.raises(policy.ReviewRefused):policy.validate_plan(plan)


@pytest.mark.parametrize('name',['PGHOST','pgpassword','DOCKER_HOST','RA_DEMO_DB_PASSWORD','VITE_ENABLE_ADMIN','ADMIN_DEMO_VERIFIER'])
def test_ambient_targets_or_secrets_are_not_discovered_or_echoed(name):
    with pytest.raises(policy.ReviewRefused) as result:policy.safe_environment({name:'SECRET_CANARY'})
    assert result.value.code == 'ENVIRONMENT' and 'SECRET_CANARY' not in str(result.value)


def test_valid_identity_still_requires_the_exact_restricted_runtime_role_and_marker(plan):
    db=plan['databases']['voting'];login='voting_ballot_login'
    row=(db['name'],login,login,db['owner'],db['marker'],180007)
    policy.validate_database_identity(plan,'voting',login,row)
    for field,value in [(0,'voting_db'),(1,'postgres'),(2,'voting_owner'),(3,'postgres'),(4,'other-marker'),(5,170000),(5,190000),(5,True)]:
        bad=list(row);bad[field]=value
        with pytest.raises(policy.ReviewRefused):policy.validate_database_identity(plan,'voting',login,tuple(bad))
    for login in ('postgres','voting_owner','voting_migrator_login','ra_auth_login','voting_tally_login'):
        with pytest.raises(policy.ReviewRefused):policy.validate_database_identity(plan,'voting',login,row)


@pytest.mark.parametrize('service',list(policy.SERVICES))
def test_service_key_and_role_boundaries_are_explicit(service):
    spec=policy.SERVICES[service]
    policy.validate_assets(service,spec['roles'],spec['keys'],spec['verifiers'],spec['evidence'])
    for field,extra in [('roles','ra_owner'),('keys','tally_decryption'),('verifiers','other_identity')]:
        bad=deepcopy(spec);bad[field]=bad[field]+[extra]
        with pytest.raises(policy.ReviewRefused):policy.validate_assets(service,bad['roles'],bad['keys'],bad['verifiers'],bad['evidence'])
    if service in ('board','voting','web_admin','web_a','web_b'):
        assert not spec['keys'] and spec['evidence'] == 'none'


def observation(plan,kind='ra'):
    spec=plan['databases'][kind]
    ports={'5432/tcp':[dict(HostIp='127.0.0.1',HostPort=str(spec['port']))]}
    return dict(Id='a'*64 if kind=='ra' else 'b'*64,Name='/'+spec['container'],
        Config=dict(Image=plan['postgres_image'],Labels=policy.labels(plan,kind),Env=[
            'POSTGRES_PASSWORD_FILE=/run/evote-secrets/bootstrap-password','POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer']),
        HostConfig=dict(Privileged=False,NetworkMode=plan['network'],PidMode='',IpcMode='private',AutoRemove=False,PortBindings=ports),
        NetworkSettings=dict(Ports=deepcopy(ports)),Mounts=[dict(Type='volume',Name=spec['volume'],Destination='/var/lib/postgresql',RW=True)])


@pytest.mark.parametrize('mutation',['id','name','image','label','network','privileged','autoremove','port','bind_mount','extra_mount','password_env'])
def test_owned_container_observation_refuses_unrelated_unsafe_or_secret_bearing_resources(plan,mutation):
    observed=observation(plan)
    if mutation=='id':observed['Id']='b'*64
    elif mutation=='name':observed['Name']='/user-postgres'
    elif mutation=='image':observed['Config']['Image']='postgres:latest'
    elif mutation=='label':observed['Config']['Labels']['secure-evoting-local-demo']=str(uuid4())
    elif mutation=='network':observed['HostConfig']['NetworkMode']='host'
    elif mutation=='privileged':observed['HostConfig']['Privileged']=True
    elif mutation=='autoremove':observed['HostConfig']['AutoRemove']=True
    elif mutation=='port':observed['HostConfig']['PortBindings']['5432/tcp'][0]['HostIp']='0.0.0.0'
    elif mutation=='bind_mount':observed['Mounts'][0]['Type']='bind'
    elif mutation=='extra_mount':observed['Mounts'].append(dict(Type='bind',Source='user-directory',Destination='/data'))
    else:observed['Config']['Env'].append('POSTGRES_PASSWORD=SECRET_CANARY')
    with pytest.raises(policy.ReviewRefused) as error:policy.validate_container(plan,'ra','a'*64,observed)
    assert 'SECRET_CANARY' not in str(error.value)


def test_cleanup_review_requires_separate_exact_confirmation_and_all_ownership_proofs(plan):
    containers={kind:(observation(plan,kind)['Id'],observation(plan,kind)) for kind in ('ra','voting')}
    volumes={kind:dict(Name=plan['databases'][kind]['volume'],Driver='local',Options=None,Labels=policy.labels(plan,kind)) for kind in ('ra','voting')}
    with pytest.raises(policy.ReviewRefused):policy.removal_review(plan,containers,volumes,'yes')
    result=policy.removal_review(plan,containers,volumes,'REMOVE '+policy.fingerprint(plan))
    assert len(result)==2 and result[0][0]=='a'*64
    volumes['voting']['Options']={'device':'user-directory'}
    with pytest.raises(policy.ReviewRefused):policy.removal_review(plan,containers,volumes,'REMOVE '+policy.fingerprint(plan))


def test_storage_and_network_requirements_preserve_data_on_stop_and_refuse_host_paths(plan):
    assert plan['database_storage']=='owned-named-volume-preserve-on-stop'
    network=dict(Name=plan['network'],Driver='bridge',Internal=True,
        Labels={'secure-evoting-local-demo':plan['identifiers']['profile'],'secure-evoting-purpose':'synthetic-only'})
    policy.validate_network(plan,network)
    network['Internal']=False
    with pytest.raises(policy.ReviewRefused):policy.validate_network(plan,network)
    for options in (None,{}):
        policy.validate_volume(plan,'ra',dict(Name=plan['databases']['ra']['volume'],Driver='local',Options=options,Labels=policy.labels(plan,'ra')))
    with pytest.raises(policy.ReviewRefused):policy.validate_volume(plan,'ra',dict(Name='user-data',Driver='local',Options=None,Labels=policy.labels(plan,'ra')))


def test_web_profiles_cannot_substitute_publishers_or_cross_voter_ra_origins(plan):
    assert plan['web_targets']['web_a']['ra'] != plan['web_targets']['web_b']['ra']
    assert 'publisher' not in plan['web_targets']['web_a']
    plan['web_targets']['web_admin']['publisher']=plan['web_targets']['web_a']['voting']
    with pytest.raises(policy.ReviewRefused):policy.validate_plan(plan)


def test_plan_reader_refuses_secret_filename_before_open_and_bounds_input(monkeypatch,tmp_path,plan):
    read=Mock();monkeypatch.setattr(Path,'open',read)
    with pytest.raises(policy.ReviewRefused):cli.load_public_plan(tmp_path/'ra-demo-auth.local.json')
    read.assert_not_called();monkeypatch.undo()
    path=tmp_path/cli.PUBLIC_PLAN_NAME;path.write_text(json.dumps(plan),encoding='utf8')
    assert cli.load_public_plan(path)==plan
    path.write_bytes(b' '*32769)
    with pytest.raises(policy.ReviewRefused):cli.load_public_plan(path)
    path.write_text('{"password":"SECRET_CANARY","password":"other"}')
    with pytest.raises(policy.ReviewRefused):cli.load_public_plan(path)


def test_cli_is_offline_never_claims_runtime_readiness_and_sanitizes_failure(monkeypatch,tmp_path,capsys):
    monkeypatch.setattr(cli,'safe_environment',lambda:None)
    assert cli.main(['new'])==0
    plan=json.loads(capsys.readouterr().out)
    assert 'SECRET_CANARY' not in json.dumps(plan)
    path=tmp_path/cli.PUBLIC_PLAN_NAME;path.write_text(json.dumps(plan))
    assert cli.main(['check','--public-plan',str(path)])==0
    result=json.loads(capsys.readouterr().out)
    assert result['status']=='OFFLINE_VALIDATED_NOT_DEPLOYED' and result['execution_ready'] is False
    monkeypatch.setattr(cli,'load_public_plan',Mock(side_effect=RuntimeError('SECRET_CANARY')))
    assert cli.main(['check','--public-plan',str(path)])==2
    assert 'SECRET_CANARY' not in capsys.readouterr().out


@pytest.mark.parametrize('action',['start','migrate','stop','cleanup','destroy'])
def test_cli_has_no_execution_or_deletion_entrypoint(action):
    assert cli.main([action]) == 2


def test_argument_errors_do_not_echo_accidental_credentials(capsys):
    assert cli.main(['--password','SECRET_CANARY']) == 2
    output=capsys.readouterr()
    assert output.err == '' and 'SECRET_CANARY' not in output.out
    assert json.loads(output.out) == {'status':'REFUSED','code':'CONFIG','execution_ready':False}


def test_new_workflow_is_offline_scoped_and_has_no_database_or_cleanup_commands():
    import yaml
    text=(policy.ROOT/'.github/workflows/local-demo-preflight.yml').read_text(encoding='utf8')
    workflow=yaml.safe_load(text)
    assert workflow['on']=={'push':{'branches':['feat/security-local-demo']},'workflow_dispatch':None}
    assert workflow['permissions']=={'contents':'read'}
    job=workflow['jobs']['offline-preflight'];assert job['runs-on']=='ubuntu-24.04'
    scripts='\n'.join(step.get('run','') for step in job['steps'])
    assert 'python -I -S scripts/local_demo_preflight.py check' in scripts
    assert 'tests/test_local_demo_policy.py tests/test_local_demo_lifecycle.py' in scripts
    for forbidden in ('docker ','psql ','alembic upgrade','continue-on-error','upload-artifact','secrets.'):
        assert forbidden not in text
    assert all(len(step['uses'].split('@')[1])==40 for step in job['steps'] if 'uses' in step)
