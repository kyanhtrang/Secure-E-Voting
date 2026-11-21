"""Database-free deployment/CI safety checks; not real PostgreSQL evidence."""
import ast
from pathlib import Path
from unittest.mock import Mock
from alembic.config import Config
from alembic.script import ScriptDirectory
import pytest
import yaml

from scripts import board_postgres_ci as ci


def test_local_activation_refused_before_database_docker_or_key_access(monkeypatch):
    monkeypatch.setattr(ci.sys,'platform','win32')
    connect,docker,read=Mock(),Mock(),Mock()
    monkeypatch.setattr(ci.psycopg,'connect',connect)
    monkeypatch.setattr(ci.guard.real.vote_ci,'docker',docker)
    monkeypatch.setattr(Path,'read_bytes',read)
    with pytest.raises(SystemExit) as error:ci.main(['--allow-ephemeral-ci-database'])
    assert str(error.value)=='FAIL: board_postgres_ci stage=preflight category=assertion sqlstate=unavailable'
    connect.assert_not_called();docker.assert_not_called();read.assert_not_called()


def test_forward_graph_reuses_all_reviewed_heads_without_mutating_history():
    config=Config(str(ci.ROOT/'alembic_board.ini'))
    graph=ScriptDirectory.from_config(config)
    assert graph.get_heads()==[ci.HEAD] and len(list(graph.walk_revisions()))==6
    assert graph.get_revision(ci.HEAD).down_revision=='e6a90c72b541'


def test_migration_fails_closed_and_grants_only_four_specific_rpc_capabilities():
    file=ci.ROOT/'migrations/board/versions/f8b31c2d970a_publication_board.py'
    text=file.read_text(encoding='utf8');ast.parse(text)
    for expected in ('rolinherit','rolsuper','rolbypassrls','pg_auth_members','has_any_column_privilege',"CASE WHEN c.relkind",'voting_board.publishers',
        'FOR UPDATE','FOR SHARE OF s,p',"session_user<>'voting_publication_login'",'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA voting_board FROM PUBLIC',
        'voting_tally._assert_snapshot',"status='SUCCEEDED'",'board_immutable_publication','board_immutable_audit','board_terminal_election'):
        assert expected in text
    grants=[line.strip() for line in text.splitlines() if line.startswith('GRANT EXECUTE')]
    assert len(grants)==2 and all('ON FUNCTION voting_board.' in line for line in grants)
    assert 'CREATE ROLE' not in text and 'GRANT SELECT' not in text and 'CREATE OR REPLACE' not in text


def test_workflow_is_scoped_hosted_locked_and_has_no_secret_artifacts():
    text=(ci.ROOT/'.github/workflows/publication-board.yml').read_text(encoding='utf8');value=yaml.safe_load(text)
    assert value['on']=={'push':{'branches':['feat/public-results-bulletin-board']},'workflow_dispatch':None}
    assert value['permissions']=={'contents':'read'}
    job=value['jobs']['publication-board-postgres'];assert job['runs-on']=='ubuntu-24.04'
    assert 'secrets.' not in text and 'upload-artifact' not in text and 'continue-on-error' not in text
    scripts=[step.get('run','') for step in job['steps']]
    index=next(i for i,s in enumerate(scripts) if 'scripts/board_postgres_ci.py' in s)
    for command in ('-m pytest','npm test','test:browser','test:voting-browser','test:admin-browser','test:tally-browser','test:board-browser'):
        assert any(command in s for s in scripts[:index])


def test_real_harness_keeps_disposable_guards_and_asserts_security_and_cleanup():
    text=Path(ci.__file__).read_text(encoding='utf8')
    assert 'ephemeral_postgres()' in text and "guard.discover('voting',target)" in text
    assert 'disposable_marker=target.marker' in text and 'hide_parameters=True' in text
    assert "'SET TRANSACTION READ ONLY'" in text and 'owned.verify()' in text
    for required in ("publish(409)","publish(403,other)","publish(401,tally_token)",'conn.rollback()',
        'ThreadPoolExecutor','receipt_status','Conflicting publication accepted','Immutable evidence changed','guard.real.deny',
        'owned_container=removed','temporarily_hidden.rename(original)'):
        assert required in text


@pytest.mark.parametrize('role',['postgres','voting_owner','voting_migrator_login','ra_auth_login'])
def test_launcher_never_accepts_an_elevated_or_ra_login(role,monkeypatch):
    from backend.board.launcher import connections
    from pydantic import SecretStr
    connect=Mock();monkeypatch.setattr(ci.psycopg,'connect',connect)
    with pytest.raises(ValueError):connections(role,SecretStr('synthetic-only'))
    connect.assert_not_called()


def test_operator_client_refuses_credentials_or_tokens_in_origins():
    from scripts.publish_results import origin
    assert origin('http://127.0.0.1:8007')=='http://127.0.0.1:8007'
    for value in ('https://example.test','http://user:SECRET_CANARY@127.0.0.1:8007','http://127.0.0.1:8007?token=SECRET_CANARY',
        'http://127.0.0.1:8007/path','http://127.0.0.1:99999','http://127.0.0.1:invalid'):
        with pytest.raises(ValueError):origin(value)
