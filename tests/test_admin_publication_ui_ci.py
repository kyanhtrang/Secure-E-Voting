"""Database-free hosted UI composition safety checks, not real-service evidence."""
from contextlib import contextmanager
import inspect
import io
import json
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest
import yaml
from scripts import admin_publication_ui_ci as ci


def config():
    return dict(origin='http://127.0.0.1:12345',username='synthetic',password='synthetic-only',
        election_id=str(uuid4()),receipts=['a'*64,'b'*64])


def test_local_refusal_precedes_database_docker_process_and_key_access(monkeypatch):
    monkeypatch.setattr(ci.sys,'platform','win32')
    calls=[Mock() for _ in range(4)]
    monkeypatch.setattr(ci.gate.guard.psycopg,'connect',calls[0])
    monkeypatch.setattr(ci.real.vote_ci,'docker',calls[1])
    monkeypatch.setattr(ci.real.subprocess,'Popen',calls[2])
    monkeypatch.setattr(Path,'read_bytes',calls[3])
    with pytest.raises(SystemExit) as result:
        ci.main(['--allow-ephemeral-ci-databases','--node','unopened','--signer-binary','unopened'])
    assert str(result.value)=='FAIL: admin_publication_ui stage=preflight category=assertion_error sqlstate=unavailable'
    for call in calls:call.assert_not_called()


@pytest.mark.parametrize('field',['token','private_key','unlock','target','db_password','tally_key','authority_key'])
def test_browser_accepts_no_cross_service_secrets(field):
    with pytest.raises(AssertionError):ci.browser_configuration(dict(config(),**{field:'SECRET_CANARY'}))


@pytest.mark.parametrize('origin',['http://example.test','http://localhost:12345','http://user:SECRET_CANARY@127.0.0.1:12345','http://127.0.0.1:12345?next=1'])
def test_browser_origin_is_coordinator_loopback_only(origin):
    with pytest.raises(AssertionError):ci.browser_configuration(dict(config(),origin=origin))


def test_receipts_are_canonical_and_distinct():
    ci.browser_configuration(config())
    for receipts in (['a'*64,'a'*64],['A'*64,'b'*64],['a'*64],['a'*64,'b'*64,'c'*64]):
        with pytest.raises(AssertionError):ci.browser_configuration(dict(config(),receipts=receipts))


def test_default_gate_hook_is_noop_and_is_after_rollback_before_first_publication():
    gate=ci.gate.Publication(['preflight'])
    assert gate.before_publication(['a'*64,'b'*64]) is None
    source=inspect.getsource(ci.gate.Publication.finish)
    assert source.index('conn.rollback()')<source.index('self.before_publication(receipts)')<source.index('ThreadPoolExecutor')
    assert 'pool.map(lambda _:self.publish(),range(4))' in source


def test_ui_hook_uses_private_pipe_real_driver_and_requires_committed_published_state(monkeypatch):
    gate=ci.UIPublication(['publication_concurrent'],Path('node'))
    gate.db=Mock();gate.election=uuid4();gate.browser_admin=('http://127.0.0.1:12345','synthetic','SECRET_CANARY')
    gate.pub_origin,gate.board_origin,gate.trust_config='http://127.0.0.1:12346','http://127.0.0.1:12347',{}
    checked=[];monkeypatch.setattr(ci.gate.board_ci,'aggregate_rows',lambda *args:checked.append(args[-1]))
    @contextmanager
    def frontend(*args):yield 'http://127.0.0.1:12348'
    monkeypatch.setattr(ci,'frontend',frontend)
    process=Mock(stdin=io.StringIO(),stdout=io.StringIO('{"event":"published_and_verified"}\n'));process.wait.return_value=0
    commands=[]
    @contextmanager
    def child(command):commands.append(command);yield process
    monkeypatch.setattr(ci.real,'child',child)
    gate.before_publication(['a'*64,'b'*64])
    assert checked==['TALLIED','PUBLISHED']
    assert 'SECRET_CANARY' not in json.dumps(commands) and 'SECRET_CANARY' in process.stdin.getvalue()
    assert commands[0][-1]=='--real-services-only'
    process.wait.assert_called_once_with(timeout=15)


def test_new_workflow_keeps_original_gate_and_regressions_before_real_ui():
    text=(ci.ROOT/'.github/workflows/admin-publication-ui.yml').read_text(encoding='utf8');value=yaml.safe_load(text)
    assert value['on']=={'push':{'branches':['feat/admin-publish-ui']},'workflow_dispatch':None}
    assert value['permissions']=={'contents':'read'}
    job=value['jobs']['admin-publication-ui'];assert job['runs-on']=='ubuntu-24.04'
    scripts=[s.get('run','') for s in job['steps']]
    last=next(i for i,s in enumerate(scripts) if 'scripts/admin_publication_ui_ci.py' in s)
    for command in ('scripts/full_election_e2e.py','scripts/board_postgres_ci.py','scripts/tally_postgres_ci.py','-m pytest','npm test',
        'test:browser','test:voting-browser','test:admin-browser','test:tally-browser','test:board-browser','npm run build','pending_state.test.js'):
        assert any(command in s for s in scripts[:last])
    assert 'secrets.' not in text and 'upload-artifact' not in text and 'continue-on-error' not in text
    assert all(len(s['uses'].split('@')[1])==40 for s in job['steps'] if 'uses' in s)


def test_real_driver_has_no_mock_or_artifact_capture_and_verifies_public_evidence():
    text=(ci.ROOT/'frontend/tests/real-admin-publication.mjs').read_text(encoding='utf8')
    assert 'route(' not in text and 'route.fulfill' not in text
    assert 'screenshot(' not in text and 'error.message' not in text and 'console.log' not in text
    assert 'PUBLISHED — publication is committed.' in text and 'VERIFIED: Signed evidence chain verified.' in text
    assert 'localStorage.length+sessionStorage.length' in text and 'cookie' in text
