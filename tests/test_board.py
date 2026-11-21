from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path
from unittest.mock import MagicMock,Mock
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest
import rfc8785

from backend.board.verification import BoardError, decode, receipt_status, verify
from backend.board.service import Board, Publisher, Store
from backend.board.http import create_board_app,create_publication_app
from tests.board_helpers import evidence


@pytest.fixture(scope='module')
def data(tmp_path_factory):return evidence(tmp_path_factory.mktemp('board-evidence'))


def client(app):return TestClient(app,base_url='http://127.0.0.1',client=('127.0.0.1',45000))


def test_offline_chain_and_real_receipts(data):
    assert verify(data.bundle,data.election,data.trust)==data.bundle
    for row in data.bundle['snapshot']['ballots']:
        assert receipt_status(data.bundle,data.election,row['receipt_hash'],data.trust)=='VERIFIED'
    assert receipt_status(data.bundle,data.election,'0'*64,data.trust)=='NOT_FOUND'


@pytest.mark.parametrize('part',['configuration','snapshot','snapshot_evidence','tally','publication'])
def test_tampered_signature_or_records_rejected(data,part):
    value=deepcopy(data.bundle)
    if part=='snapshot':
        old=value[part]['ballots'][0]['envelope']['ciphertext']
        value[part]['ballots'][0]['envelope']['ciphertext']=('B' if old[0]=='A' else 'A')+old[1:]
    else:value[part]['signature']='A'*86
    with pytest.raises(BoardError):verify(value,data.election,data.trust)


@pytest.mark.parametrize('change',['count','candidate','config','election','extra','order','duplicate'])
def test_chain_mismatches_rejected(data,change):
    value=deepcopy(data.bundle)
    if change=='count':value['tally']['report']['accepted_total']+=1
    elif change=='candidate':value['tally']['report']['candidate_counts'][0]['candidate_id']=str(uuid4())
    elif change=='config':value['snapshot']['election_config_digest']='0'*64
    elif change=='election':value['election_id']=str(uuid4())
    elif change=='extra':value['voter_id']=str(uuid4())
    elif change=='order':value['snapshot']['ballots'].reverse()
    else:value['snapshot']['ballots'].append(value['snapshot']['ballots'][0])
    with pytest.raises(BoardError):verify(value,data.election,data.trust)


def test_even_authentically_signed_wrong_counts_fail_dataset_binding(data):
    from backend.crypto.credential_protocol import b64encode
    from backend.board.verification import publication_manifest
    value=deepcopy(data.bundle);report=value['tally']['report'];report['accepted_total']=4
    value['tally']['report_digest']=hashlib.sha256(rfc8785.dumps(report)).hexdigest()
    value['tally']['signature']=b64encode(data.snapshot_key.sign(b'EVOTE-TALLY-REPORT-v1\0'+rfc8785.dumps(report)))
    manifest=publication_manifest(value,data.trust)
    value['publication']={'manifest':manifest,'signature':b64encode(data.pub_key.sign(b'EVOTE-RESULTS-v1\0'+rfc8785.dumps(manifest)))}
    with pytest.raises(BoardError):verify(value,data.election,data.trust)


def test_draft_domain_prefixed_report_digest_is_not_silently_supported(data):
    from backend.crypto.credential_protocol import b64encode
    from backend.board.verification import publication_manifest
    value=deepcopy(data.bundle)
    value['tally']['report_digest']=hashlib.sha256(b'EVOTE-TALLY-REPORT-v1\0'+rfc8785.dumps(value['tally']['report'])).hexdigest()
    manifest=publication_manifest(value,data.trust)
    value['publication']={'manifest':manifest,'signature':b64encode(data.pub_key.sign(b'EVOTE-RESULTS-v1\0'+rfc8785.dumps(manifest)))}
    with pytest.raises(BoardError):verify(value,data.election,data.trust)


@pytest.mark.parametrize('field',['authority','evidence','publication'])
def test_missing_or_wrong_independent_pins(data,field):
    with pytest.raises(BoardError) as missing:verify(data.bundle,data.election,replace(data.trust,**{field:b''}))
    assert missing.value.code=='UNVERIFIED'
    with pytest.raises(BoardError):verify(data.bundle,data.election,replace(data.trust,**{field:bytes(32)}))


def test_duplicate_json_and_noncanonical_file_rejected(data):
    with pytest.raises(BoardError):decode(b'{"version":1,"version":1}')
    with pytest.raises(BoardError):decode(b' '+rfc8785.dumps(data.bundle))


def test_publisher_verifies_original_evidence_and_committed_bytes(data,tmp_path):
    store=Mock()
    store.call.side_effect=lambda name,*args: {'input':data.source,'published_hex':None} if name=='input' else args[-1]
    publisher=Publisher(store,data.trust,data.pub_key.sign,data.directory)
    result=publisher.publish('adm1.'+'A'*43,data.election)
    assert result['status']=='PUBLISHED'
    finish=store.call.call_args.args
    assert finish[0]=='finish' and finish[-1]==rfc8785.dumps(data.bundle)
    assert hashlib.sha256(finish[-1]).hexdigest()==result['bundle_digest']
    missing=Publisher(store,data.trust,data.pub_key.sign,tmp_path)
    store.reset_mock()
    with pytest.raises(BoardError):missing.publish('adm1.'+'A'*43,data.election)
    assert all(call.args[0]!='finish' for call in store.call.call_args_list)


def test_existing_publication_recovery_needs_no_signer_or_original_file(data,tmp_path):
    store=Mock();store.call.return_value={'published_hex':rfc8785.dumps(data.bundle).hex()}
    signer=Mock(side_effect=AssertionError('Must not sign again'))
    result=Publisher(store,data.trust,signer,tmp_path).publish('adm1.'+'A'*43,data.election)
    assert result['status']=='PUBLISHED';signer.assert_not_called();assert store.call.call_count==1


def test_commit_error_is_never_reported_as_success():
    conn=MagicMock();conn.__enter__.return_value=conn
    conn.execute.return_value.fetchone.return_value=(b'not-committed',)
    conn.__exit__.side_effect=RuntimeError('SECRET_CANARY')
    with pytest.raises(BoardError) as error:Store(lambda:conn).call('finish',bytes(32),str(uuid4()),b'',bytes(64),b'')
    assert error.value.code=='UNAVAILABLE' and 'SECRET_CANARY' not in str(error.value)


def test_public_http_pagination_receipt_and_only_public_record_fields(data):
    store=Mock();store.call.return_value=rfc8785.dumps(data.bundle)
    with client(create_board_app(Board(store,data.trust))) as http:
        base='/api/v1/board/'+data.election
        first=http.get(base+'/ballots?limit=2');assert first.status_code==200
        assert first.headers['cache-control']=='no-store'
        page=first.json();assert len(page['records'])==2 and page['next_cursor']
        second=http.get(base+'/ballots?limit=2&cursor='+page['next_cursor'])
        assert second.status_code==200 and len(second.json()['records'])==1 and second.json()['next_cursor'] is None
        for row in page['records']:assert set(row)=={'election_id','serial','envelope','prepared_msg','signature','receipt_hash'}
        found=http.get(base+'/receipts/'+page['records'][0]['receipt_hash'])
        assert found.status_code==200 and found.json()['status']=='FOUND'
        assert http.get(base+'/receipts/'+'0'*64).status_code==404
        assert http.post(base+'/results',json={}).status_code==405
        assert http.get(base+'/results').json()['tally']==data.bundle['tally']


def test_cursor_cannot_be_reused_for_another_snapshot_or_unknown_boundary(data):
    store=Mock();store.call.return_value=rfc8785.dumps(data.bundle)
    with client(create_board_app(Board(store,data.trust))) as http:
        base='/api/v1/board/'+data.election+'/ballots?cursor=1.'+data.election+'.'
        actual=data.bundle['tally']['report']['snapshot_digest']
        known=data.bundle['snapshot']['ballots'][0]['receipt_hash']
        assert http.get(base+'0'*64+'.'+known).status_code==422
        assert http.get(base+actual+'.'+'0'*64).status_code==422


@pytest.mark.parametrize('suffix',['/receipts/UPPER','/ballots?limit=0','/ballots?limit=01','/ballots?limit=101',
    '/ballots?limit=2&limit=3','/results?token=bad','/ballots?cursor=bad'])
def test_malformed_public_queries_rejected_before_database(suffix,data):
    service=Mock()
    with client(create_board_app(service)) as http:assert http.get('/api/v1/board/'+data.election+suffix).status_code==422
    service.evidence.assert_not_called()


@pytest.mark.parametrize('name',['authorization','cookie','x-ra-token','x-voter-id','x-request-id'])
def test_board_never_accepts_identity_headers(name):
    service=Mock()
    with client(create_board_app(service)) as http:assert http.get('/api/v1/board',headers={name:'SECRET_CANARY'}).status_code==400
    service.catalogue.assert_not_called()


def test_default_apps_fail_closed_and_generic_errors_hide_secrets(data):
    with client(create_board_app()) as http:assert http.get('/api/v1/board').status_code==503
    service=Mock();service.publish.side_effect=RuntimeError('SECRET_CANARY')
    with client(create_publication_app(service)) as http:
        url='/api/v1/publication/elections/'+data.election+'/publish'
        assert http.post(url,json={}).status_code==401
        response=http.post(url,json={},headers={'Authorization':'Bearer unit-only'})
        assert response.status_code==503 and 'SECRET_CANARY' not in response.text


def test_offline_cli_distinguishes_verified_absence_invalid_and_untrusted(data,tmp_path,capsys):
    from scripts.verify_publication import main
    from backend.crypto.credential_protocol import b64encode
    import json
    trust=tmp_path/'public-trust.json';bundle=tmp_path/'published.json'
    trust.write_bytes(rfc8785.dumps({'authority':b64encode(data.trust.authority),'evidence':b64encode(data.trust.evidence),
        'evidence_key_id':data.trust.evidence_key_id,'publication':b64encode(data.trust.publication),'publication_key_id':data.trust.publication_key_id}))
    bundle.write_bytes(rfc8785.dumps(data.bundle))
    args=['--bundle',str(bundle),'--trusted-keys',str(trust),'--election-id',data.election]
    assert main(args)==0 and json.loads(capsys.readouterr().out)=={'status':'VERIFIED'}
    assert main(args+['--receipt','0'*64])==3 and json.loads(capsys.readouterr().out)=={'status':'NOT_FOUND'}
    bundle.write_bytes(b'{}')
    assert main(args)==1 and json.loads(capsys.readouterr().out)=={'status':'INVALID'}
    trust.unlink()
    assert main(args)==2 and json.loads(capsys.readouterr().out)=={'status':'UNVERIFIED'}


def test_only_matching_encrypted_publication_key_can_sign(data,tmp_path):
    from backend.board.launcher import EncryptedPublicationSigner
    from scripts.admin_voter_e2e import write_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    path=tmp_path/'generated.encrypted.pem';unlock=write_key(path,data.pub_key)
    raw=b'public-unit-test-only'
    signature=EncryptedPublicationSigner(path,unlock,data.trust.publication)(raw)
    Ed25519PublicKey.from_public_bytes(data.trust.publication).verify(signature,raw)
    with pytest.raises(BoardError):EncryptedPublicationSigner(path,unlock,data.trust.evidence)(raw)
