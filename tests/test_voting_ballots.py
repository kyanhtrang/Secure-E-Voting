import copy
import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from uuid import uuid4

import pytest
import rfc8785
from fastapi.testclient import TestClient

from backend.crypto.credential_protocol import ProtocolError, b64decode, b64encode
from backend.voting.ballot_router import get_ballot_service, router
from backend.voting.ballot_service import (
    AlreadySpent, BallotService, ElectionClosed, ReceiptNotFound, VotingUnavailable, receipt_digest,
)
from tests.voting_helpers import MemoryBallotStore, material, payload_for


@pytest.fixture(scope="module")
def keys():
    return material()


@pytest.fixture
def env(keys):
    from types import SimpleNamespace
    from fastapi import FastAPI
    store = MemoryBallotStore(keys)
    service = BallotService(store, keys.pin)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_ballot_service] = lambda: service
    return SimpleNamespace(store=store, service=service, payload=payload_for(keys), client=TestClient(app))


URL = "/api/v1/vote/ballots"


def test_accept_duplicate_and_protected_receipt_recovery(env):
    result = env.client.post(URL, json=env.payload)
    assert result.status_code == 201
    assert result.json() == {"status": "accepted", "receipt_hash": env.service.recover(env.payload)}
    assert result.headers["cache-control"] == "no-store"
    assert env.client.post(URL, json=env.payload).status_code == 409
    env.store.open = False
    assert env.client.post(URL+"/receipt", json=env.payload).json() == result.json()
    assert len(env.store.rows) == 1


def test_existing_receipt_definition(env):
    proof = env.payload["credential"]
    expected = {"election_id": env.payload["election_id"], "serial": proof["message"]["serial"],
                "envelope_hash": proof["message"]["envelope_hash"],
                "prepared_msg": proof["prepared_msg"], "signature": proof["signature"]}
    assert receipt_digest(env.payload["election_id"], proof, proof["message"]["envelope_hash"]) == hashlib.sha256(
        b"EVOTE-RECEIPT-v1\x00"+rfc8785.dumps(expected)).digest()


@pytest.mark.parametrize("change", ["signature", "serial", "election", "config", "envelope", "key", "nonce",
                                   "wrap", "tag", "algorithm", "extra", "padding", "prefix", "noncanonical"])
def test_reject_modified_or_malformed_inputs_before_accept(env, change):
    value = copy.deepcopy(env.payload)
    proof, envelope = value["credential"], value["envelope"]
    if change == "signature":
        proof["signature"] = b64encode(b"\x01"*384)
    elif change == "serial":
        proof["message"]["serial"] = b64encode(b"\x01"*32)
    elif change == "election":
        proof["message"]["election_id"] = str(uuid4())
    elif change == "config":
        proof["message"]["config_hash"] = "a"*64
    elif change == "envelope":
        envelope["ciphertext"] = b64encode(b"x"*64)
    elif change == "key":
        envelope["key_id"] = "substituted"
    elif change == "nonce":
        envelope["nonce"] = b64encode(b"x"*11)
    elif change == "wrap":
        envelope["encrypted_key"] = b64encode(b"x"*383)
    elif change == "tag":
        envelope["ciphertext"] = b64encode(b"x"*16)
    elif change == "algorithm":
        envelope["cipher_algorithm"] = "AES-CBC"
    elif change == "extra":
        envelope["voter_id"] = "SECRET_CANARY"
    elif change == "padding":
        proof["signature"] += "="
    elif change == "prefix":
        proof["prepared_msg"] = b64encode(b64decode(proof["prepared_msg"])[1:])
    else:
        raw = b64decode(proof["prepared_msg"])
        proof["prepared_msg"] = b64encode(raw[:32]+b" "+raw[32:])
    result = env.client.post(URL, json=value)
    assert result.status_code == 422
    assert not env.store.rows and "accept" not in env.store.calls
    assert "SECRET_CANARY" not in result.text


@pytest.mark.parametrize("field", ["voter_id", "username", "ra_token", "request_id", "manifest", "pin"])
def test_unknown_identity_or_trust_fields_rejected(env, field):
    env.payload[field] = "SECRET_CANARY"
    assert env.client.post(URL, json=env.payload).status_code == 422
    assert not env.store.calls


@pytest.mark.parametrize("header", ["Authorization", "Cookie", "X-Voter-ID", "X-RA-Token", "X-Username", "X-Request-ID"])
def test_no_ra_credentials_accepted_or_logged(env, header, caplog):
    result = env.client.post(URL, json=env.payload, headers={header: "SECRET_CANARY"})
    assert result.status_code == 400
    assert not env.store.calls
    assert "SECRET_CANARY" not in result.text+caplog.text


@pytest.mark.parametrize("body", [b'{"election_id":"SECRET_CANARY","election_id":"other"}',
                                  b'{"password":"SECRET_CANARY"', b'NaN', b'\xff', b'[]'])
def test_strict_json_generic_no_store_errors(env, body):
    response = env.client.post(URL, content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 422 and "SECRET_CANARY" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_body_bound_query_and_content_type(env):
    assert env.client.post(URL, content=b"x"*32769, headers={"Content-Type": "application/json"}).status_code == 413
    assert env.client.post(URL+"?voter_id=SECRET_CANARY", json=env.payload).status_code == 400
    assert env.client.post(URL, content=b"{}").status_code == 415


def test_disabled_by_default_and_no_ra_routes_in_voting(env):
    from backend.main import app
    from backend.voting.local_launcher import create_voting_app
    assert TestClient(app).post(URL, json=env.payload).status_code == 503
    app = create_voting_app(env.service)
    client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
    assert client.post("/api/v1/ra/auth/login", json={}).status_code == 404
    assert client.post(URL, json=env.payload).status_code == 201
    assert client.post(URL, json=env.payload, headers={"Origin": "https://attacker.invalid"}).status_code == 403


@pytest.mark.parametrize("field", ["signature", "config_digest", "authority_fingerprint", "opens_at", "manifest_bytes"])
def test_database_policy_corruption_fails_closed(env, field):
    current = env.store.policy_value
    bad = b"x"*len(getattr(current, field)) if isinstance(getattr(current, field), bytes) else current.closes_at
    env.store.policy_value = replace(current, **{field: bad})
    assert env.client.post(URL, json=env.payload).status_code == 503
    assert not env.store.rows


def test_wrong_authority_pin(env):
    env.service._pin = b"x"*32
    assert env.client.post(URL, json=env.payload).status_code == 503


def test_authority_metadata_preserves_der_spki_fingerprint_contract(env, keys):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    der = ed25519.Ed25519PublicKey.from_public_bytes(keys.pin).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert env.store.policy_value.authority_fingerprint == hashlib.sha256(der).digest()
    env.store.policy_value = replace(env.store.policy_value, authority_fingerprint=hashlib.sha256(keys.pin).digest())
    assert env.client.post(URL, json=env.payload).status_code == 503


@pytest.mark.parametrize("salt,prefix", [(47, 32), (49, 32), (48, 31), (48, 33)])
def test_pss_profile_exact_lengths(keys, salt, prefix):
    with pytest.raises(ProtocolError):
        BallotService(MemoryBallotStore(keys), keys.pin).submit(payload_for(keys, salt_length=salt, prefix_length=prefix))


def test_twenty_competing_submissions_one_acceptance_double_only(env):
    def submit(_):
        try:
            env.service.submit(env.payload)
            return 201
        except AlreadySpent:
            return 409
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(submit, range(20)))
    assert results.count(201) == 1 and results.count(409) == 19
    assert len(env.store.rows) == 1


def test_commit_failure_rollback_and_response_loss_recovery(env):
    env.store.fail_commit = True
    assert env.client.post(URL, json=env.payload).status_code == 503
    assert not env.store.rows
    env.store.fail_commit = False
    env.store.lose_response = True
    assert env.client.post(URL, json=env.payload).status_code == 503
    assert len(env.store.rows) == 1
    assert env.client.post(URL+"/receipt", json=env.payload).status_code == 200


def test_closed_and_missing_receipt(env):
    env.store.open = False
    assert env.client.post(URL, json=env.payload).status_code == 409
    assert env.client.post(URL+"/receipt", json=env.payload).status_code == 404


def test_identical_ballot_choices_are_independent(keys, env):
    second = payload_for(keys)
    assert env.service.submit(env.payload) != env.service.submit(second)
    assert len(env.store.rows) == 2


def test_database_errors_are_sanitized(env, caplog):
    def fail(*args):
        raise RuntimeError("SECRET_CANARY database password token")
    env.store.accept = fail
    result = env.client.post(URL, json=env.payload)
    assert result.status_code == 503
    assert "SECRET_CANARY" not in result.text+caplog.text


def test_signature_from_another_key_rejected(env):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    proof = env.payload["credential"]
    proof["signature"] = b64encode(other.sign(b64decode(proof["prepared_msg"]),
        padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384()))
    assert env.client.post(URL, json=env.payload).status_code == 422
    assert not env.store.rows


def test_encrypted_choice_and_tag_validation_is_explicitly_deferred(env, keys):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from backend.crypto.credential_protocol import canonical_message
    # A structurally valid envelope with a meaningless ciphertext can carry a valid credential.
    # Voting cannot assert that it decrypts or names a candidate.
    env.payload["envelope"]["ciphertext"] = b64encode(b"x"*64)
    proof = env.payload["credential"]
    proof["message"]["envelope_hash"] = hashlib.sha256(rfc8785.dumps(env.payload["envelope"])).hexdigest()
    prepared = b"p"*32+canonical_message(proof["message"])
    proof["prepared_msg"] = b64encode(prepared)
    proof["signature"] = b64encode(keys.ra.sign(prepared,
        padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384()))
    assert env.client.post(URL, json=env.payload).status_code == 201
