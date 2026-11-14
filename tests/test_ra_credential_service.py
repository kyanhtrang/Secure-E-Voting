from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from backend.ra.credential_service import (
    CredentialConflict, CredentialDenied, CredentialExpired, CredentialUnavailable, InvalidBlindedMessage,
)
from backend.ra.session_service import InvalidRASession
from tests.credential_helpers import credential_environment, credential_material


@pytest.fixture(scope="module")
def material():
    return credential_material()


@pytest.fixture
def setup(material):
    return credential_environment(material)


def issue(env, request=None, blinded=None):
    return env.service.issue(env.token, env.store.election, request or env.request,
                             env.blinded if blinded is None else blinded)


def test_authorized_issuance_signs_original_bytes_after_commit(setup):
    result = issue(setup)
    assert result.blind_signature == setup.signature and not result.replayed
    setup.signer.sign.assert_called_once_with(setup.blinded)
    assert len(setup.blinded) == 384
    assert setup.store.events == ["reservation committed", "signed original bytes", "completion staged", "completion committed"]
    record = next(iter(setup.store.completed.values()))
    assert record.ciphertext != setup.signature and len(record.ciphertext) == 400
    assert setup.signature not in record.ciphertext


def test_identical_retries_return_stored_response_without_signing(setup):
    first = issue(setup)
    second = issue(setup)
    assert second.replayed and second.blind_signature == first.blind_signature
    setup.signer.sign.assert_called_once()
    assert len(setup.store.records) == len(setup.store.completed) == 1


@pytest.mark.parametrize("field", ["active", "session_valid"])
def test_invalid_inactive_or_expired_session_never_reserves(setup, field):
    setattr(setup.store, field, False)
    with pytest.raises(InvalidRASession):
        issue(setup)
    assert not setup.store.records
    setup.signer.sign.assert_not_called()


def test_ineligible_voter_never_reserves(setup):
    setup.store.eligible = False
    with pytest.raises(CredentialDenied):
        issue(setup)
    assert not setup.store.records


@pytest.mark.parametrize("changed", ["request", "bytes"])
def test_different_request_is_rejected_after_reservation(setup, changed):
    setup.signer.sign.side_effect = CredentialUnavailable()
    with pytest.raises(CredentialUnavailable):
        issue(setup)
    with pytest.raises(CredentialConflict):
        issue(setup, request=uuid4() if changed == "request" else None,
              blinded=b"\x02"*384 if changed == "bytes" else None)
    assert len(setup.store.records) == 1 and not setup.store.completed


def test_signer_failure_can_retry_only_exact_request(setup):
    setup.signer.sign.side_effect = CredentialUnavailable()
    with pytest.raises(CredentialUnavailable): issue(setup)
    setup.signer.sign.side_effect = None
    setup.signer.sign.return_value = setup.signature
    assert issue(setup).blind_signature == setup.signature
    assert len(setup.store.records) == len(setup.store.completed) == 1


def test_crash_after_reservation_preserves_authorization(setup):
    setup.store.fail_reservation_response = True
    with pytest.raises(CredentialUnavailable): issue(setup)
    setup.signer.sign.assert_not_called()
    assert len(setup.store.records) == 1
    setup.store.fail_reservation_response = False
    assert issue(setup).blind_signature == setup.signature


def test_crash_after_signing_before_persistence_can_retry(setup):
    original = setup.recovery.encrypt
    setup.recovery.encrypt = Mock(side_effect=CredentialUnavailable())
    with pytest.raises(CredentialUnavailable): issue(setup)
    assert not setup.store.completed and len(setup.store.records) == 1
    setup.recovery.encrypt = original
    assert issue(setup).blind_signature == setup.signature
    assert setup.signer.sign.call_count == 2
    assert all(call.args == (setup.blinded,) for call in setup.signer.sign.call_args_list)


@pytest.mark.parametrize("after_commit", [False, True])
def test_commit_failure_never_returns_success_and_exact_retry_recovers(setup, after_commit):
    setattr(setup.store, "fail_after_commit" if after_commit else "fail_before_commit", True)
    with pytest.raises(CredentialUnavailable): issue(setup)
    assert bool(setup.store.completed) == after_commit
    setup.store.fail_before_commit = setup.store.fail_after_commit = False
    setup.signer.sign.side_effect = None
    setup.signer.sign.return_value = setup.signature
    result = issue(setup)
    assert result.blind_signature == setup.signature
    assert result.replayed == after_commit
    assert setup.signer.sign.call_count == (1 if after_commit else 2)


def test_expiry_never_releases_the_reserved_slot(setup):
    setup.signer.sign.side_effect = CredentialUnavailable()
    with pytest.raises(CredentialUnavailable): issue(setup)
    setup.store.now = setup.store.expiry
    with pytest.raises(CredentialExpired): issue(setup)
    with pytest.raises(CredentialConflict): issue(setup, uuid4())
    assert len(setup.store.records) == 1


def test_concurrent_different_requests_have_one_winner_in_business_model(setup):
    def attempt(request):
        try:
            return issue(setup, request)
        except CredentialConflict:
            return None
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, [uuid4(), uuid4()]))
    assert sum(result is not None for result in results) == 1
    assert len(setup.store.records) == len(setup.store.completed) == 1
    setup.signer.sign.assert_called_once()


def test_legacy_completed_issuance_blocks_new_reservation(setup):
    setup.store.completed[(setup.store.voter, setup.store.election)] = object()
    with pytest.raises(CredentialConflict): issue(setup)
    assert not setup.store.records
    setup.signer.sign.assert_not_called()


@pytest.mark.parametrize("blinded", [b"", b"\0"*32, b"\0"*384, b"\xff"*384])
def test_bad_blinded_representative_is_rejected_before_reservation(setup, blinded):
    with pytest.raises(InvalidBlindedMessage): issue(setup, blinded=blinded)
    assert not setup.store.records
    setup.signer.sign.assert_not_called()


def test_wrong_signed_policy_fails_before_reservation(setup):
    setup.store.public_policy = replace(setup.store.public_policy, manifest_signature=bytes(64))
    with pytest.raises(CredentialUnavailable): issue(setup)
    assert not setup.store.records


def test_wrong_signing_key_does_not_issue_or_release_reservation(setup):
    setup.signer.matches.return_value = False
    with pytest.raises(CredentialUnavailable): issue(setup)
    setup.signer.sign.assert_not_called()
    assert len(setup.store.records) == 1 and not setup.store.completed


def test_recovery_aad_binds_request_election_and_storage_context(setup):
    issue(setup)
    context = next(iter(setup.store.completed.values()))
    for changed in (replace(context, request_id=uuid4()), replace(context, election_id=uuid4()),
                    replace(context, voter_id=uuid4()), replace(context, config_hash=bytes(32)),
                    replace(context, nonce=bytes(12)), replace(context, storage_key_id="missing"),
                    replace(context, ciphertext=bytes(400))):
        with pytest.raises(CredentialUnavailable): setup.recovery.decrypt(changed)
    assert setup.recovery.decrypt(context) == setup.signature


def test_lost_recovery_key_does_not_reset_slot(setup):
    issue(setup)
    from backend.ra.credential_recovery import CredentialRecovery
    setup.service.recovery = CredentialRecovery({"replacement": bytes(32)}, "replacement")
    with pytest.raises(CredentialUnavailable): issue(setup)
    with pytest.raises(CredentialConflict): issue(setup, uuid4())
    assert len(setup.store.records) == len(setup.store.completed) == 1
