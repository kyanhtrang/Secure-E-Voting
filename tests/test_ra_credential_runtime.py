import hashlib
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.crypto.credential_protocol import b64encode
from backend.ra.credential_service import CredentialUnavailable
from backend.ra.credential_signer import LocalCIRCLSigner


@pytest.fixture(scope="module")
def test_key():
    return rsa.generate_private_key(public_exponent=65537,key_size=3072)


def boot(monkeypatch,key):
    fingerprint=hashlib.sha256(key.public_key().public_bytes(
        serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).digest()
    process=MagicMock()
    process.stdout=BytesIO()
    popen=Mock(return_value=process)
    replies=Mock(side_effect=[{"key_id":"test-ra","fingerprint":fingerprint.hex()},
                             {"blind_sig":b64encode(b"s"*384)}])
    monkeypatch.setattr("backend.ra.credential_signer.subprocess.Popen",popen)
    monkeypatch.setattr(LocalCIRCLSigner,"_call",replies)
    signer=LocalCIRCLSigner(Path("reviewed-test-signer"),key,"test-ra")
    return signer,popen,replies,process


def test_signer_uses_private_stdin_bootstrap_and_original_message(monkeypatch,test_key):
    signer,popen,replies,process=boot(monkeypatch,test_key)
    assert popen.call_args.args==(["reviewed-test-signer"],)
    assert "shell" not in popen.call_args.kwargs and "env" not in popen.call_args.kwargs
    assert set(replies.call_args_list[0].args[0])=={"op","key_id","private_key_pkcs8"}
    original=b"b"*384
    assert signer.sign(original)==b"s"*384
    assert replies.call_args.args[0]=={"op":"sign","key_id":"test-ra","blinded_msg":b64encode(original)}
    assert not signer.matches("wrong",signer._fingerprint)
    assert not signer.matches("test-ra",b"wrong")
    signer.close()


def test_signer_does_not_reuse_process_after_uncertain_reply(monkeypatch,test_key):
    signer,_,replies,process=boot(monkeypatch,test_key)
    replies.side_effect=TimeoutError("synthetic secret canary")
    process.poll.return_value=None
    with pytest.raises(CredentialUnavailable) as caught:
        signer.sign(b"b"*384)
    assert str(caught.value)==""
    process.kill.assert_called_once()
    assert signer._process is None


def test_signer_rejects_digest_before_rpc(monkeypatch,test_key):
    signer,_,replies,_=boot(monkeypatch,test_key)
    with pytest.raises(CredentialUnavailable):
        signer.sign(b"h"*32)
    assert replies.call_count==1
    signer.close()


def test_launcher_requires_explicit_flags_without_reading_configuration(monkeypatch):
    from backend.ra import credential_launcher as launcher
    reader=Mock(side_effect=AssertionError("must not read credentials"))
    monkeypatch.setattr(launcher,"load_local_verifier",reader)
    monkeypatch.setattr("sys.argv",["credential_launcher"])
    with pytest.raises(SystemExit):
        launcher.main()
    reader.assert_not_called()


def test_launcher_prompts_and_local_security_settings(monkeypatch,test_key,tmp_path,capsys):
    from backend.ra import credential_launcher as launcher
    from tests.demo_auth_helpers import demo_environment
    key_path=tmp_path/"ephemeral-encrypted-test-key.pem"
    # Generated TEST key only. Never inspect the user's configured key paths.
    key_path.write_bytes(test_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                        serialization.BestAvailableEncryption(b"synthetic-test-unlock")))
    pin=tmp_path/"public-pin"
    pin.write_bytes(b"p"*32)
    monkeypatch.setattr("sys.argv",["credential_launcher","--enable-local-demo","--load-local-verifier",
        "--enable-credential-issuance","--signer-binary","test-signer","--encrypted-signing-key",str(key_path),
        "--manifest-authority-pin",str(pin),"--key-id","test-ra","--recovery-key-id","test-recovery"])
    config=demo_environment()
    config.pop("RA_DEMO_DB_PASSWORD")
    monkeypatch.setattr(launcher,"load_local_verifier",Mock(return_value=config))
    values=["synthetic-auth-db","synthetic-issuance-db",b64encode(b"r"*32),"synthetic-test-unlock"]
    monkeypatch.setattr(launcher.getpass,"getpass",Mock(side_effect=values))
    signer=Mock()
    monkeypatch.setattr(launcher,"LocalCIRCLSigner",Mock(return_value=signer))
    app=Mock()
    build=Mock(return_value=app)
    monkeypatch.setattr(launcher,"create_credential_app",build)
    run=Mock()
    monkeypatch.setattr(launcher.uvicorn,"run",run)
    launcher.main()
    assert run.call_args.args==(app,)
    options=run.call_args.kwargs
    assert options["host"]=="127.0.0.1" and options["workers"]==1
    assert options["proxy_headers"] is False and options["access_log"] is False
    assert options["forwarded_allow_ips"]==""
    assert "RA_DEMO_DB_PASSWORD" not in config
    signer.close.assert_called_once()
    output=capsys.readouterr()
    for secret in values:
        assert secret not in output.out+output.err


def test_prompt_refuses_echo_fallback(monkeypatch):
    import warnings
    from backend.ra.credential_launcher import prompt
    import getpass
    def insecure(_):
        warnings.warn("Echo fallback",getpass.GetPassWarning)
    monkeypatch.setattr(getpass,"getpass",insecure)
    with pytest.raises(getpass.GetPassWarning):
        prompt("test")
