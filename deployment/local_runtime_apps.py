"""New local composition using reviewed application classes and frozen protocols.

No production launcher is invoked or relaxed. No hosted environment is spoofed.
The controller supplies service-scoped private config through a pipe, with an
ownership broker that exposes no Docker socket or privileged SQL capability.
"""
from contextlib import ExitStack
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from pydantic import SecretStr

from backend.crypto.credential_protocol import b64decode, verify_manifest
from deployment.local_demo_policy import SERVICES, require
from deployment.local_runtime_database import connection_factory


def key_ids(plan):
    suffix = plan['identifiers']['profile'].replace('-','')
    return {name:'local-'+name+'-'+suffix for name in ('ra','tally','evidence','publication','recovery')}


def validate_package(service, package):
    spec = SERVICES[service]
    expected = {'passwords','keys','verifiers','public'} | ({'recovery'} if service in {'ra_a','ra_b'} else set())
    require(set(package) == expected and set(package['passwords']) == set(spec['roles'])
        and set(package['keys']) == set(spec['keys'])-{'ra_recovery'}
        and set(package['verifiers']) == set(spec['verifiers']), 'ASSET_BOUNDARY')
    require(set(package['public']) == {'ra_signing','tally_decryption','manifest_signing','evidence_signing','publication_signing'}, 'ASSET_BOUNDARY')
    for entry in package['public'].values(): require(set(entry) == {'spki','pin','fingerprint'}, 'ASSET_BOUNDARY')


def private_key(package, name):
    entry = package['keys'][name]
    require(entry['pem'].startswith('-----BEGIN ENCRYPTED PRIVATE KEY-----'), 'CONFIG')
    key = serialization.load_pem_private_key(entry['pem'].encode(),password=entry['unlock'].encode())
    actual = key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    require(actual == b64decode(package['public'][name]['spki']), 'IDENTITY')
    return key


def public_keyset(plan, public):
    ids = key_ids(plan)
    return {'synthetic-local':dict(ra_key=dict(key_id=ids['ra'],spki=public['ra_signing']['spki'],fingerprint=public['ra_signing']['fingerprint']),
        tally_key=dict(key_id=ids['tally'],spki=public['tally_decryption']['spki'],fingerprint=public['tally_decryption']['fingerprint']),
        private_key_reference='local-demo:'+plan['identifiers']['profile'])}


def ra_app(plan, service, package, factories, signer, election_bundle):
    from fastapi import FastAPI
    from backend.ra.auth_service import RAAuthenticationService
    from backend.ra.auth_middleware import AuthNoStoreMiddleware
    from backend.ra.credential_runtime import CredentialNoStore
    from backend.ra.credential_router import router as credentials, get_credential_service
    from backend.ra.demo_credential_verifier import DemoCredentialVerifier
    from backend.ra.demo_launcher import LocalDemoMiddleware
    from backend.ra.election_catalogue import ElectionCatalogue, router as catalogue, get_election_catalogue
    from backend.ra.login_rate_limit import LimitedDemoAuthentication
    from backend.ra.login_router import router as login, get_ra_auth_service
    from backend.ra.session_router import router as session, get_ra_session_service
    from backend.ra.credential_service import CredentialIssuanceService
    from backend.ra.credential_recovery import CredentialRecovery
    from backend.ra.postgres_credential_store import PostgreSQLCredentialStore
    from scripts.voting_tally_auth import SessionStore, BoundSessions, BoundIssuance
    voter = 'voter_a' if service == 'ra_a' else 'voter_b'
    subject = 'demo-voter-001' if service == 'ra_a' else 'demo-voter-002'
    verifier = package['verifiers'][voter]
    account = SessionStore(factories['ra_auth_login'],UUID(plan['identifiers'][voter]),subject)
    authentication = LimitedDemoAuthentication(RAAuthenticationService(DemoCredentialVerifier(
        username=verifier['username'],password_salt=b64decode(verifier['salt'],16),password_digest=b64decode(verifier['digest'],32),
        provider='demo-local',subject=subject,enable_demo=True),account,account))
    sessions = BoundSessions(account)
    pin = b64decode(package['public']['manifest_signing']['pin'],32)
    manifest,_ = verify_manifest(election_bundle,pin,election_bundle['manifest']['election_id'])
    keys = public_keyset(plan,package['public'])['synthetic-local']
    require(manifest['ra_key'] == keys['ra_key'] and manifest['tally_key'] == keys['tally_key'], 'IDENTITY')
    recovery_id = key_ids(plan)['recovery']
    issuance = CredentialIssuanceService(PostgreSQLCredentialStore(factories['ra_issuance_login']),signer,
        CredentialRecovery({recovery_id:b64decode(package['recovery'],32)},recovery_id),pin)
    listing = ElectionCatalogue(issuance.store,pin,[UUID(manifest['election_id'])])
    app = FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    for router in (login,session,credentials,catalogue): app.include_router(router)
    app.dependency_overrides.update({get_ra_auth_service:lambda:authentication,get_ra_session_service:lambda:sessions,
        get_credential_service:lambda:BoundIssuance(issuance,sessions),get_election_catalogue:lambda:listing})
    for middleware in (LocalDemoMiddleware,AuthNoStoreMiddleware,CredentialNoStore): app.add_middleware(middleware)
    return app


def create_app(plan, service, package, boundary, resources: ExitStack, *, election_bundle=None,
               signer_binary=None, signer_digest=None, evidence_directory=None):
    validate_package(service,package)
    factories = {role:connection_factory(plan,service,role,SecretStr(password),boundary=boundary[role])
        for role,password in package['passwords'].items()}
    for factory in factories.values():
        with factory(): pass  # Refuse readiness until actual DB+ACL checks succeed.
    pin = b64decode(package['public']['manifest_signing']['pin'],32)
    if service in {'ra_a','ra_b'}:
        from backend.ra.credential_signer import LocalCIRCLSigner
        from deployment.local_runtime_processes import verify_binary
        binary = verify_binary(signer_binary,signer_digest)
        signer = LocalCIRCLSigner(binary,private_key(package,'ra_signing'),key_ids(plan)['ra'])
        resources.callback(signer.close)
        return ra_app(plan,service,package,factories,signer,election_bundle)
    if service == 'voting':
        from backend.voting.local_launcher import create_voting_app
        from backend.voting.ballot_service import BallotService
        from backend.voting.postgres_ballot_store import PostgreSQLBallotStore
        return create_voting_app(BallotService(PostgreSQLBallotStore(factories['voting_ballot_login']),pin))
    if service == 'admin':
        from backend.admin.auth import AdminAuthentication
        from backend.admin.router import create_admin_app
        from backend.admin.service import AdminService, ManifestAuthority
        from backend.admin.store import VotingAdminStore, RAPublisherStore
        store = VotingAdminStore(factories['voting_admin_login'])
        entry = package['verifiers']['admin']
        auth = AdminAuthentication(store,plan['identifiers']['admin'],entry['username'],b64decode(entry['salt'],16),b64decode(entry['digest'],32))
        return create_admin_app(AdminService(auth,store,RAPublisherStore(factories['ra_election_publisher_login']),
            ManifestAuthority(private_key(package,'manifest_signing'),pin),public_keyset(plan,package['public'])))
    if service == 'tally':
        from backend.tally.http import create_tally_app
        from backend.tally.runtime import TallyAuthentication, TallyService, TallyStore
        from backend.tally.verification import EvidenceVault
        store = TallyStore(factories['voting_tally_login']); entry = package['verifiers']['tally']
        auth = TallyAuthentication(store,UUID(plan['identifiers']['tally']),entry['username'],b64decode(entry['salt'],16),b64decode(entry['digest'],32))
        vault = EvidenceVault(Path(evidence_directory),private_key(package,'evidence_signing'),
            b64decode(package['public']['evidence_signing']['pin'],32),key_ids(plan)['evidence'])
        tally_key = private_key(package,'tally_decryption')
        def load(metadata):
            require(metadata['key_id'] == key_ids(plan)['tally'], 'IDENTITY')
            return tally_key
        return create_tally_app(TallyService(auth,store,pin,vault,load))
    if service in {'publisher','board'}:
        from backend.board.http import create_board_app, create_publication_app
        from backend.board.service import Board, Publisher, Store
        from backend.board.verification import Trust
        trust = Trust(pin,b64decode(package['public']['evidence_signing']['pin'],32),key_ids(plan)['evidence'],
            b64decode(package['public']['publication_signing']['pin'],32),key_ids(plan)['publication'])
        trust.validate()
        store = Store(factories['voting_publication_login' if service == 'publisher' else 'voting_board_login'])
        if service == 'board': return create_board_app(Board(store,trust))
        key = private_key(package,'publication_signing')
        return create_publication_app(Publisher(store,trust,key.sign,Path(evidence_directory)))
    require(False,'ASSET_BOUNDARY')
