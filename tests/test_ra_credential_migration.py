"""Offline contract checks only; PostgreSQL execution is a separate approval gate."""
import ast
import re
from pathlib import Path
from uuid import UUID


MIGRATION=Path(__file__).resolve().parents[1]/"migrations/ra/versions/7b2d91a6c840_ra_credential_reservations.py"


def test_revision_and_forward_only_ownership_boundary():
    source=MIGRATION.read_text(encoding="utf8")
    tree=ast.parse(source)
    values={node.targets[0].id:node.value.value for node in tree.body
            if isinstance(node,ast.Assign) and isinstance(node.value,ast.Constant)}
    assert values["down_revision"]=="f3c2a1d4e6b8"
    assert values["revision"]=="7b2d91a6c840"
    assert "Forward-only" in source
    assert "CREATE ROLE" not in source and "ALTER ROLE" not in source
    assert "voting." not in source.lower()
    assert source.index("Required RA issuance roles")<source.index("SET LOCAL ROLE ra_owner")<source.index("CREATE TABLE")
    assert "UNIQUE (voter_id,election_id)" in source
    assert "Reservation required" in source and "Credential reservations are immutable" in source
    assert "p.closes_at+INTERVAL '24 hours'" in source
    assert "has_issuance AND NOT has_reservation" in source


def test_functions_definer_acl_and_preflight_fail_closed():
    source=MIGRATION.read_text(encoding="utf8")
    for role in ("ra_owner","ra_auth_login","ra_issuance_login","ra_service","ra_service_login",
                 "ra_recovery_worker","ra_audit_reader"):
        assert f"('{role}')" in source
    for check in ("has_schema_privilege","has_table_privilege","has_any_column_privilege",
                  "has_sequence_privilege","has_function_privilege","pg_auth_members","aclexplode"):
        assert check in source
    for function in source.split("CREATE FUNCTION ")[1:]:
        before_body=function.split("AS $f$")[0]
        assert "SECURITY DEFINER" in before_body
        assert "search_path=pg_catalog,ra,pg_temp" in before_body
    assert "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ra_credential FROM PUBLIC" in source
    assert "REVOKE ALL ON TYPE ra_credential.request_context FROM PUBLIC" in source
    assert "GRANT USAGE ON SCHEMA ra TO" not in source
    assert "GRANT EXECUTE ON FUNCTION ra." not in source
    assert source.count('"policy_for_session(text,uuid)"')==1


def applied_sources():
    """Follow the actual parent chain; never import/execute a migration."""
    revisions={}
    for path in MIGRATION.parent.glob("*.py"):
        source=path.read_text(encoding="utf8")
        metadata={}
        for node in ast.parse(source).body:
            if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name):
                name,value=node.targets[0].id,node.value
            elif isinstance(node,ast.AnnAssign) and isinstance(node.target,ast.Name):
                name,value=node.target.id,node.value
            else:
                continue
            if name in ("revision","down_revision"):
                metadata[name]=ast.literal_eval(value)
        revisions[metadata["revision"]]=(metadata["down_revision"],source)
    chain=[]
    current="f3c2a1d4e6b8"
    while current is not None:
        parent,source=revisions[current]
        chain.append((current,source))
        current=parent
    return dict(reversed(chain))


def compact(value):
    return re.sub(r"\s+","",value).lower()


def test_actual_final_eligibility_schema_requires_uuid_supplied_by_trusted_function():
    sources=applied_sources()
    baseline=sources["e52b0a9227ef"]
    assert re.search(r"eligibility_id\s+UUID\s+PRIMARY KEY\s*,",baseline)
    assert not re.search(r"ALTER\s+TABLE\s+(?:ra\.)?voter_eligibility.*?eligibility_id",
                        "\n".join(sources.values()),re.I|re.S)
    trusted=sources["615b4733bd61"]
    assert "CREATE FUNCTION ra.set_voter_eligibility(" in trusted
    assert compact("INSERT INTO ra.voter_eligibility(eligibility_id,voter_id,election_id,is_eligible)VALUES(pg_catalog.gen_random_uuid(),p_voter_id,p_election_id,true)") in compact(trusted)
    assert "Eligibility change blocked after issuance" in trusted
    assert "'SERVICE',p_actor_principal_id".lower() in compact(trusted)


def test_issuance_call_matches_applied_signature_and_fixed_service_audit_identity():
    sources=applied_sources()
    original=sources["1dcfbb1dd9a4"]
    parameters=re.search(r"CREATE FUNCTION ra.issue_blind_credential\((.*?)\)\s*RETURNS",original,re.S).group(1)
    assert [tuple(item.split()) for item in parameters.split(",")]==[
        ("p_voter_id","uuid"),("p_election_id","uuid"),("p_request_id","uuid"),
        ("p_blinded_request_hash","bytea"),("p_ra_key_id","text"),
        ("p_encrypted_blind_signature","bytea"),("p_storage_nonce","bytea"),
        ("p_storage_key_id","text"),("p_recovery_expires_at","timestamptz"),("p_actor_principal_id","uuid")]
    assert "p_actor_principal_id IS NULL" in original
    assert "'SERVICE',p_actor_principal_id,'BLIND_ISSUANCE_ISSUED','SUCCESS'".lower() in compact(original)
    assert "'SERVICE',p_actor_principal_id,'BLIND_ISSUANCE_REPLAYED','SUCCESS'".lower() in compact(original)
    baseline=sources["e52b0a9227ef"]
    assert "actor_principal_id UUID NOT NULL" in baseline
    assert not re.search(r"FOREIGN KEY\s*\(actor_principal_id\)",baseline)
    source=MIGRATION.read_text(encoding="utf8")
    principal=re.search(r"service_actor_id CONSTANT uuid := '([^']+)'::uuid",source).group(1)
    assert UUID(principal)==UUID("00000000-0000-4000-8000-000000000002")
    call=re.search(r"PERFORM ra.issue_blind_credential\((.*?)\);",source,re.S).group(1)
    assert [part.strip() for part in call.split(",")]==[
        "c.voter_id","c.election_id","c.request_id","c.blinded_hash","c.key_id",
        "p_cipher","p_nonce","p_storage_key","c.recovery_expires_at","service_actor_id"]
    assert source.index("CREATE FUNCTION ra_credential.complete_request")<source.index("COMMENT ON FUNCTION ra_credential.complete_request")
    wrapper_signature=source.split("CREATE FUNCTION ra_credential.complete_request(")[1].split(") RETURNS")[0]
    assert "actor" not in wrapper_signature and "voter" not in wrapper_signature


def test_schema_foreign_keys_lock_order_sessions_and_expiry_match_applied_contracts():
    sources=applied_sources()
    baseline=compact(sources["e52b0a9227ef"])
    assert "unique(voter_id,election_id)" in baseline
    assert "unique(election_id,ra_key_id)" in baseline
    assert "check(recovery_expires_at>issued_at)" in baseline
    original=compact(sources["1dcfbb1dd9a4"])
    assert original.index("fromra.votersv")<original.index("fromra.voter_eligibilitye")<original.index("fromra.blind_issuancesb")<original.index("fromra.ra_signing_keysk")
    source=compact(MIGRATION.read_text(encoding="utf8"))
    request=source.split("createfunctionra_credential._request(")[1]
    assert request.index("ra_credential._voter(p_digest)")<request.index("fromra.voter_eligibilitye")<request.index("fromra.credential_reservationsx")<request.index("fromra.blind_issuancesx")<request.index("fromra.ra_signing_keysx")<request.index("fromra.credential_policiesx")
    assert "foreignkey(voter_id,election_id)referencesra.voter_eligibility(voter_id,election_id)" in source
    assert "foreignkey(election_id,ra_key_id)referencesra.ra_signing_keys(election_id,ra_key_id)" in source
    voter=source.split("createfunctionra_credential._voter(")[1].split("createfunctionra_credential.policy_for_session")[0]
    assert voter.index("fromra.votersv")<voter.index("fromra.ra_sessionss")
    assert "s.revoked_atisnullands.expires_at>pg_catalog.clock_timestamp()forshare" in voter
    assert "eligibleisdistinctfromtrue" in request
    assert "decision>=r.recovery_expires_at" in request and "b.recovery_state<>'retained'" in request
    assert "v_issued_at:=pg_catalog.clock_timestamp()" in original
    assert "p_recovery_expires_at<=v_issued_at" in original
    assert "alterfunctionra.find_active_session(text)volatile" in compact(sources["ad688fa2b359"])
