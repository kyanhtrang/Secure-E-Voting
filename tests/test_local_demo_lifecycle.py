"""Pure lifecycle policy rehearsals. They do not start or stop real processes."""
import ast
from pathlib import Path
from uuid import uuid4
import pytest
from deployment.local_demo_lifecycle import StartupLedger, ProcessRef, CORE, VOTING
from deployment.local_demo_policy import ReviewRefused


def reference(profile,service,index=0,boot_id=None):return ProcessRef(profile,service,boot_id or str(uuid4()),100+index,1000+index,1000)


def test_startup_failure_returns_reverse_owned_stop_intents_without_any_database_cleanup():
    profile=str(uuid4());ledger=StartupLedger(profile);refs=[]
    for index,service in enumerate(CORE[:3]):
        ref=reference(profile,service,index,ledger.boot_id);ledger.record_started(ref);ledger.mark_ready(ref);refs.append(ref)
    safe,refused=ledger.stop_plan({ref.service:ref for ref in refs})
    assert safe==tuple(reversed(refs)) and refused==()
    assert all(ref.service not in ('ra_database','voting_database') for ref in safe)
    with pytest.raises(ReviewRefused):ledger.record_started(reference(profile,'publisher',4))


def test_no_voter_service_until_core_is_ready_and_verified_election_explicitly_bound():
    profile=str(uuid4());ledger=StartupLedger(profile)
    with pytest.raises(ReviewRefused):ledger.record_started(reference(profile,'ra_a'))
    for index,service in enumerate(CORE):
        ref=reference(profile,service,index,ledger.boot_id);ledger.record_started(ref)
        if index==0:
            with pytest.raises(ReviewRefused):ledger.record_started(reference(profile,'admin',99,ledger.boot_id))
        ledger.mark_ready(ref)
    with pytest.raises(ReviewRefused):ledger.record_started(reference(profile,'ra_a',99,ledger.boot_id))
    ledger.bind_verified_election()
    for index,service in enumerate(VOTING,start=len(CORE)):
        ref=reference(profile,service,index,ledger.boot_id);ledger.record_started(ref);ledger.mark_ready(ref)
    assert ledger.ready==set(CORE+VOTING)


@pytest.mark.parametrize('change',['profile','pid','start_ticks','boot_id','uid'])
def test_shutdown_never_targets_a_reused_or_unowned_process(change):
    profile=str(uuid4());ledger=StartupLedger(profile);ref=reference(profile,'voting');ledger.record_started(ref)
    fields=dict(profile=ref.profile,service=ref.service,boot_id=ref.boot_id,pid=ref.pid,start_ticks=ref.start_ticks,uid=ref.uid)
    fields[change]=str(uuid4()) if change in ('profile','boot_id') else 9999
    safe,refused=ledger.stop_plan({'voting':ProcessRef(**fields)})
    assert safe==() and refused==('voting',)


def test_unobserved_process_is_preserved_and_database_is_never_in_ledger():
    profile=str(uuid4());ledger=StartupLedger(profile)
    with pytest.raises(ReviewRefused):ledger.record_started(reference(profile,'ra_database'))
    ref=reference(profile,'voting');ledger.record_started(ref)
    assert ledger.stop_plan({})==((),('voting',))


def test_runtime_cannot_be_root_or_span_multiple_vm_boots():
    profile=str(uuid4());ledger=StartupLedger(profile);ref=reference(profile,'voting')
    with pytest.raises(ReviewRefused):ledger.record_started(ProcessRef(profile,'voting',ref.boot_id,100,1000,0))
    ledger.record_started(ref);ledger.mark_ready(ref)
    with pytest.raises(ReviewRefused):ledger.record_started(reference(profile,'admin',1))


def test_preflight_and_ledger_import_no_execution_database_or_network_modules():
    root=Path(__file__).resolve().parents[1]
    forbidden={'subprocess','psycopg','sqlalchemy','docker','socket','shutil','getpass'}
    for name in ('deployment/local_demo_policy.py','deployment/local_demo_lifecycle.py','scripts/local_demo_preflight.py'):
        tree=ast.parse((root/name).read_text(encoding='utf8'))
        imports={node.names[0].name.split('.')[0] for node in ast.walk(tree) if isinstance(node,ast.Import)}
        imports|={node.module.split('.')[0] for node in ast.walk(tree) if isinstance(node,ast.ImportFrom) and node.module}
        assert not imports & forbidden
        attributes={node.func.attr for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)}
        assert not attributes & {'connect','execute','Popen','unlink','rmtree','kill','terminate','startfile'}
