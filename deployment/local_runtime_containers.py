"""Explicit approved VM-only container creation/start/stop. NEVER remove data.

No SQL here. Partial creation is durably recorded and preserved for review.
Bootstrap secrets use private exec stdin into container tmpfs, never argv/env.
"""
import json
import os
from pathlib import Path
import stat
import subprocess

from deployment.local_demo_policy import database_spec, fingerprint, labels, require
from deployment.local_runtime_boundary import DOCKER_PREFIX, PG_COMMAND, OwnedContainers, verify_vm


def docker(*args, secret=None, timeout=60):
    require(not Path('/run/evote-no-docker-credentials').exists(), 'ENVIRONMENT')
    result = subprocess.run(DOCKER_PREFIX+list(args),input=secret,capture_output=True,timeout=timeout,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','HOME':'/nonexistent'},check=False)
    require(result.returncode == 0 and len(result.stdout) <= 2_000_000, 'OWNERSHIP')
    return result.stdout.decode().strip()


def create(plan, approval, registry_directory, bootstrap_passwords, *, confirmation):
    verify_vm(plan,approval)
    require(os.geteuid() == 0 and confirmation == 'CREATE OWNED DEMO CONTAINERS '+fingerprint(plan), 'APPROVAL_REQUIRED')
    require(set(bootstrap_passwords) == {'ra','voting'}, 'CONFIG')
    directory = Path(registry_directory)
    require(directory.is_absolute() and not directory.is_symlink() and directory.stat().st_uid == 0
        and stat.S_IMODE(directory.stat().st_mode) == 0o700, 'OWNERSHIP')
    # Never adopt an existing resource, even when its name/labels match.
    for command,field,expected in (
        (['container','ls','--all','--format','{{.Names}}'],'container',[database_spec(plan,k)['container'] for k in ('ra','voting')]),
        (['volume','ls','--format','{{.Name}}'],'volume',[database_spec(plan,k)['volume'] for k in ('ra','voting')]),
        (['network','ls','--format','{{.Name}}'],'network',[plan['network']])):
        existing = set(docker(*command).splitlines())
        require(not existing.intersection(expected), 'OWNERSHIP')
    fd = os.open(directory/'containers.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as journal:
        def record(kind, name, identifier):
            journal.write(json.dumps(dict(kind=kind,name=name,id=identifier,profile=plan['identifiers']['profile']))+'\n')
            journal.flush(); os.fsync(journal.fileno())
        docker('pull',plan['postgres_image'],timeout=180)
        identifier = docker('network','create','--internal','--driver','bridge',
            '--label','secure-evoting-local-demo='+plan['identifiers']['profile'],'--label','secure-evoting-purpose=synthetic-only',plan['network'])
        record('network',plan['network'],identifier)
        ids = {}
        for kind in ('ra','voting'):
            verify_vm(plan,approval)
            spec = database_spec(plan,kind)
            label_args = [item for key,value in labels(plan,kind).items() for item in ('--label',key+'='+value)]
            docker('volume','create',*label_args,spec['volume']); record('volume',spec['volume'],spec['volume'])
            ids[kind] = docker('run','--detach','--name',spec['container'],*label_args,'--network',plan['network'],
                '--publish','127.0.0.1:'+str(spec['port'])+':5432','--mount','type=volume,src='+spec['volume']+',dst=/var/lib/postgresql',
                '--tmpfs','/run/evote-secrets:rw,noexec,nosuid,nodev,mode=0755',
                '--env','POSTGRES_PASSWORD_FILE=/run/evote-secrets/bootstrap-password',
                '--env','POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer',
                '--entrypoint','/bin/sh',plan['postgres_image'],*PG_COMMAND)
            record('container',spec['container'],ids[kind])
            inject(ids[kind],bootstrap_passwords[kind])
        owned = OwnedContainers(plan,approval,ids)
        for kind in ('ra','voting'): owned.verify(kind)
        return ids


def inject(identifier, password):
    from pydantic import SecretStr
    require(isinstance(password,SecretStr) and len(password.get_secret_value()) >= 48, 'CONFIG')
    docker('exec','--interactive',identifier,'/bin/sh','-ec',
        'umask 077; cat > /run/evote-secrets/bootstrap-password.tmp; chown postgres:postgres /run/evote-secrets/bootstrap-password.tmp; mv /run/evote-secrets/bootstrap-password.tmp /run/evote-secrets/bootstrap-password',
        secret=password.get_secret_value().encode())


def transition(owned, action, bootstrap_passwords, *, confirmation):
    require(action in {'start','stop'} and confirmation == action.upper()+' OWNED DEMO CONTAINERS '+fingerprint(owned.plan), 'APPROVAL_REQUIRED')
    verify_vm(owned.plan,owned.approval); require(os.geteuid() == 0, 'OWNERSHIP')
    for kind in (('ra','voting') if action == 'start' else ('voting','ra')):
        owned.verify_container(kind,running=action == 'stop')
        if action == 'start':
            docker('start',owned.ids[kind]); inject(owned.ids[kind],bootstrap_passwords[kind]); owned.verify(kind)
        else:
            docker('stop','--time','30',owned.ids[kind]); owned.verify_container(kind,running=False)
    # No rm/prune/down -v, network removal, volume removal or key deletion API.
