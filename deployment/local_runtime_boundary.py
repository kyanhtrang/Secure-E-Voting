"""Live guest/container evidence and pinned SSH command construction.

An approval is a human-reviewed public contract, not an attestation. The VM's
hypervisor/Windows share and forwarding configuration still requires independent
host inspection. Guest checks do not pretend to prove an uncompromised host.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from deployment.local_demo_policy import (
    ReviewRefused, database_spec, fingerprint, labels, require, safe_environment,
    validate_container, validate_network, validate_plan, validate_volume,
)

WAIT = 'while [ ! -s /run/evote-secrets/bootstrap-password ]; do sleep 0.05; done; exec /usr/local/bin/docker-entrypoint.sh "$@"'
PG_COMMAND = ['-ec',WAIT,'guarded-local','postgres','-c','password_encryption=scram-sha-256',
    '-c','log_statement=none','-c','log_min_error_statement=panic','-c','log_parameter_max_length=0',
    '-c','log_parameter_max_length_on_error=0','-c','max_connections=80']
DOCKER_PREFIX = ['/usr/bin/docker','--config','/run/evote-no-docker-credentials','--host','unix:///var/run/docker.sock']


@dataclass(frozen=True)
class Approval:
    plan_digest: str
    machine_id: str
    product_uuid: str
    boot_id: str
    host_review: str

    def check(self, plan):
        validate_plan(plan)
        require(self.plan_digest == fingerprint(plan) and self.host_review ==
            'APPROVED dedicated VM; no shares; no host DB forwarding; dedicated pinned SSH', 'APPROVAL_REQUIRED')
        require(re.fullmatch('[0-9a-f]{32}', self.machine_id) is not None, 'IDENTITY')
        for value in (self.product_uuid,self.boot_id):
            require(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value) is not None, 'IDENTITY')


def command(argv, *, timeout=10):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','HOME':'/nonexistent'}, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 2_000_000, 'OWNERSHIP')
    return result.stdout


def verify_vm(plan, approval):
    approval.check(plan); safe_environment()
    require(sys.platform == 'linux' and hasattr(os,'pidfd_open'), 'ENVIRONMENT')
    release = dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID','').strip('"') == 'ubuntu' and release.get('VERSION_ID','').strip('"') == '24.04', 'ENVIRONMENT')
    require(Path('/etc/machine-id').read_text().strip() == approval.machine_id
        and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == approval.product_uuid
        and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == approval.boot_id, 'IDENTITY')
    require(command(['/usr/bin/systemd-detect-virt','--vm']).strip() in {b'kvm',b'microsoft',b'oracle',b'vmware'}, 'ENVIRONMENT')
    # Reject observed host shares and namespaces that would invalidate inspection.
    mounts = Path('/proc/self/mountinfo').read_text().splitlines()
    forbidden = {'9p','virtiofs','vboxsf','fuse.vmhgfs-fuse','cifs','nfs','nfs4'}
    filesystems = [line.split(' - ',1)[1].split()[0] for line in mounts]
    require(not any(fs in forbidden or fs.startswith('fuse.') for fs in filesystems), 'OWNERSHIP')
    require(os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'), 'OWNERSHIP')
    # Only SSH may listen on a non-loopback interface. Unknown forwards/listeners
    # fail closed, rather than inferring safety from proposed JSON booleans.
    allowed = {22,55432,55433,5173,5174,5175,8000,8001,8002,8003,8005,8006,8007}
    for name in ('tcp','tcp6'):
        for line in Path('/proc/net/'+name).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] != '0A': continue
            address, port = fields[1].split(':'); port = int(port,16)
            require(port in allowed, 'OWNERSHIP')
            require(port == 22 or address in {'0100007F','00000000000000000000000001000000'}, 'OWNERSHIP')


class OwnedContainers:
    """Controller only: raw Docker evidence, no caller-supplied projections.

    IDs are recorded at *creation* in the separately approved setup phase. A
    container with merely the right name/label is insufficient on restart.
    """
    def __init__(self, plan, approval, created_ids):
        approval.check(plan)
        require(set(created_ids) == {'ra','voting'}, 'OWNERSHIP')
        self.plan, self.approval, self.ids = plan, approval, dict(created_ids)
        for value in self.ids.values(): require(re.fullmatch('[0-9a-f]{64}',value) is not None, 'OWNERSHIP')

    def inspect(self, *args):
        require(not Path('/run/evote-no-docker-credentials').exists(), 'ENVIRONMENT')
        raw = command(DOCKER_PREFIX+['inspect',*args])
        value = json.loads(raw)
        require(type(value) is list and len(value) == 1 and type(value[0]) is dict, 'OWNERSHIP')
        return value[0]

    def verify_container(self, kind, *, running=True):
        """Also used explicitly by hosted tests; does NOT assert VM validation."""
        spec = database_spec(self.plan,kind)
        actual = self.inspect(self.ids[kind])
        require(actual['State']['Running'] is running and not actual['HostConfig'].get('Binds')
            and not actual['HostConfig'].get('CapAdd') and not actual['HostConfig'].get('Devices'), 'OWNERSHIP')
        require(actual['Config']['Entrypoint'] == ['/bin/sh'] and actual['Config']['Cmd'] == PG_COMMAND, 'OWNERSHIP')
        image = self.inspect('--type=image',self.plan['postgres_image'])
        require(actual['Image'] == image['Id'], 'OWNERSHIP')
        expected_labels = dict(image['Config'].get('Labels') or {})
        expected_labels.update(labels(self.plan,kind))
        require(actual['Config']['Labels'] == expected_labels, 'OWNERSHIP')
        defaults = dict(item.split('=',1) for item in image['Config']['Env'])
        env = actual['Config']['Env']
        require(len(env) == len({item.split('=',1)[0] for item in env}), 'OWNERSHIP')
        overrides = [item for item in env if defaults.get(item.split('=',1)[0]) != item.split('=',1)[1]]
        require(all(any(item == key+'='+value for item in env) or any(item.startswith(key+'=') for item in overrides)
            for key,value in defaults.items()), 'OWNERSHIP')
        expected_env = ['POSTGRES_PASSWORD_FILE=/run/evote-secrets/bootstrap-password',
            'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer']
        require(len(overrides) == len(expected_env) and set(overrides) == set(expected_env), 'OWNERSHIP')
        # Do not drop unknown mounts. Only tmpfs secret staging is additional to
        # the Phase11A persistent-volume projection; it cannot contain host data.
        mounts = actual['Mounts']
        require(len(mounts) == 2 and len(actual['HostConfig'].get('Tmpfs',{})) == 1
            and set(actual['HostConfig']['Tmpfs']) == {'/run/evote-secrets'}, 'OWNERSHIP')
        require(set(actual['HostConfig']['Tmpfs']['/run/evote-secrets'].split(',')) ==
            {'rw','noexec','nosuid','nodev','mode=0755'}, 'OWNERSHIP')
        secret = [m for m in mounts if m['Destination'] == '/run/evote-secrets']
        require(len(secret) == 1 and secret[0]['Type'] == 'tmpfs' and secret[0]['RW'] is True, 'OWNERSHIP')
        data = [{k:m[k] for k in ('Type','Name','Destination','RW')} for m in mounts if m['Destination'] != '/run/evote-secrets']
        observed = dict(actual,Config=dict(actual['Config'],Env=expected_env,Labels=labels(self.plan,kind)),Mounts=data)
        if not running:
            # A stopped container has no live port mapping. Check that fact,
            # then validate its *configured* mapping with the same base policy.
            require(actual['NetworkSettings']['Ports'] in ({},{'5432/tcp':None}), 'OWNERSHIP')
            observed['NetworkSettings'] = dict(actual['NetworkSettings'],Ports=actual['HostConfig']['PortBindings'])
        validate_container(self.plan,kind,self.ids[kind],observed)
        validate_volume(self.plan,kind,self.inspect('--type=volume',spec['volume']))
        network = self.inspect('--type=network',self.plan['network'])
        validate_network(self.plan,{k:network[k] for k in ('Name','Driver','Internal','Labels')})
        require(set(actual['NetworkSettings']['Networks']) == {self.plan['network']}, 'OWNERSHIP')
        return hashlib.sha256((self.ids[kind]+spec['marker']).encode()).hexdigest()

    def verify(self, kind):
        verify_vm(self.plan,self.approval)
        return self.verify_container(kind)


def ssh_arguments(executable, host, user, identity_file, known_hosts_file):
    """Windows-side argv only. Does not read a private key or start SSH.

    Independently inspect/pin known_hosts before invoking this command. There is
    deliberately no password, arbitrary forward, SSH config or personal agent.
    """
    require(re.fullmatch('[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?',host) is not None
        and re.fullmatch('[a-z][a-z0-9_-]{0,31}',user) is not None, 'CONFIG')
    for path in (executable,identity_file,known_hosts_file):
        require(Path(path).is_absolute(), 'CONFIG')
    return [str(executable),'-F','none','-N','-T','-i',str(identity_file),
        '-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','ForwardAgent=no',
        '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known_hosts_file),
        '-o','GlobalKnownHostsFile=none','-o','ExitOnForwardFailure=yes','-o','ClearAllForwardings=no',
        '-o','PermitLocalCommand=no','-o','ProxyCommand=none','-o','ProxyJump=none',
        '-L','127.0.0.1:5173:127.0.0.1:5173','-L','127.0.0.1:5174:127.0.0.1:5174',
        '-L','127.0.0.1:5175:127.0.0.1:5175',user+'@'+host]
