"""Private child entrypoint for the guarded controller, never an operator launcher."""
from contextlib import ExitStack
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time

import httpx
import uvicorn

from backend.crypto.credential_protocol import strict_json
from deployment.local_demo_policy import ROOT, ROLE_DATABASE, SERVICES, require, safe_environment, validate_plan
from deployment.local_runtime_apps import create_app, key_ids, validate_package
from deployment.local_runtime_processes import BoundaryClient, verify_binary


def validate_configuration(config, service):
    extra = {'node','node_digest'} if service.startswith('web_') else (
        {'signer','signer_digest','election_bundle'} if service in {'ra_a','ra_b'} else (
            {'evidence_directory'} if service in {'tally','publisher'} else set()))
    require(type(config) is dict and set(config) == {'service','plan','package'}|extra and config['service'] == service, 'CONFIG')
    validate_plan(config['plan']); validate_package(service,config['package'])
    if service in {'tally','publisher'}:
        path = Path(config['evidence_directory'])
        require(path.is_absolute() and not path.resolve().is_relative_to(ROOT), 'OWNERSHIP')
        for parent in (path,*path.parents): require(not parent.is_symlink(), 'OWNERSHIP')
        status = path.stat()
        require(stat.S_ISDIR(status.st_mode), 'OWNERSHIP')
        if service == 'tally':
            require(status.st_uid == os.geteuid() and stat.S_IMODE(status.st_mode) == 0o700, 'OWNERSHIP')
        else:
            require(status.st_uid == 0 and status.st_gid == os.getegid() and stat.S_IMODE(status.st_mode) == 0o750
                and not os.access(path,os.W_OK), 'OWNERSHIP')


def web_environment(plan, service, public):
    require(service in {'web_admin','web_a','web_b'}, 'ASSET_BOUNDARY')
    targets = plan['web_targets'][service]
    env = dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',VITE_MANIFEST_AUTHORITY_PIN=public['manifest_signing']['pin'])
    if service == 'web_admin':
        env.update(VITE_ENABLE_ADMIN='true',VITE_ENABLE_TALLY='true',VITE_ENABLE_BOARD='true',VITE_ENABLE_PUBLICATION='true',
            ADMIN_DEMO_TARGET=targets['admin'],TALLY_DEMO_TARGET=targets['tally'],BOARD_DEMO_TARGET=targets['board'],
            PUBLICATION_DEMO_TARGET=targets['publisher'],VITE_EVIDENCE_PIN=public['evidence_signing']['pin'],
            VITE_EVIDENCE_KEY_ID=key_ids(plan)['evidence'],VITE_PUBLICATION_PIN=public['publication_signing']['pin'],
            VITE_PUBLICATION_KEY_ID=key_ids(plan)['publication'])
    else: env.update(VITE_ENABLE_VOTING='true',RA_DEMO_TARGET=targets['ra'],VOTING_DEMO_TARGET=targets['voting'])
    return env


def owns_listener(pid, port):
    """Do not accept another process's HTTP 200 as this child's readiness."""
    inodes = set()
    for path in Path('/proc',str(pid),'fd').iterdir():
        try: target = os.readlink(path)
        except FileNotFoundError: continue
        if target.startswith('socket:['): inodes.add(target[8:-1])
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        if fields[3] == '0A' and fields[1] == '0100007F:'+format(port,'04X') and fields[9] in inodes:
            return True
    return False


def web(config):
    plan,service = config['plan'],config['service']
    binary = verify_binary(config['node'],config['node_digest'])
    require(not any((ROOT/'frontend').glob('.env*')) and not any(ROOT.glob('.env*')), 'ENVIRONMENT')
    port = SERVICES[service]['port']
    process = subprocess.Popen([str(binary),str(ROOT/'frontend/node_modules/vite/bin/vite.js'),
        '--mode','local-demo','--host','127.0.0.1','--port',str(port),'--strictPort'],cwd=ROOT/'frontend',
        env=web_environment(plan,service,config['package']['public']),stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    stopping = False
    def stop(_signum,_frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM,stop)
    try:
        with httpx.Client(trust_env=False,follow_redirects=False,timeout=1) as client:
            deadline = time.monotonic()+20
            while True:
                require(process.poll() is None and not stopping and time.monotonic() < deadline, 'LIFECYCLE')
                try:
                    response = client.get('http://127.0.0.1:'+str(port)+'/')
                    if response.status_code == 200: break
                except httpx.TransportError: pass
                time.sleep(0.05)
        require(owns_listener(process.pid,port), 'OWNERSHIP')
        print('READY',flush=True)
        while not stopping and process.poll() is None: time.sleep(0.1)
        require(stopping, 'LIFECYCLE')
    finally:
        if process.poll() is None: process.terminate()
        process.wait(timeout=15)  # Owned child, never broad process group cleanup.


class ReadyServer(uvicorn.Server):
    async def startup(self, sockets=None):
        await super().startup(sockets=sockets)
        require(self.started and owns_listener(os.getpid(),self.config.port), 'LIFECYCLE')
        print('READY',flush=True)


def main():
    try:
        safe_environment()
        require(sys.platform == 'linux' and os.geteuid() > 0 and len(sys.argv) == 3, 'ENVIRONMENT')
        require(not os.access('/var/run/docker.sock',os.R_OK|os.W_OK), 'OWNERSHIP')
        service,fd = sys.argv[1],int(sys.argv[2])
        require(service in SERVICES and fd > 2, 'CONFIG')
        # The broker must be an inherited Unix stream, not a selectable endpoint.
        client = BoundaryClient(fd)
        require(client.channel.family == socket.AF_UNIX and client.channel.type == socket.SOCK_STREAM, 'OWNERSHIP')
        raw = sys.stdin.buffer.readline(131073)
        require(0 < len(raw) <= 131072 and raw.endswith(b'\n'), 'CONFIG')
        config = strict_json(raw); del raw
        validate_configuration(config,service)
        if service.startswith('web_'):
            web(config); return 0
        # Uvicorn replays a captured SIGTERM after restoring the previous handler.
        # A Python exit unwinds ExitStack, closing the owned CIRCL child; the
        # default OS termination would skip Python cleanup and orphan the signer.
        def terminate(_signum,_frame): raise SystemExit(0)
        signal.signal(signal.SIGTERM,terminate)
        with ExitStack() as resources:
            resources.callback(client.channel.close)
            app = create_app(config['plan'],service,config['package'],
                {role:client.for_kind(ROLE_DATABASE[role]) for role in SERVICES[service]['roles']},resources,
                **{name:config[name] for name in ('election_bundle','signer_binary','signer_digest','evidence_directory') if name in config},
                **({'signer_binary':config['signer']} if 'signer' in config else {}))
            del config
            server = ReadyServer(uvicorn.Config(app,host='127.0.0.1',port=SERVICES[service]['port'],
                proxy_headers=False,forwarded_allow_ips='',access_log=False,log_level='critical',server_header=False))
            server.run()
        return 0
    except SystemExit as error:
        if error.code == 0: return 0
        print('REFUSED runtime',file=sys.stderr); return 2
    except BaseException:
        print('REFUSED runtime',file=sys.stderr); return 2


if __name__ == '__main__': raise SystemExit(main())
