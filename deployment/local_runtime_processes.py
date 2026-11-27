"""Linux pidfd-based owned child lifecycle. No database/container deletion.

Controller runs as the separately trusted root operator; each application has a
different non-root UID with no Docker group. Private config and live ownership
requests use inherited pipes/socketpairs, not argv, environment or shared files.
"""
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import socket
import stat
import subprocess
import sys
import threading

from deployment.local_demo_lifecycle import ProcessRef, StartupLedger
from deployment.local_demo_policy import ROOT, ROLE_DATABASE, SERVICES, require
from deployment.local_runtime_boundary import verify_vm


def observe(profile, service, pid):
    status = Path('/proc',str(pid),'status').read_text()
    uid = next(line.split()[1:] for line in status.splitlines() if line.startswith('Uid:'))
    require(len(set(uid)) == 1 and int(uid[0]) > 0, 'OWNERSHIP')
    raw = Path('/proc',str(pid),'stat').read_text()
    ticks = int(raw.rsplit(')',1)[1].split()[19])
    return ProcessRef(profile,service,Path('/proc/sys/kernel/random/boot_id').read_text().strip(),pid,ticks,int(uid[0]))


def verify_binary(path, digest):
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink() and path.is_file(), 'SOURCE')
    status = path.stat()
    require(status.st_uid == 0 and not status.st_mode & 0o022 and bool(status.st_mode & 0o111)
        and hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'SOURCE')
    for parent in path.parents:
        require(not parent.is_symlink() and parent.stat().st_uid == 0 and not parent.stat().st_mode & 0o022, 'SOURCE')
    return path


def verify_repository():
    # A service UID that can edit the worker, Vite dependencies or a parent
    # directory could steal another service's next private configuration.
    for path in (ROOT,*ROOT.parents):
        require(not path.is_symlink() and path.stat().st_uid == 0 and not path.stat().st_mode & 0o022, 'SOURCE')
    for folder,names,files in os.walk(ROOT,followlinks=False):
        names[:] = [name for name in names if name != '.git']
        for name in names+files:
            path = Path(folder)/name
            status = path.lstat()
            # npm bin links may point within the root-owned checkout only.
            if path.is_symlink():
                if path.parent == ROOT/'.venv/bin' and path.name.startswith('python'):
                    verify_binary(path.resolve(),hashlib.sha256(path.resolve().read_bytes()).hexdigest())
                else: require(path.resolve().is_relative_to(ROOT), 'SOURCE')
                status = path.resolve().stat()
            require(status.st_uid == 0 and not status.st_mode & 0o022, 'SOURCE')


class Supervisor:
    def __init__(self, plan, approval, containers, accounts, registry, python, python_digest):
        verify_vm(plan,approval)
        verify_repository()
        require(os.geteuid() == 0 and set(accounts) == set(SERVICES), 'OWNERSHIP')
        require(len({uid for uid,gid in accounts.values()}) == len(SERVICES)
            and all(type(uid) is int and type(gid) is int and uid > 0 and gid > 0 for uid,gid in accounts.values()), 'OWNERSHIP')
        import pwd
        for service,(uid,gid) in accounts.items():
            entry = pwd.getpwuid(uid)
            require(entry.pw_name == 'evote_'+service and entry.pw_gid == gid
                and entry.pw_shell in {'/usr/sbin/nologin','/bin/false'}
                and entry.pw_dir in {'/nonexistent','/var/empty'}, 'OWNERSHIP')
        self.plan,self.approval,self.containers,self.accounts = plan,approval,containers,dict(accounts)
        self.python = verify_binary(python,python_digest)
        self.ledger = StartupLedger(plan['identifiers']['profile'])
        self.children = {}
        path = Path(registry)
        require(path.is_absolute() and not path.is_symlink() and path.parent.stat().st_uid == 0
            and stat.S_IMODE(path.parent.stat().st_mode) == 0o700, 'OWNERSHIP')
        # A retained registry requires explicit review on controller restart; it
        # must never be silently replaced or used to signal old/reused PIDs.
        fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        self.registry = os.fdopen(fd,'w')

    def _record(self, event, ref):
        self.registry.write(json.dumps(dict(event=event,**vars(ref)),sort_keys=True)+'\n')
        self.registry.flush(); os.fsync(self.registry.fileno())

    def _broker(self, channel, service):
        allowed = {ROLE_DATABASE[r] for r in SERVICES[service]['roles']}
        try:
            with channel.makefile('rwb',buffering=0) as stream:
                while True:
                    line = stream.readline(17)
                    if not line: return
                    require(line in {b'ra\n',b'voting\n'} and line.decode().strip() in allowed, 'ASSET_BOUNDARY')
                    self.containers.verify(line.decode().strip())
                    stream.write(b'OK\n')
        except Exception:
            # A closed/error channel fails every future runtime DB connection.
            pass
        finally: channel.close()

    def start(self, service, private_configuration):
        verify_vm(self.plan,self.approval)
        require(service in SERVICES, 'LIFECYCLE')
        require(type(private_configuration) is dict and private_configuration.get('service') == service, 'ASSET_BOUNDARY')
        for role in SERVICES[service]['roles']: self.containers.verify(ROLE_DATABASE[role])
        uid,gid = self.accounts[service]
        import grp
        require(not any(g.gr_name in {'docker','sudo','adm'} and (g.gr_gid == gid or
            __import__('pwd').getpwuid(uid).pw_name in g.gr_mem) for g in grp.getgrall()), 'OWNERSHIP')
        raw = json.dumps(private_configuration,separators=(',',':')).encode()+b'\n'
        require(len(raw) <= 131072, 'CONFIG')
        parent,child = socket.socketpair(); child.settimeout(15)
        process = None; pidfd = None; ref = None
        try:
            process = subprocess.Popen([str(self.python),'-m','deployment.local_runtime_worker',service,str(child.fileno())],
                cwd=ROOT,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONUNBUFFERED':'1'},
                user=uid,group=gid,extra_groups=[],umask=0o077,pass_fds=(child.fileno(),),
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
            child.close()
            pidfd = os.pidfd_open(process.pid)
            ref = observe(self.ledger.profile,service,process.pid)
            require(ref.uid == uid and process.poll() is None, 'OWNERSHIP')
            # Record ownership immediately, including failures BEFORE readiness.
            self.children[service] = (process,pidfd,ref)
            self._record('started',ref)
            self.ledger.record_started(ref)
            threading.Thread(target=self._broker,args=(parent,service),daemon=True).start()
            process.stdin.write(raw); process.stdin.flush(); process.stdin.close()
            response = queue.Queue(maxsize=1)
            def read_ready():
                try: response.put(process.stdout.readline(65))
                except Exception: response.put(b'')
            threading.Thread(target=read_ready,daemon=True).start()
            require(response.get(timeout=30) == b'READY\n' and process.poll() is None, 'LIFECYCLE')
            require(observe(self.ledger.profile,service,process.pid) == ref, 'OWNERSHIP')
            self.ledger.mark_ready(ref); self._record('ready',ref)
        except BaseException:
            child.close()
            if process is None: parent.close()
            elif service not in self.children:
                # No private config has been sent yet. EOF also makes the worker
                # refuse if acquiring a pidfd itself failed. Never fall back to
                # a numeric-PID kill or lose an unrecorded secret-bearing child.
                process.stdin.close(); parent.close()
                if pidfd is not None:
                    signal.pidfd_send_signal(pidfd,signal.SIGTERM)
                    process.wait(timeout=20); os.close(pidfd)
                else: process.wait(timeout=5)
            raise

    def check_ready(self):
        require(not self.ledger.closed and set(self.children) == self.ledger.ready, 'LIFECYCLE')
        for service,(process,_fd,ref) in self.children.items():
            require(process.poll() is None and observe(self.ledger.profile,service,process.pid) == ref, 'OWNERSHIP')
        for kind in ('ra','voting'): self.containers.verify(kind)

    def stop(self):
        self.ledger.closed = True
        refused = []
        for service,(process,pidfd,ref) in reversed(tuple(self.children.items())):
            try:
                if process.poll() is None:
                    require(observe(self.ledger.profile,service,process.pid) == ref, 'OWNERSHIP')
                    signal.pidfd_send_signal(pidfd,signal.SIGTERM)
                    process.wait(timeout=20)
                self._record('stopped',ref)
                os.close(pidfd)
                if process.stdout: process.stdout.close()
                del self.children[service]
            except Exception: refused.append(service)
        # No SIGKILL, kill(pid), process-group kill, container stop/rm, volume
        # removal or vault/evidence deletion. Unknown/slow resources survive.
        return tuple(refused)


class BoundaryClient:
    def __init__(self, fd):
        self.channel = socket.socket(fileno=os.dup(fd)); self.channel.settimeout(15)
        self.lock = threading.Lock()

    def for_kind(self, kind):
        require(kind in {'ra','voting'}, 'ASSET_BOUNDARY')
        def verify():
            with self.lock:
                self.channel.sendall((kind+'\n').encode())
                reply = bytearray()
                while len(reply) < 3:
                    part = self.channel.recv(3-len(reply))
                    require(bool(part), 'OWNERSHIP'); reply.extend(part)
                require(reply == b'OK\n', 'OWNERSHIP')
        return verify
