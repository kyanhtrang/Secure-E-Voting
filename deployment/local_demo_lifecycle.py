"""Pure startup/stop ledger for review. It never launches, signals or deletes.

An approved Linux adapter must collect fresh boot ID and /proc start ticks before
acting on a stop intent. A PID alone is insufficient. Database instances/volumes
are deliberately not services in this ledger and never enter a rollback plan.
"""
from dataclasses import dataclass
from deployment.local_demo_policy import SERVICES, require, uuid4_string

CORE = ('voting','admin','tally','publisher','board','web_admin')
VOTING = ('ra_a','ra_b','web_a','web_b')


@dataclass(frozen=True)
class ProcessRef:
    profile: str
    service: str
    boot_id: str
    pid: int
    start_ticks: int
    uid: int


class StartupLedger:
    def __init__(self, profile):
        self.profile = uuid4_string(profile)
        self.started = []
        self.ready = set()
        self.closed = False
        self.election_bound = False
        self.boot_id = None

    def record_started(self, ref):
        require(not self.closed and isinstance(ref,ProcessRef) and ref.profile == self.profile
            and ref.service in SERVICES and ref.service not in {p.service for p in self.started},'LIFECYCLE')
        uuid4_string(ref.boot_id)
        require(self.boot_id in (None,ref.boot_id) and type(ref.uid) is int and ref.uid > 0,'OWNERSHIP')
        require(type(ref.pid) is int and ref.pid > 1 and type(ref.start_ticks) is int and ref.start_ticks > 0,'OWNERSHIP')
        require(not any(p.pid == ref.pid for p in self.started),'OWNERSHIP')
        order = CORE+VOTING
        index = len(self.started)
        require(index < len(order) and ref.service == order[index] and {p.service for p in self.started} == self.ready,'LIFECYCLE')
        require(ref.service not in VOTING or self.election_bound,'LIFECYCLE')
        self.started.append(ref)
        self.boot_id = ref.boot_id

    def mark_ready(self, ref):
        require(not self.closed and self.started and self.started[-1] == ref,'LIFECYCLE')
        self.ready.add(ref.service)

    def bind_verified_election(self):
        # A future collector must verify the signed manifest/eligibility/key
        # policy before this transition. No election or permission is invented.
        require(not self.closed and self.ready == set(CORE),'LIFECYCLE')
        self.election_bound = True

    def stop_plan(self, observations):
        """Fail closed on changed/reused PIDs; collect safe intents for the rest."""
        self.closed = True
        safe,refused = [],[]
        for ref in reversed(self.started):
            if observations.get(ref.service) == ref: safe.append(ref)
            else: refused.append(ref.service)
        return tuple(safe),tuple(refused)
