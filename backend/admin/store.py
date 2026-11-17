"""Restricted function adapters. Each RPC commits before returning a result."""
from contextlib import contextmanager
from psycopg.types.json import Jsonb


class AdminError(Exception):
    def __init__(self, status=503):
        self.status=status
        super().__init__("Administrative operation unavailable")


def translate(error):
    if isinstance(error,AdminError):return error
    return AdminError({"P4301":401,"P4302":403,"P4303":409,"P4304":404,
        "22023":422,"23505":409,"23514":422,"22007":422}.get(getattr(error,"sqlstate",None),503))


class VotingAdminStore:
    QUERIES={
        "login":"SELECT voting_admin.login_session(%s::uuid,%s::bytea)",
        "session":"SELECT voting_admin.session(%s::bytea)",
        "logout":"SELECT voting_admin.logout(%s::bytea)",
        "read":"SELECT voting_admin.read_elections(%s::bytea,%s::uuid)",
        "audit":"SELECT voting_admin.audit(%s::bytea,%s::uuid)",
        "operation":"SELECT voting_admin.operation(%s::bytea,%s::uuid,%s::boolean)",
        "mutate":"SELECT voting_admin.mutate(%s::bytea,%s::uuid,%s::text,%s::jsonb)",
    }
    def __init__(self,connect):self.connect=connect
    def _call(self,conn,name,*args):
        try:
            row=conn.execute(self.QUERIES[name],args).fetchone()
            if row is None or len(row)!=1:raise AdminError()
            result=row[0];conn.commit();return result
        except Exception as error:
            conn.rollback();raise translate(error) from None
    def call(self,name,*args):
        try:
            with self.connect() as conn:return self._call(conn,name,*args)
        except Exception as error:raise translate(error) from None
    @contextmanager
    def operation(self,digest,election):
        try:
            with self.connect() as conn:
                if self._call(conn,"operation",digest,election,False) is not True:raise AdminError(409)
                # Session advisory lock survives each explicit RPC commit. Closing
                # this dedicated connection always releases it, even after expiry.
                yield AdminOperation(self,conn,digest,election)
        except Exception as error:raise translate(error) from None


class AdminOperation:
    def __init__(self,store,conn,digest,election):self.store,self.conn,self.digest,self.election=store,conn,digest,election
    def read(self):return self.store._call(self.conn,"read",self.digest,self.election)[0]
    def mutate(self,command,data):return self.store._call(self.conn,"mutate",self.digest,self.election,command,Jsonb(data))


class RAPublisherStore:
    def __init__(self,connect):self.connect=connect
    def _call(self,query,args):
        try:
            with self.connect() as conn:
                row=conn.execute(query,args).fetchone()
                if row is None or len(row)!=1:raise AdminError()
                return row[0] # Connection context commits before returning.
        except Exception as error:raise translate(error) from None
    def prepare(self,election,raw,sig,spki,reference,actor):
        return self._call("SELECT ra_admin.prepare(%s::uuid,%s::bytea,%s::bytea,%s::bytea,%s::text,%s::uuid)",
            (election,raw,sig,spki,reference,actor))
    def reconcile(self,election,digest,closed,actor):
        return self._call("SELECT ra_admin.reconcile(%s::uuid,%s::bytea,%s::boolean,%s::uuid)",(election,digest,closed,actor))
