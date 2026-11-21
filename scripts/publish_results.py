"""Interactive local operator action. Passwords/tokens never enter argv or output."""
import argparse
import getpass
import logging
from pathlib import Path
import sys
from urllib.parse import urlsplit
import warnings

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import httpx
from backend.crypto.credential_protocol import uuid_string


def origin(value):
    parsed=urlsplit(value)
    if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or not 1<=(parsed.port or 80)<=65535:
        raise ValueError('Loopback origin required')
    return value


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enable-local-demo',action='store_true',required=True)
    parser.add_argument('--election-id',required=True)
    parser.add_argument('--admin-origin',default='http://127.0.0.1:8002')
    parser.add_argument('--publication-origin',default='http://127.0.0.1:8007')
    args=parser.parse_args(argv)
    try:
        if not sys.stdin.isatty():raise ValueError()
        uuid_string(args.election_id);admin=origin(args.admin_origin);publisher=origin(args.publication_origin)
        if admin==publisher:raise ValueError()
        logging.disable(logging.CRITICAL)
        with warnings.catch_warnings():
            warnings.simplefilter('error',getpass.GetPassWarning)
            username=getpass.getpass('Admin username: ');password=getpass.getpass('Admin password: ')
        with httpx.Client(trust_env=False,follow_redirects=False,timeout=45) as http:
            login=http.post(admin+'/api/v1/admin/auth/login',json={'username':username,'password':password})
            del password
            if login.status_code!=200:raise ValueError()
            token=login.json()['access_token']
            revoked=False
            try:
                if input('Type PUBLISH to authorize irreversible publication: ')!='PUBLISH':raise ValueError()
                result=http.post(publisher+'/api/v1/publication/elections/'+args.election_id+'/publish',json={},headers={'Authorization':'Bearer '+token})
                if result.status_code!=200 or result.json().get('status')!='PUBLISHED':raise ValueError()
            finally:
                try:revoked=http.post(admin+'/api/v1/admin/auth/logout',json={},headers={'Authorization':'Bearer '+token}).status_code==204
                except httpx.HTTPError:pass
                del token
            print('PUBLISHED: committed signed evidence. Verify independently using trusted public keys.')
            if not revoked:print('Admin session revocation was not confirmed; the existing DB session TTL still applies.',file=sys.stderr)
    except Exception:parser.exit(2,'Publication unavailable; inspect authoritative status before retrying.\n')


if __name__=='__main__':main()
