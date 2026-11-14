"""Explicit browser-test fixture: real RA routes/verifier, in-memory DB double.

No credential files, real database connections or election fixtures. This is
never used by the application launcher or presented as a working election API.
"""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-auth-only', action='store_true', required=True)
    parser.parse_args()
    import uvicorn
    from backend.ra.demo_launcher import create_demo_app
    from tests.demo_auth_helpers import DemoDatabaseDouble, demo_environment

    database = DemoDatabaseDouble()
    app = create_demo_app(demo_environment(), connection_factory=database.factory)
    uvicorn.run(app, host='127.0.0.1', port=8001, proxy_headers=False,
                forwarded_allow_ips='', access_log=False, log_level='warning')


if __name__ == '__main__':
    main()
