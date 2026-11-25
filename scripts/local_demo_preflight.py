"""Public-only, OFFLINE deployment preparation; no start/migrate/stop/delete CLI."""
import argparse
import json
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from deployment.local_demo_policy import ReviewRefused, safe_environment, new_plan, validate_plan, fingerprint

PUBLIC_PLAN_NAME = 'evote-local-demo-plan.json'


class PublicArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default diagnostics echo rejected arguments, which could
        # contain an accidentally supplied secret or connection string.
        raise ReviewRefused()


def load_public_plan(path):
    path = Path(path)
    if path.name != PUBLIC_PLAN_NAME: raise ReviewRefused()
    for part in (path,*path.parents):
        value = part.lstat()
        if part.is_symlink() or getattr(value,'st_file_attributes',0) & getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0): raise ReviewRefused()
    with path.open('rb') as stream: raw = stream.read(32769)
    if len(raw) > 32768: raise ReviewRefused()
    def unique(pairs):
        value = {}
        for key,item in pairs:
            if key in value: raise ReviewRefused()
            value[key] = item
        return value
    return validate_plan(json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique))


def main(argv=None):
    parser = PublicArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('new','check'))
    parser.add_argument('--public-plan',type=Path)
    try:
        args = parser.parse_args(argv)
        safe_environment()
        if args.action == 'new':
            if args.public_plan is not None: raise ReviewRefused()
            print(json.dumps(new_plan(),sort_keys=True,indent=2)); return 0
        if args.public_plan is None: raise ReviewRefused()
        plan = load_public_plan(args.public_plan)
        print(json.dumps(dict(status='OFFLINE_VALIDATED_NOT_DEPLOYED',execution_ready=False,plan_digest=fingerprint(plan),
            pending=['separate-human-deployment-approval','reviewed-local-runtime-adapter','local-two-voter-installer',
                'live-ownership-acl-and-lifecycle-validation']),sort_keys=True))
        return 0
    except Exception as error:
        code = error.code if isinstance(error,ReviewRefused) else 'CONFIG'
        print(json.dumps(dict(status='REFUSED',code=code,execution_ready=False),sort_keys=True)); return 2


if __name__ == '__main__':raise SystemExit(main())
