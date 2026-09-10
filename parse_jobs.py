import json, os, sys

path = os.environ.get('JSONFILE', sys.argv[1] if len(sys.argv) > 1 else None)
with open(path, encoding='utf-8-sig') as f:
    d = json.load(f)
for j in d['jobs']:
    name = j['name']
    status = j['status']
    concl = j.get('conclusion') or ''
    print(f"{name:32s} {status:11s} {concl:10s}")
