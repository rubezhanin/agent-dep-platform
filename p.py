import json, os, sys
path = os.environ.get('JSONFILE') or (sys.argv[1] if len(sys.argv) > 1 else None)
with open(path, encoding='utf-8-sig') as f:
    d = json.load(f)
for j in d.get('jobs', []):
    print(f"{j['name']:32s} {j['status']:11s} {str(j.get('conclusion') or ''):10s}")
