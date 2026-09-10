import sys, json

path = sys.argv[1] if len(sys.argv) > 1 else None
if path:
    with open(path, encoding='utf-8-sig') as f:
        data = json.load(f)
else:
    data = json.load(sys.stdin)
for r in data['workflow_runs']:
    rid = r['id']
    sha = r['head_sha'][:7]
    status = r.get('conclusion') or r['status']
    title = r['display_title'][:60]
    print(f"{rid} {sha} {status:10s} {title}")

