import os
import sys
import json
from datetime import datetime, timezone
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent import egress_snapshot, BASE_DIR
LOGD = os.path.join(BASE_DIR, 'logs')
NETL = os.path.join(LOGD, 'nettrack.log')
def is_priv(ip):
    s = (ip or '').strip()
    if s.startswith('127.') or s == 'localhost':
        return True
    if s.startswith('10.'):
        return True
    if s.startswith('192.168.'):
        return True
    if s.startswith('172.'):
        try:
            n = int(s.split('.')[1])
            if 16 <= n <= 31:
                return True
        except Exception:
            pass
    return False
def split_hostport(s):
    s = (s or '').strip()
    if ':' in s:
        h, p = s.rsplit(':', 1)
        try:
            return h.strip('[] '), int(p)
        except Exception:
            return h, 0
    return s, 0
def infer_dir(local, remote):
    lh, _ = split_hostport(local)
    rh, _ = split_hostport(remote)
    lp = is_priv(lh)
    rp = is_priv(rh)
    if lp and not rp:
        return 'out'
    if rp and not lp:
        return 'in'
    return 'local'
def snapshot_once():
    rows = egress_snapshot()
    out = []
    for c in rows:
        e = dict(c)
        e['direction'] = infer_dir(c.get('local',''), c.get('remote',''))
        out.append(e)
    ts = datetime.now(timezone.utc).isoformat()
    try:
        os.makedirs(LOGD, exist_ok=True)
        fh = open(NETL, 'a', encoding='utf-8', newline=chr(10))
        fh.write(json.dumps({'ts': ts, 'count': len(out), 'conns': out[:200]}) + chr(10))
        fh.close()
    except Exception:
        pass
    return len(out), 0
def main():
    t, s = snapshot_once()
    print('NETTRACK total=' + str(t) + ' suspicious=' + str(s))
if __name__ == '__main__':
    main()

SEENF = os.path.join(LOGD, 'seen_ips.json')
SUSP_PORTS = set([22, 4444, 5555, 6666, 6667, 1337, 31337, 8081, 8444])
def load_seen():
    try:
        fh = open(SEENF, 'r', encoding='utf-8')
        d = json.load(fh)
        fh.close()
        if isinstance(d, dict):
            return d
        if isinstance(d, list):
            return {k: '' for k in d}
    except Exception:
        pass
    return {}
def save_seen(d):
    try:
        os.makedirs(LOGD, exist_ok=True)
        fh = open(SEENF, 'w', encoding='utf-8', newline=chr(10))
        fh.write(json.dumps(d) + chr(10))
        fh.close()
    except Exception:
        pass
def score_conn(e, seen):
    rh, rp = split_hostport(e.get('remote',''))
    if e.get('direction','') != 'out':
        return 0
    if rp in SUSP_PORTS:
        return 1
    if rh and rh not in seen and not is_priv(rh):
        return 1
    return 0
def snapshot_once():
    rows = egress_snapshot()
    seen = load_seen()
    out = []
    susp = 0
    now = datetime.now(timezone.utc).isoformat()
    for c in rows:
        e = dict(c)
        e['direction'] = infer_dir(c.get('local',''), c.get('remote',''))
        s = score_conn(e, seen)
        e['suspicious'] = s
        susp += s
        rh, _ = split_hostport(c.get('remote',''))
        if rh and rh not in seen:
            seen[rh] = now
        out.append(e)
    save_seen(seen)
    ts = datetime.now(timezone.utc).isoformat()
    try:
        os.makedirs(LOGD, exist_ok=True)
        fh = open(NETL, 'a', encoding='utf-8', newline=chr(10))
        fh.write(json.dumps({'ts': ts, 'count': len(out), 'suspicious': susp, 'conns': out[:200]}) + chr(10))
        fh.close()
    except Exception:
        pass
    return len(out), susp
