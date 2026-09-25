import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent


def make_query(domain, qtype=1, txid=0x1234):
    h = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    q = b""
    for part in domain.split("."):
        b = part.encode()
        q += struct.pack("!B", len(b)) + b
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    return h + q


def check(name, cond):
    print(("PASS" if cond else "FAIL") + " " + name)
    return cond


def main():
    ok = True
    q = make_query("contoh-blocked.test", 1, 0x1234)
    r = agent.build_blocked_response(q, "A")
    ok &= check("A-txid", r[0:2] == b"\x12\x34")
    ok &= check("A-ancount", struct.unpack("!H", r[6:8])[0] == 1)
    ok &= check("A-rdata", r[-4:] == b"\x00\x00\x00\x00")
    q6 = make_query("contoh-blocked.test", 28, 0x4321)
    r6 = agent.build_blocked_response(q6, "AAAA")
    ok &= check("AAAAA-txid", r6[0:2] == b"\x43\x21")
    ok &= check("AAAAA-ancount", struct.unpack("!H", r6[6:8])[0] == 1)
    ok &= check("AAAA-rdata", r6[-16:] == b"\x00" * 16)
    old_base = agent.BASE_DIR
    try:
        with tempfile.TemporaryDirectory() as td:
            agent.BASE_DIR = td
            cfg = {"blocklist": os.path.join(td, "blocklist.txt")}
            agent.save_blocklist(cfg, set(["contoh-blocked.test"]))
            got = agent.load_blocklist(cfg)
            ok &= check("save-load", got == set(["contoh-blocked.test"]))
            agent.save_blocklist(cfg, set())
            got2 = agent.load_blocklist(cfg)
            ok &= check("remove", got2 == set())
            mj = os.path.join(td, "blocklist.json")
            ok &= check("json-mirror", os.path.exists(mj))
    finally:
        agent.BASE_DIR = old_base
    snap = agent.egress_snapshot()
    ok &= check("egress-list", isinstance(snap, list))
    print("ALL-PASS" if ok else "SOME-FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
