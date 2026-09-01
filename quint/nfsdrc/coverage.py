# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""NFSDRC MBT corpus coverage gate.

Scans the generated ITF traces and asserts the corpus actually exercises the
behaviour buckets the model exists to cover.  A duplicate-request cache is
easy to test vacuously: a corpus in which no request is ever repeated replays
green against a server with no cache at all, and against one whose cache is
badly broken.  This gate turns that into a failure.

What it requires, and why:

  * both PROTOCOLS, and a REPLAY on each.  Without a replay there is no cache
    under test; without both protocols only one of the two scopes is.
  * every CACHEABLE OPERATION, replayed.  Each of them is here because
    re-executing it produces a different answer, and that difference is the
    only evidence a cache did its job.  One that is never replayed is one whose
    cacheability is untested.
  * a MISS of each kind the key can produce: a different XID, a different
    procedure over identical arguments, a different credential, and (for the
    connection-scoped cache) a different connection.  These are the four ways a
    key can be wrong, and each of them silently drops a mutation.
  * a RECONNECT with a replay on each side of it: the NFSv3 cache must survive
    one and the NFSv4.0 cache must not, and a corpus that only reconnects when
    nothing is cached demonstrates neither.
  * an ERROR REPLY replayed.  A cache that only stores successes answers a
    retransmitted failure by re-executing it, which is the same bug pointed the
    other way.
  * the NFSv4.0 cache at its BOUND: enough distinct entries on one connection
    to evict the oldest.

Coverage is required over the corpus as a whole.  The buckets that need a
particular profile (the eviction bound needs a long single-connection run) are
listed as such rather than demanded of every trace.
"""

import glob
import json
import os
import sys

# The NFSv3 procedures whose replies the cache must hold.  A replay of each is
# required: these are exactly the operations whose second execution answers
# differently, so an unreplayed one is an untested one.
CACHEABLE_PROCS = {
    2: "SETATTR",
    8: "CREATE",
    9: "MKDIR",
    10: "SYMLINK",
    12: "REMOVE",
    13: "RMDIR",
    14: "RENAME",
    15: "LINK",
}

# Slots in one NFSv4.0 connection's cache; the bound the corpus must reach.
V40_SLOTS = 16


def big(v):
    """Decode an ITF integer, which may be a bigint wrapper."""
    if isinstance(v, dict) and "#bigint" in v:
        return int(v["#bigint"])
    return v


def var(state, name):
    """Look up a state variable whose key is module-qualified."""
    for k, v in state.items():
        if k.split("::")[-1] == name:
            return v
    return None


def digest(act):
    """The request body as a cache checksums it.

    Not the model's action: NFSv3 REMOVE and RMDIR are the same bytes and
    differ only in the procedure number, so `asDir` -- which is how the model
    spells the procedure -- is not part of what a digest can see.  Comparing
    actions instead of digests would make that pair look like two different
    requests and hide the one case where the procedure has to be in the key.
    """
    a = json.loads(json.dumps(act))
    if a.get("tag") == "ARemove":
        a["value"].pop("asDir", None)
    return json.dumps(a, sort_keys=True)


def seq(v):
    if isinstance(v, list):
        return v
    if isinstance(v, dict):
        for k in ("#set", "#list"):
            if k in v:
                return v[k]
    return []


def scan(path, buckets):
    with open(path) as fh:
        trace = json.load(fh)

    # A request is remembered by everything its key is made of, so that a later
    # request differing in exactly one of them can be recognised as the miss it
    # is meant to demonstrate.
    seen = []
    reconnected = set()
    replayed_before_reconnect = set()

    for state in trace["states"]:
        op = var(state, "lastOp")
        if not op:
            continue
        tag = op["tag"]
        val = op.get("value", {})
        buckets.add("op:" + tag)

        if tag == "OReconnect":
            reconnected.add(big(val["conn"]))
            continue
        if tag not in ("OV3", "OV4"):
            continue

        proto = "v3" if tag == "OV3" else "v4"
        conn = big(val["conn"])
        xid = big(val["xid"])
        cred = big(val["cred"])
        proc = big(val.get("proc", 1))
        act = digest(val["act"])
        served = val["served"]["tag"]
        st = big(val["st"])

        key = (proto, conn, xid, cred, proc, act)

        if served == "SReplayed":
            buckets.add("replay:" + proto)
            if proto == "v3" and proc in CACHEABLE_PROCS:
                buckets.add("replay-proc:" + CACHEABLE_PROCS[proc])
            if st != 0:
                buckets.add("replay:error-reply")
            if conn in reconnected:
                buckets.add("replay:after-reconnect-" + proto)
            else:
                replayed_before_reconnect.add((proto, conn))
        else:
            # Classify the miss by what differs from something already sent.
            for k in seen:
                if k[0] != proto or k[5] != act:
                    continue
                if k[1] == conn and k[3] == cred and k[4] == proc \
                        and k[2] != xid:
                    buckets.add("miss:other-xid-" + proto)
                if k[1] == conn and k[2] == xid and k[3] == cred \
                        and k[4] != proc:
                    buckets.add("miss:other-proc")
                if k[1] == conn and k[2] == xid and k[4] == proc \
                        and k[3] != cred:
                    buckets.add("miss:other-cred-" + proto)
                if k[2] == xid and k[3] == cred and k[4] == proc \
                        and k[1] != conn:
                    buckets.add("miss:other-conn-" + proto)
            if st != 0:
                buckets.add("execute:error-reply")

        seen.append(key)

        # The NFSv4.0 cache is bounded per connection; the bound is reached when
        # one connection has been offered more distinct cacheable requests than
        # it has slots since it was last opened.
        if proto == "v4":
            distinct = {k for k in seen if k[0] == "v4" and k[1] == conn}
            if len(distinct) > V40_SLOTS:
                buckets.add("v40:past-the-bound")

    for proto, conn in replayed_before_reconnect:
        if conn in reconnected:
            buckets.add("replay:before-reconnect-" + proto)


def required():
    req = ["op:OV3", "op:OV4", "op:OReconnect", "op:ONull"]
    req += ["replay:v3", "replay:v4"]
    req += ["replay-proc:" + n for n in CACHEABLE_PROCS.values()]
    req += ["replay:error-reply", "execute:error-reply"]
    req += ["miss:other-xid-v3", "miss:other-xid-v4",
            "miss:other-proc",
            "miss:other-cred-v3", "miss:other-cred-v4",
            "miss:other-conn-v4"]
    req += ["replay:before-reconnect-v3", "replay:after-reconnect-v3"]
    req += ["v40:past-the-bound"]
    return req


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: coverage.py <trace-dir>\n")
        return 2
    traces = sorted(glob.glob(os.path.join(sys.argv[1], "*.itf.json")))
    if not traces:
        sys.stderr.write("coverage gate: no traces under %s\n" % sys.argv[1])
        return 2

    buckets = set()
    for t in traces:
        scan(t, buckets)

    req = required()
    missing = [b for b in req if b not in buckets]
    print("NFSDRC MBT coverage over %d trace(s):" % len(traces))
    for b in req:
        print("  %-34s %s" % (b, "HIT" if b in buckets else "MISSING"))
    extra = sorted(b for b in buckets if b not in req)
    if extra:
        print("  (also observed: %s)" % ", ".join(extra))
    if missing:
        sys.stderr.write("coverage gate: %d bucket(s) never exercised: %s\n"
                         % (len(missing), ", ".join(missing)))
        return 1
    print("  all %d coverage buckets exercised" % len(req))
    return 0


if __name__ == "__main__":
    sys.exit(main())
