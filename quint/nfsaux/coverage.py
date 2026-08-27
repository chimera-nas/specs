# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""NFSAUX MBT corpus coverage gate.

Scans the generated ITF traces and asserts the corpus actually exercises the
behaviour buckets the model is meant to cover.  Random stepping can silently
starve a corner -- a status nothing ever produces, a procedure nothing ever
calls -- and a starved corner masquerades as covered: the replay is green
because it never tried.  This gate turns that starvation red.

What it requires, and why:

  * EVERY PROCEDURE of all four protocols is called.  These are protocols
    where the unexercised procedures are exactly the ones that rot, so the
    bar is the whole procedure set rather than a sample of it -- including
    the ones a minimal server refuses, since the refusal is under test too.
  * The interesting NLM STATUSES: not just GRANTED, but DENIED, BLOCKED and
    STALE_FH.  A corpus that only ever succeeds tests very little.
  * The MOUNT resolution OUTCOMES: a mount that works, one that no export
    matches, one whose path is missing under an export, and one that walks
    into a regular file.
  * The portmap LOOKUP outcomes: a served triple and an unserved one, over
    both the version and the transport axis.
  * The cross-protocol SEAMS: a monitored host, a notify that drops locks,
    a FREE_ALL, and a queue promotion.  These are the behaviours that only
    exist because the protocols are modeled together.

Coverage is required over the corpus as a whole rather than per flavour: the
flavours are deliberately narrow (a portmap-only trace has no locks in it),
so a per-flavour bar would be a bar on the flavour list, not on the corpus.
"""

import glob
import json
import os
import sys

# nlm4_stats the corpus must produce.
NLM_STATUSES = {
    0: "NLM4_GRANTED",
    1: "NLM4_DENIED",
    3: "NLM4_BLOCKED",
    7: "NLM4_STALE_FH",
}

# mountstat3 the corpus must produce.
MNT_STATUSES = {
    0: "MNT3_OK",
    2: "MNT3ERR_NOENT",
    20: "MNT3ERR_NOTDIR",
}

# Every operation tag the model can emit.  A tag that never appears is a
# procedure the corpus never called.
OP_TAGS = [
    "OPmNull", "OPmGetport", "OPmSet", "OPmDump", "OPmCallit",
    "ORbGetaddr", "ORbDump", "ORbGettime", "ORbGetversaddr",
    "OMntNull", "OMnt", "OMntDump", "OMntUmnt", "OMntUmntAll", "OMntExport",
    "ONlmNull", "ONlmTestOp", "ONlmLock", "ONlmCancel", "ONlmUnlock",
    "ONlmGranted", "ONlmRes", "ONlmReserved", "ONlmShare", "ONlmFreeAll",
    "OSmNull", "OSmStat", "OSmMon", "OSmUnmon", "OSmUnmonAll",
    "OSmSimuCrash", "OSmNotify",
]


def big(v):
    """Decode an ITF integer, which may be a bigint wrapper."""
    if isinstance(v, dict) and "#bigint" in v:
        return int(v["#bigint"])
    return v


def seq(v):
    """Decode an ITF sequence, which may be a set or list wrapper."""
    if isinstance(v, list):
        return v
    if isinstance(v, dict):
        for k in ("#set", "#list"):
            if k in v:
                return v[k]
    return []


def var(state, name):
    """Look up a state variable whose key is module-qualified."""
    for k, v in state.items():
        if k.split("::")[-1] == name:
            return v
    return None


def scan(path, buckets):
    with open(path) as fh:
        trace = json.load(fh)

    prev_monitors = set()
    prev_queue_len = 0
    prev_held_len = 0

    for state in trace["states"]:
        op = var(state, "lastOp")
        if not op or op.get("tag") == "OInit":
            continue
        tag = op["tag"]
        val = op.get("value", {})
        reply = val.get("reply", {})
        buckets.add("op:" + tag)

        if reply.get("tag") == "RUnavail":
            buckets.add("reply:PROC_UNAVAIL")

        # ---- NLM statuses, from whichever shape carries them -------------
        if reply.get("tag") == "RNlm":
            st = big(reply.get("value"))
            if st in NLM_STATUSES:
                buckets.add("nlm:" + NLM_STATUSES[st])
        elif reply.get("tag") == "RNlmTestRes":
            st = big(reply["value"].get("stat"))
            if st in NLM_STATUSES:
                buckets.add("nlm:" + NLM_STATUSES[st])
            if seq(reply["value"].get("holders", [])):
                buckets.add("nlm:holder-reported")
        elif reply.get("tag") == "RNlmShare":
            st = big(reply["value"].get("stat"))
            if st in NLM_STATUSES:
                buckets.add("nlm:" + NLM_STATUSES[st])
        for a in seq(val.get("asyncs", [])):
            st = big(a.get("stat"))
            buckets.add("nlm:async-proc-%d" % big(a.get("proc")))
            if st in NLM_STATUSES:
                buckets.add("nlm:" + NLM_STATUSES[st])
        if len(seq(val.get("asyncs", []))) > 1:
            buckets.add("nlm:two-async-messages")

        # ---- lock shapes -------------------------------------------------
        lock = val.get("lock")
        if lock:
            if big(lock.get("wireLen")) <= 0:
                buckets.add("nlm:to-eof-range")
            if lock.get("excl") is True:
                buckets.add("nlm:exclusive")
            else:
                buckets.add("nlm:shared")
        if tag == "ONlmLock":
            if val.get("block") is True:
                buckets.add("nlm:blocking-request")
            if val.get("reclaim") is True:
                buckets.add("nlm:reclaim-request")
            buckets.add("nlm:lock-proc-%d" % big(val.get("nproc")))

        # ---- MOUNT -------------------------------------------------------
        if reply.get("tag") == "RMntOk":
            buckets.add("mnt:MNT3_OK")
        elif reply.get("tag") == "RMntErr":
            st = big(reply.get("value"))
            if st in MNT_STATUSES:
                buckets.add("mnt:" + MNT_STATUSES[st])
        if reply.get("tag") == "RMountTab" and seq(reply.get("value")):
            buckets.add("mnt:non-empty-table")

        # ---- portmap -----------------------------------------------------
        if reply.get("tag") == "RPort":
            buckets.add("pm:port-served" if big(reply["value"])
                        else "pm:port-unserved")
        if reply.get("tag") == "RUaddr":
            buckets.add("pm:uaddr-served" if big(reply["value"]["port"])
                        else "pm:uaddr-unserved")
        if tag == "OPmGetport":
            served_vers = {2: [100000], 3: [100000, 100003, 100005],
                           4: [100000, 100003, 100021], 1: [100024]}
            prog, vers = big(val["prog"]), big(val["vers"])
            if prog not in (100000, 100003, 100005, 100021, 100024):
                buckets.add("pm:unknown-program")
            elif prog not in served_vers.get(vers, []):
                buckets.add("pm:unserved-version")
            if big(val["prot"]) != 6:
                buckets.add("pm:unserved-transport")

        # ---- the cross-protocol seams ------------------------------------
        monitors = set(seq(var(state, "monitors") or []))
        queue_len = len(seq(var(state, "queue") or []))
        held_len = len(seq(var(state, "held") or []))
        if monitors:
            buckets.add("seam:host-monitored")
        if prev_monitors and not monitors and tag == "OSmNotify":
            buckets.add("seam:notify-cleared-monitors")
        if tag == "OSmNotify" and seq(val.get("granted", [])):
            buckets.add("seam:notify-promoted-a-waiter")
        if tag == "ONlmFreeAll" and prev_held_len > held_len:
            buckets.add("seam:free-all-released-locks")
        if tag == "ONlmUnlock" and seq(val.get("granted", [])):
            buckets.add("seam:unlock-promoted-a-waiter")
        if queue_len > prev_queue_len:
            buckets.add("seam:request-queued")

        prev_monitors = monitors
        prev_queue_len = queue_len
        prev_held_len = held_len


def required():
    req = ["op:" + t for t in OP_TAGS]
    req += ["reply:PROC_UNAVAIL"]
    req += ["nlm:" + n for n in NLM_STATUSES.values()]
    req += ["nlm:holder-reported", "nlm:to-eof-range", "nlm:exclusive",
            "nlm:shared", "nlm:blocking-request", "nlm:reclaim-request",
            "nlm:two-async-messages"]
    req += ["nlm:lock-proc-%d" % p for p in (2, 7, 22)]
    req += ["nlm:async-proc-%d" % p for p in (11, 12, 13, 14)]
    req += ["mnt:" + n for n in MNT_STATUSES.values()]
    req += ["mnt:non-empty-table"]
    req += ["pm:port-served", "pm:port-unserved", "pm:uaddr-served",
            "pm:uaddr-unserved", "pm:unknown-program", "pm:unserved-version",
            "pm:unserved-transport"]
    req += ["seam:host-monitored", "seam:notify-cleared-monitors",
            "seam:free-all-released-locks", "seam:request-queued",
            "seam:unlock-promoted-a-waiter"]
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
    print("NFSAUX MBT coverage over %d trace(s):" % len(traces))
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
