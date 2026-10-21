# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Unit tests for the parts of the NFSv4 replayer that decide whether a
trace PASSES: the deviation registry's scoping and the outcome of a replay
that can no longer be compared.  No server; every case builds the replayer
state by hand.

    python3 -m unittest discover -s harness/nfs -p 'test_*.py'
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nfs4_replay as r4  # noqa: E402
import ganesha_deviations as gd  # noqa: E402
import knfsd_deviations as kd  # noqa: E402
from deviations import (Finding, NFS4_OK, NFS4ERR_BAD_STATEID,  # noqa: E402
                        NFS4ERR_OPENMODE, NFS4ERR_EXPIRED,
                        NFS4ERR_STALE_STATEID, NFS4ERR_STALE_CLIENTID,
                        NFS4ERR_BADNAME, NFS4ERR_OLD_STATEID)
from itf import Divergence, TraceFormatError  # noqa: E402


def sel_ref(sid, kind):
    """A SelRef as itf.load_states decodes it: a unit variant's payload is
    the empty tuple."""
    return {"tag": "SelRef",
            "value": {"sid": sid, "argSeq": 0,
                      "kind": {"tag": kind, "value": ()}}}


def setattr_ops(sel, size_blocks=1):
    return [{"tag": "RPutfh", "value": 1},
            {"tag": "RSetattr",
             "value": {"mode": -1, "sizeBlocks": size_blocks, "sel": sel}}]


def make_replayer(cls=r4.Replayer, **attrs):
    """A Replayer with no client behind it: only the bookkeeping the test
    needs, set explicitly."""
    r = cls.__new__(cls)
    r.fh = {}
    r.dry = False
    r.minor = 0
    r.caps = {}
    r.status_dev = 0
    r.tol_status = 0
    r.sid_seq = {}
    r.sid_other = {}
    r.sid_wr = {}
    r.last_hit = None
    r.cur_step = 0
    r.cur_lab = None
    r.history = []
    r.verbose = False
    for k, v in attrs.items():
        setattr(r, k, v)
    return r


def registry_ctx(ops, replayer, minor=2):
    return {"minor": minor, "caps": {}, "ops": ops, "lab": {"ops": ops},
            "step": 9, "replayer": replayer}


class GD39Scope(unittest.TestCase):
    """GD-39 forgives NFS4ERR_BAD_STATEID for a SETATTR(size) sent through
    a lock stateid whose lock is a READ lock -- and nothing else.  A
    BAD_STATEID for the same SETATTR through an open, delegation or
    write-lock stateid is unexplained and must reach the mismatch path
    (chimera-nas/chimera#1728 is exactly that shape)."""

    def lookup(self, sel, sid_wr, expected=NFS4_OK):
        f = Finding("SSetattr", "status", expected, NFS4ERR_BAD_STATEID)
        ctx = registry_ctx(setattr_ops(sel), make_replayer(sid_wr=sid_wr))
        return gd.NFS4.lookup(f, ctx)

    def test_matches_setattr_size_through_a_read_lock_stateid(self):
        self.assertIs(self.lookup(sel_ref(5, "KLock"), {5: False}),
                      gd.GD_39_SETATTR_READ_LOCK)

    def test_reconcilable_only_where_the_model_also_refused(self):
        f = Finding("SSetattr", "status", NFS4ERR_OPENMODE,
                    NFS4ERR_BAD_STATEID)
        ctx = registry_ctx(setattr_ops(sel_ref(5, "KLock")),
                           make_replayer(sid_wr={5: False}))
        dev = gd.NFS4.lookup(f, ctx)
        self.assertIs(dev, gd.GD_39_SETATTR_READ_LOCK)
        self.assertTrue(dev.is_reconcilable(f, ctx))
        f_ok = Finding("SSetattr", "status", NFS4_OK, NFS4ERR_BAD_STATEID)
        self.assertFalse(dev.is_reconcilable(f_ok, ctx))

    def test_ignores_setattr_through_a_write_lock_stateid(self):
        self.assertIsNone(self.lookup(sel_ref(5, "KLock"), {5: True}))

    def test_ignores_setattr_through_an_open_stateid(self):
        self.assertIsNone(self.lookup(sel_ref(5, "KOpen"), {5: False}))

    def test_ignores_setattr_through_a_delegation_stateid(self):
        self.assertIsNone(self.lookup(sel_ref(5, "KDeleg"), {5: False}))

    def test_ignores_a_lock_stateid_whose_lock_type_was_never_learned(self):
        self.assertIsNone(self.lookup(sel_ref(5, "KLock"), {}))

    def test_ignores_setattr_through_the_anonymous_stateid(self):
        self.assertIsNone(self.lookup({"tag": "SelAnon", "value": ()},
                                      {5: False}))

    def test_ignores_a_setattr_that_does_not_change_the_size(self):
        f = Finding("SSetattr", "status", NFS4_OK, NFS4ERR_BAD_STATEID)
        ctx = registry_ctx(setattr_ops(sel_ref(5, "KLock"), size_blocks=-1),
                           make_replayer(sid_wr={5: False}))
        self.assertIsNone(gd.NFS4.lookup(f, ctx))


class LockTypeBookkeeping(unittest.TestCase):
    """A LOCK reply binds the model's lock stateid to a wire stateid; the
    replayer also remembers which lock TYPE the stateid last carried, which
    is what a registry entry scoped to read locks needs."""

    def lock(self, r, sid, wr, seq=1):
        exp = {"tag": "SLock", "value": {"st": NFS4_OK, "sid": sid,
                                         "seq": seq}}
        wire = {"status": NFS4_OK, "stateid": (seq, bytes([sid]) * 12)}
        req = {"tag": "RLock", "value": {"wr": wr, "lo": 0, "hi": 1,
                                         "newOwner": True, "lockSid": -1}}
        mism = []
        r.check_result(exp, wire, {"cur": None, "saved": None}, mism, req)
        self.assertEqual(mism, [])

    def test_a_read_lock_reply_records_the_stateid_as_a_read_lock(self):
        r = make_replayer()
        self.lock(r, 5, wr=False)
        self.assertEqual(r.sid_wr, {5: False})

    def test_a_later_write_lock_on_the_same_stateid_updates_the_type(self):
        r = make_replayer()
        self.lock(r, 5, wr=False)
        self.lock(r, 5, wr=True, seq=2)
        self.assertEqual(r.sid_wr, {5: True})


class MissingFilehandle(unittest.TestCase):
    """The model holds an object the server never handed out.  After a
    forgiven deviation that is a divergence the registry did not cover
    (the forgiveness was wrong for this shape), so the trace is a
    MISMATCH that names the entry -- never an abandoned-and-green trace.
    With no forgiven deviation behind it the trace itself is malformed."""

    def test_after_a_forgiven_deviation_it_is_a_mismatch_naming_it(self):
        dev = gd.GD_40_SETATTR_OPENMODE_FIRST
        forgiven = Finding("SSetattr", "status", NFS4ERR_BAD_STATEID,
                           NFS4ERR_OPENMODE)
        lab = {"ops": [{"tag": "RPutfh", "value": 42}], "status": 0,
               "results": []}
        r = make_replayer(last_hit=(dev, 3, forgiven), cur_step=7,
                          cur_lab=lab)
        try:
            r.real_fh(42)
        except Exception as e:  # noqa: BLE001 -- the type IS the assertion
            raised = e
        else:
            self.fail("real_fh returned for an ino with no filehandle")
        self.assertIsInstance(raised, Divergence)
        self.assertEqual(raised.step, 7)
        self.assertEqual(raised.op, ("LCompound", lab))
        self.assertEqual(len(raised.findings), 1)
        self.assertIn(dev.id, str(raised))
        self.assertIn("step 3", str(raised))

    def test_without_a_forgiven_deviation_it_is_a_trace_error(self):
        r = make_replayer(cur_step=7)
        with self.assertRaises(TraceFormatError):
            r.real_fh(42)

    def test_replay_tracks_the_compound_being_sent(self):
        seen = []

        class Recording(r4.Replayer):
            def run_compound(self, idx, lab):
                seen.append((self.cur_step, self.cur_lab))
                return {"status": NFS4_OK, "results": []}

        r = make_replayer(Recording)
        lab = {"ops": [], "status": 0, "results": []}
        r.replay([{"tag": "LInit", "value": {}},
                  {"tag": "LCompound", "value": lab}])
        self.assertEqual(seen, [(1, lab)])


class LeaseLapse(unittest.TestCase):
    """Under the T_RENEW_LAPSED tolerance the model declares that a server
    may answer NFS4ERR_EXPIRED (or STALE_STATEID, or STALE_CLIENTID to a
    RENEW) wherever the model, which carries no clock, predicted something
    else.  The model walks on along its own prediction, so from that reply
    on the two sides hold different state: the replayer stops comparing
    there, as a lapse, instead of running on into the parted state."""

    def result(self, r, tag, expected, actual, accept=None):
        v = {"st": expected}
        if accept is not None:
            v["stAccept"] = accept
        if tag == "SOpen":
            v.update(sid=-1, seq=0, needConfirm=False, deleg={"tag": "DNone"},
                     recalls=[], cinfo=None)
        mism = []
        r.check_result({"tag": tag, "value": v}, {"status": actual},
                       {"cur": None, "saved": None}, mism, None)
        return mism

    def test_expired_where_the_model_predicted_success_is_a_lapse(self):
        r = make_replayer(caps={"tolRenewLapsed": True}, cur_step=27)
        with self.assertRaises(r4.LeaseLapsed) as cm:
            self.result(r, "SLockt", NFS4_OK, NFS4ERR_EXPIRED,
                        accept=[NFS4ERR_EXPIRED, NFS4ERR_STALE_STATEID])
        self.assertEqual(cm.exception.step, 27)
        self.assertEqual(cm.exception.op, "SLockt")
        self.assertEqual(cm.exception.actual, NFS4ERR_EXPIRED)

    def test_an_accepted_lapse_status_still_stops_the_trace(self):
        # The model's own lapseAccept lists EXPIRED beside an OK OPEN that
        # creates a file: accepting it and running on is how a filehandle
        # the server never issued ends up in a later PUTFH.
        r = make_replayer(caps={"tolRenewLapsed": True}, cur_step=30)
        with self.assertRaises(r4.LeaseLapsed):
            self.result(r, "SOpen", NFS4_OK, NFS4ERR_EXPIRED,
                        accept=[NFS4ERR_EXPIRED, NFS4ERR_STALE_STATEID])

    def test_stale_clientid_to_a_renew_is_a_lapse(self):
        r = make_replayer(caps={"tolRenewLapsed": True}, cur_step=57)
        with self.assertRaises(r4.LeaseLapsed):
            self.result(r, "SRenew", NFS4_OK, NFS4ERR_STALE_CLIENTID,
                        accept=[NFS4_OK])

    def test_a_lapse_status_where_the_model_also_refused_parts_nothing(self):
        # Both sides refused the OPEN of a bad name; the server's reason is
        # the lease, the model's the name.  The model's lapseAccept lists
        # the alternative and the trace goes on (knfsd40_step_80_0x7_0
        # step 53, which precedes the RENEW that is the real lapse).
        r = make_replayer(caps={"tolRenewLapsed": True})
        mism = self.result(r, "SOpen", NFS4ERR_BADNAME, NFS4ERR_EXPIRED,
                           accept=[NFS4ERR_EXPIRED, NFS4ERR_STALE_STATEID])
        self.assertEqual(mism, [])
        self.assertEqual(r.tol_status, 1)

    def test_a_renew_the_model_refused_is_compared_by_its_accept_set(self):
        # ganesha answers EXPIRED to a RENEW of an unconfirmed client where
        # the model says STALE_CLIENTID and lists EXPIRED beside it (RFC
        # 7530 16.30.4 allows both): not a lapse, the two agree to refuse.
        r = make_replayer(caps={"tolRenewLapsed": True})
        mism = self.result(r, "SRenew", NFS4ERR_STALE_CLIENTID,
                           NFS4ERR_EXPIRED,
                           accept=[NFS4ERR_STALE_CLIENTID, NFS4ERR_EXPIRED,
                                   NFS4_OK])
        self.assertEqual(mism, [])

    def test_stale_clientid_elsewhere_is_not_a_lapse(self):
        # SETCLIENTID_CONFIRM answered STALE_CLIENTID belongs to the knfsd
        # registry (KN-17), not to the lapse rule.
        r = make_replayer(caps={"tolRenewLapsed": True})
        mism = self.result(r, "SSetclientidConfirm", NFS4_OK,
                           NFS4ERR_STALE_CLIENTID)
        self.assertEqual([(f.op, f.kind, f.expected, f.actual) for f in mism],
                         [("SSetclientidConfirm", "status", NFS4_OK,
                           NFS4ERR_STALE_CLIENTID)])

    def test_without_the_tolerance_expired_is_an_ordinary_finding(self):
        r = make_replayer(caps={"tolRenewLapsed": False})
        mism = self.result(r, "SOpen", NFS4_OK, NFS4ERR_EXPIRED)
        self.assertEqual([(f.op, f.expected, f.actual) for f in mism],
                         [("SOpen", NFS4_OK, NFS4ERR_EXPIRED)])

    def test_a_predicted_expired_is_compared_as_usual(self):
        r = make_replayer(caps={"tolRenewLapsed": True})
        mism = self.result(r, "SRenew", NFS4ERR_EXPIRED, NFS4ERR_EXPIRED,
                           accept=[NFS4ERR_EXPIRED])
        self.assertEqual(mism, [])


class LockStateidSeqid(unittest.TestCase):
    """A LOCK names an open stateid (new owner) or a lock stateid (existing
    owner).  Both go out with the seqid the server last handed us, as every
    other stateid the replayer sends does: a literal 0 is not the wildcard
    on a real stateid, and a strict 4.0 server answers OLD_STATEID once
    OPEN_CONFIRM has advanced the open stateid."""

    def encode(self, r, value):
        captured = {}

        def fake_enc_lock(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return b""
        real = r4.c4.enc_lock
        r4.c4.enc_lock = fake_enc_lock
        try:
            r.encode_op({"tag": "RLock", "value": value})
        finally:
            r4.c4.enc_lock = real
        return captured["kwargs"]

    def test_a_new_owner_lock_names_the_open_stateid_at_its_current_seqid(self):
        r = make_replayer(sid_seq={1: 2}, sid_other={1: b"o" * 12},
                          sid_client={1: 0x77}, clientid={})
        kw = self.encode(r, {"wr": True, "lo": 0, "hi": 2, "newOwner": True,
                             "openSid": 1, "lockSid": -1, "lockOwner": 6,
                             "oseq": 3, "lseq": 0})
        self.assertEqual(kw["open_sid"], (2, b"o" * 12))
        self.assertEqual(kw["open_seqid"], 3)

    def test_an_existing_owner_lock_names_the_lock_stateid_at_its_seqid(self):
        r = make_replayer(sid_seq={2: 4}, sid_other={2: b"l" * 12})
        kw = self.encode(r, {"wr": False, "lo": 0, "hi": 2,
                             "newOwner": False, "openSid": -1, "lockSid": 2,
                             "lockOwner": 6, "oseq": 0, "lseq": 5})
        self.assertEqual(kw["lock_sid"], (4, b"l" * 12))

    def test_an_unlearned_stateid_still_goes_out_with_seqid_0(self):
        r = make_replayer(sid_seq={}, sid_other={})
        kw = self.encode(r, {"wr": False, "lo": 0, "hi": 2,
                             "newOwner": False, "openSid": -1, "lockSid": 9,
                             "lockOwner": 6, "oseq": 0, "lseq": 1})
        self.assertEqual(kw["lock_sid"][0], 0)


class KN11Scope(unittest.TestCase):
    """KN-11 forgives READ and WRITE status-only; a LOCK one side granted and
    the other refused parts the lock table, so that arm stops the trace."""

    def test_a_refused_lock_is_not_reconcilable(self):
        f = Finding("SLock", "status", NFS4_OK, NFS4ERR_OLD_STATEID)
        ctx = registry_ctx([], make_replayer(), minor=0)
        dev = kd.NFS4.lookup(f, ctx)
        self.assertIs(dev, kd.KN_11_OPENMODE)
        self.assertFalse(dev.is_reconcilable(f, ctx))

    def test_a_read_openmode_disagreement_still_is(self):
        f = Finding("SRead", "status", NFS4ERR_OPENMODE, NFS4_OK)
        ctx = registry_ctx([], make_replayer(), minor=0)
        dev = kd.NFS4.lookup(f, ctx)
        self.assertIs(dev, kd.KN_11_OPENMODE)
        self.assertTrue(dev.is_reconcilable(f, ctx))


class ExitCode(unittest.TestCase):
    """A lapsed trace is not a failure and not a pass: like a capability
    SKIP it leaves the batch's verdict to the other traces, and a batch of
    nothing but skips and lapses is a SKIP (77)."""

    def test_a_single_lapsed_trace_is_a_skip(self):
        self.assertEqual(r4.exit_code({"lapsed": 1}, 1), 77)

    def test_a_lapse_beside_passing_traces_is_a_pass(self):
        self.assertEqual(r4.exit_code({"ok": 7, "lapsed": 1}, 8), 0)

    def test_skips_and_lapses_together_are_a_skip(self):
        self.assertEqual(r4.exit_code({"skip": 1, "lapsed": 1}, 2), 77)

    def test_a_mismatch_fails_whatever_else_happened(self):
        self.assertEqual(r4.exit_code({"ok": 6, "lapsed": 1, "mismatch": 1},
                                      8), 1)

    def test_an_error_fails(self):
        self.assertEqual(r4.exit_code({"error": 1, "skip": 1}, 2), 1)


if __name__ == "__main__":
    unittest.main()
