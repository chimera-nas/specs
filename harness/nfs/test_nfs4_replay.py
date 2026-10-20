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
from deviations import (Finding, NFS4_OK, NFS4ERR_BAD_STATEID,  # noqa: E402
                        NFS4ERR_OPENMODE)
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

    def test_after_a_forgiven_deviation_it_is_a_mismatch_naming_the_entry(self):
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


if __name__ == "__main__":
    unittest.main()
