# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""The deviation registry for ksmbd, the Linux kernel SMB server -- empty.

harness/samba/smb2_replay.py asks its server's registry about every reply that
differs from the model, and forgives the ones it finds there.  That mechanism
exists for divergences the MODEL cannot state; everything it can state is a
branch in quint/smb2, switched on by the cell's config, so the trace already
predicts what the server does and the comparison is exact.

ksmbd's known divergences are all of the second kind (KD-1, KD-2, KD-3 in
quint/smb2/corpus.schema.json), so there is nothing here.
"""

ST_SHARING_VIOLATION = 0xC0000043


def find(op, exp_status, act_status, fieldname=None,
         exp_value=None, act_value=None, cmd=None, res=None, ctx=None):
    """No recorded deviation: every difference is a MISMATCH."""
    return None
