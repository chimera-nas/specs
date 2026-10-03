# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""The deviation registry for the Windows SMB server -- empty, and meant to be.

harness/samba/smb2_replay.py asks its server's registry about every reply that
differs from the model, and forgives the ones it finds there.  That mechanism
exists for divergences the MODEL cannot state; everything it can state is a
branch in quint/smb2, switched on by the cell's config, so the trace already
predicts what the server does and the comparison is exact.

Windows has no entry here.  Windows is the implementation MS-SMB2 and MS-FSA
describe, so a disagreement with it is first a question about the model, and
one that turns out to be Windows' own belongs in the model as a WD-* deviation
(quint/smb2/corpus.schema.json), not in a list the harness consults after the
fact.  An entry is added here only for something no model branch can describe,
with the reason written beside it -- see samba_deviations.py for what that
looks like.
"""

ST_SHARING_VIOLATION = 0xC0000043


def find(op, exp_status, act_status, fieldname=None,
         exp_value=None, act_value=None, cmd=None, res=None, ctx=None):
    """No recorded deviation: every difference is a MISMATCH."""
    return None
