<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors
SPDX-License-Identifier: MIT
-->
# Replay harnesses

A consuming project normally brings its own replay harness and drives the
generated corpus at its own server (see the top-level README). What lives here
is different, and serves this repo rather than a consumer:

**a harness that replays the corpus against a third-party server, to test the
models themselves.**

A model written alongside one implementation drifts toward that
implementation. The traces still pass, and the passing means less and less:
the model and the server can agree on something the standard never said.
Replaying the same corpus against an unrelated server is the cheapest way to
find out. Every disagreement is a finding — a model bug, or a genuine
divergence in that server — and both are worth having written down.

| harness | server under test | suite |
|---------|-------------------|-------|
| [`samba/`](samba/) | Samba `smbd` | `quint/smb2` |

Only Samba's record lives here. A consuming project's own divergences belong in
that project, next to the code that has to change -- and because the corpus is
generated unconditionally, nothing about one server's behavior is encoded in
what gets generated for everyone.

## samba

`ctest -L samba` replays the generated SMB2 corpus against a private Samba
instance. See [`samba/README.md`](samba/README.md) for how it runs, what it
checks, and the divergences found so far.
