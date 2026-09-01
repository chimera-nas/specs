# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""ITF trace decoding shared by the NFS replayers.

Quint's `--out-itf` output wraps values in a small set of encodings
(`#bigint`, `#map`, `#set`, `#tup`, tagged sum-type values).  Everything
here decodes them into plain Python data and fails loudly on anything it
does not recognise, so a Quint format change is a visible error rather than
a silently skipped check.
"""

import json


class TraceFormatError(Exception):
    pass


class Divergence(Exception):
    """An unreconciled disagreement between the model and the server.

    `step` is the 1-based state index, `op` a (tag, value) pair describing
    the step, `findings` the list of Finding records that were not matched
    by the server's deviation registry.
    """

    def __init__(self, step, op, findings):
        self.step = step
        self.op = op
        self.findings = findings
        super().__init__(f"step {step}: " +
                         "; ".join(str(f) for f in findings))


def itf_decode(v):
    if isinstance(v, dict):
        special = [k for k in v if k.startswith("#")]
        if special == ["#bigint"]:
            return int(v["#bigint"])
        if special == ["#map"]:
            return {itf_decode(k): itf_decode(val) for k, val in v["#map"]}
        if special == ["#set"]:
            return [itf_decode(x) for x in v["#set"]]
        if special == ["#tup"]:
            return tuple(itf_decode(x) for x in v["#tup"])
        if special:
            raise TraceFormatError(f"unrecognized ITF encoding {special}")
        if set(v.keys()) == {"tag", "value"}:
            return {"tag": v["tag"], "value": itf_decode(v["value"])}
        return {k: itf_decode(val) for k, val in v.items()}
    if isinstance(v, list):
        return [itf_decode(x) for x in v]
    if isinstance(v, (str, bool, int)):
        return v
    raise TraceFormatError(f"unrecognized ITF value {v!r}")


def load_states(path, need=("lastOp",)):
    """Every state of the trace as {var: value}, module qualifiers stripped
    from the variable names (quint writes `module::var`)."""
    with open(path) as f:
        raw = json.load(f)
    if "states" not in raw:
        raise TraceFormatError(f"{path}: not an ITF trace")
    states = []
    for st in raw["states"]:
        d = {}
        for k, v in st.items():
            if k == "#meta" or k.startswith("mbt::"):
                continue
            d[k.split("::")[-1]] = itf_decode(v)
        for n in need:
            if n not in d:
                raise TraceFormatError(f"{path}: state missing {n}")
        states.append(d)
    return states


def diff_bytes(expect, actual, block_size):
    """Locate the first differing block for a divergence report."""
    n = min(len(expect), len(actual))
    for i in range(0, n, block_size):
        if expect[i:i + block_size] != actual[i:i + block_size]:
            return (f"; first differing block {i // block_size}: "
                    f"expected byte {expect[i]:#x}, got byte {actual[i]:#x}")
    return "; lengths differ only"
