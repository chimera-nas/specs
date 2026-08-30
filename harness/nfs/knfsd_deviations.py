# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Registry of known Linux kernel NFS server (knfsd) divergences from the
NFS models.  See deviations.py for the contract and ganesha_deviations.py
for the shape of an entry.  Recorded against the kernel of the
kvm-test-base guest the harness boots (harness/nfs/run_nfs_mbt.sh).
"""

from deviations import (Deviation, Registry, SERVER, MODEL, BOTH,  # noqa: F401
                        NFS4_OK, NFS3_OK)
from deviations import *  # noqa: F401,F403  -- the status constants


# knfsd's ACCESS-masking and READLINK-on-a-directory findings drove the model
# to the standard (they matched ganesha and the RFCs); the model was corrected,
# so nothing is recorded here yet.  New knfsd-specific divergences go here.



NFS4 = Registry("knfsd/nfs4", [
])


NFS3 = Registry("knfsd/nfs3", [
])
