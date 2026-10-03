#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Delete the buckets a replay left behind.

The bucket cells (run_aws_mbt.sh, SPECS_AWS_BUCKETS=ephemeral) create buckets
of their own and delete them when a trace ends.  A run that is cancelled or
killed never reaches that, and S3 gives a bucket no lifetime: a lifecycle rule
expires a bucket's CONTENTS, never the bucket.  This is the lifetime.  It lists
the caller's buckets under a name prefix and empties and deletes the ones old
enough that no live run can still own them.

  s3_sweep.py --prefix chimera-ci-mbt- --max-age-hours 3
      what a schedule, or the start of a run, does: remove what earlier runs
      leaked, and leave alone anything a concurrent run may be using.

  s3_sweep.py --prefix chimera-ci-mbt-<run>-<attempt>- --max-age-hours 0
      what the end of a run does: remove everything of its own, whatever
      happened to the replay.

Only buckets whose name starts with the prefix are ever touched, and the
credentials this is meant to run with hold rights on no others.

Exit status: 0 nothing is left to sweep, 1 a bucket could not be removed.
"""

import argparse
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from s3_wire import S3Client, list_buckets, purge_bucket  # noqa: E402


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=None,
                    help="default: s3.<region>.amazonaws.com")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--no-tls", action="store_true")
    ap.add_argument("--region",
                    default=os.environ.get("AWS_REGION") or "us-east-1")
    ap.add_argument("--prefix", required=True,
                    help="only buckets whose name starts with this")
    ap.add_argument("--max-age-hours", type=float, required=True,
                    help="only buckets created at least this long ago")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    ak = os.environ.get("AWS_ACCESS_KEY_ID")
    sk = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if not ak or not sk:
        ap.error("no credentials: set AWS_ACCESS_KEY_ID / "
                 "AWS_SECRET_ACCESS_KEY")
    if len(args.prefix) < 8:
        ap.error("refusing a prefix shorter than 8 characters")

    client = S3Client(args.host or f"s3.{args.region}.amazonaws.com",
                      args.port, ak, sk, region=args.region,
                      tls=not args.no_tls)
    now = datetime.datetime.now(datetime.timezone.utc)
    failed = swept = kept = 0
    try:
        for name, created in list_buckets(client, args.prefix):
            try:
                when = datetime.datetime.fromisoformat(
                    created.replace("Z", "+00:00"))
                age = (now - when).total_seconds() / 3600
            except ValueError:
                print(f"{name}: unreadable CreationDate '{created}'; kept")
                kept += 1
                continue
            if age < args.max_age_hours:
                kept += 1
                continue
            if args.dry_run:
                print(f"{name}: {age:.1f}h old; would delete")
                continue
            why = purge_bucket(client, name)
            if why:
                print(f"{name}: {age:.1f}h old; NOT deleted: {why}")
                failed += 1
            else:
                print(f"{name}: {age:.1f}h old; deleted")
                swept += 1
    finally:
        client.close()
    print(f"swept {swept}, kept {kept} (younger than "
          f"{args.max_age_hours}h), failed {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
