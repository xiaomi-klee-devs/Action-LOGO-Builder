#!/usr/bin/env python3
"""
Re-attach MediaTek certificates to a custom (repacked) logo image.

`mtklogo` strips the MTK `cert1`/`cert2` certificate partitions when it
repacks a logo.bin.  Without them the Preloader/LK `load_image()` path
fails with:

    [SEC] logo1 cert chain vfy fail (0x10100d)
    ASSERT FAILED at (platform/mediatek/common/loader/load_image.c:149)

The stock logo image is a chain of MTK partitions (e.g. `logo1`, `logo2`),
each carrying a signed `cert1` chain plus a `cert2` holding the header/image
SHA-256 digests.  A repack replaces the image payload but cannot re-sign it,
so this tool rebuilds the final image by:

  1. Starting from the stock (donor) image, preserving its partition order.
  2. Substituting the payload of each partition found in the repacked image.
  3. Keeping the donor `cert1` (its signature chain stays valid).
  4. Rebuilding `cert2` with a ``[0]`` hash-override block so the software
     verifier accepts the new header/image digests.

This is the same technique the `fenrir` injector uses for the `lk`
partition, and it is honoured by the LK (`bl2_ext`) cert2 parser.

Usage:
    ./sign_logo.py repacked.bin --donor stock_logo.img [-o out.bin]

If ``-o`` is omitted the output is written next to the input with a
``-signed.bin`` suffix.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running from anywhere by adding the fenrir repo (which vendors liblk)
# and its injector directory to sys.path.
_HERE = Path(__file__).resolve().parent
_FENRIR = _HERE.parent / "fenrir"
for _p in (
    _FENRIR,
    _FENRIR / "injector",
    _FENRIR / ".venv" / "lib" / "python3.14" / "site-packages",
):
    if _p.exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from liblk.image import LkImage  # noqa: E402
from liblk.structures.certificate import Certificate  # noqa: E402
from liblk.structures.partition import LkPartition  # noqa: E402


def build_override(original_cert2: bytes, header_hash: bytes, image_hash: bytes) -> bytes:
    """Rebuild cert2 with a ``[0]`` hash-override block for the new digests."""
    cert = Certificate.from_bytes(original_cert2)
    return cert.build_hash_override_block(header_hash, image_hash) + bytes(original_cert2)


def clone_cert(cert: LkPartition, *, override: bytes | None = None) -> LkPartition:
    """Clone a certificate partition, optionally replacing its payload."""
    header = cert.header
    data = override if override is not None else bytes(cert.data)
    header.data_size = len(data)
    return LkPartition(header=header, data=data, end_offset=0)


def resign_partition(part: LkPartition, donor_part: LkPartition) -> None:
    """Attach donor cert1/cert2 to ``part``, overriding cert2 hashes."""
    header_hash, image_hash = part.compute_hashes()
    override = build_override(
        bytes(donor_part.cert2.data), header_hash, image_hash
    )

    part.certs = [
        clone_cert(donor_part.cert1),
        clone_cert(donor_part.cert2, override=override),
    ]
    print(
        f"  signed '{part.header.name}': "
        f"header={header_hash.hex()[:16]}... image={image_hash.hex()[:16]}..."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("repacked", help="Repacked logo image (certs may be missing)")
    parser.add_argument(
        "-d", "--donor", required=True,
        help="Stock signed logo image to take certificates/structure from",
    )
    parser.add_argument("-o", "--output", default=None, help="Output path")
    args = parser.parse_args()

    src = Path(args.repacked)
    donor_path = Path(args.donor)
    if not src.exists():
        print(f"Error: {src} not found", file=sys.stderr)
        return 1
    if not donor_path.exists():
        print(f"Error: {donor_path} not found", file=sys.stderr)
        return 1

    out = Path(args.output) if args.output else src.with_name(src.stem + "-signed.bin")

    donor = LkImage(str(donor_path))
    repacked = LkImage(str(src))

    # Start from the donor so partition order and signature chain are preserved,
    # then swap in the repacked payload for every matching partition.
    print("Building signed image from donor structure:")
    for name, donor_part in donor.partitions.items():
        if donor_part.certs is None or len(donor_part.certs) < 2:
            print(f"  '{name}': donor has no cert1/cert2, skipping")
            continue

        new_part = repacked.partitions.get(name)
        if new_part is not None and bytes(new_part.data) != bytes(donor_part.data):
            donor_part.data = bytes(new_part.data)
            resign_partition(donor_part, donor_part)
        else:
            status = donor_part.matches_cert2()
            print(
                f"  '{name}': unchanged, keeping original certs "
                f"(cert2 match={status})"
            )

    donor._rebuild_contents()
    out.write_bytes(bytes(donor.contents))

    print(f"\nWrote {out} ({len(donor.contents)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
