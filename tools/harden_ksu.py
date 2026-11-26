#!/usr/bin/env python3
"""Harden the vendored BakaSU / KernelSU feature defaults.

Chunqiu checks #10 and #11 are both about KernelSU's SELinux footprint:

  * `u:r:ksu:s0` / `u:object_r:ksu_file:s0` show up in the live policy;
  * `untrusted_app -> ksu_file read`, injected by
    `ksu_allow(db, "domain", KERNEL_SU_FILE, ALL, ALL)` in kernel/selinux/rules.c;
  * `adbd -> adbroot binder`, the ADB Root feature escaping adbd into the KSU domain.

KernelSU already ships the remedy: the `selinux_hide` feature answers
selinuxfs queries coming from unprivileged app uids out of the pre-KernelSU
policy, and `adb_root` is a runtime toggle. Both are opt-in, and the manager
stores their state in /data/adb, so a data wipe or a manager reinstall puts
the detection back.

This script seeds the exact same "forced" mechanism that the
`force_feature=` boot parameter uses:

  * the values are applied by ksu_feature_apply_forced() at
    android-13 second_stage (right after the sepolicy backup exists) and
    retried at post-fs-data;
  * `ksu_set_feature()` refuses to change a forced feature, so the manager
    cannot turn them back off (ksud logs "Skip feature ... forced by boot
    config" and moves on);
  * nothing depends on /data/adb, so the hardening survives wipes.

Usage:
    tools/harden_ksu.py KernelSU/kernel/policy/feature.c

Exit status:
    0  patched, or already patched (idempotent)
    2  the vendored KernelSU layout changed - fail the build instead of
       silently shipping an unhardened kernel
"""

from __future__ import annotations

import pathlib
import sys

MARKER = "CHUNQIU_HARDEN"

# Insertion points inside kernel/policy/feature.c (BakaSU 57b2db6).
ANCHOR_DECL = "static DECLARE_BITMAP(forced_pending, KSU_FEATURE_MAX);\n"
# The same reset loop also exists in ksu_feature_exit(), so the anchor has to
# include the function signature to stay unique.
ANCHOR_INIT = (
    "void __init ksu_feature_init(void)\n"
    "{\n"
    "    int i;\n"
    "\n"
    "    for (i = 0; i < KSU_FEATURE_MAX; i++) {\n"
    "        feature_handlers[i] = NULL;\n"
    "    }\n"
)

HELPER = """
/*
 * CHUNQIU_HARDEN: boot defaults that the manager cannot override.
 * The values take the force_feature path, so they are applied at
 * second_stage (after the sepolicy backup exists) and retried at
 * post-fs-data.
 */
static void __init ksu_harden_feature_default(u32 id, u64 value)
{
    if (id >= KSU_FEATURE_MAX || test_bit(id, forced_mask))
        return;

    forced_values[id] = value;
    set_bit(id, forced_mask);
    set_bit(id, forced_pending);

    pr_info("feature: hardened default %s=%llu\\n",
            feature_names[id] ? feature_names[id] : "?", (unsigned long long)value);
}
"""

CALLS = """
    /* CHUNQIU_HARDEN: hide KernelSU SELinux additions, never escape adbd. */
    ksu_harden_feature_default(KSU_FEATURE_SELINUX_HIDE, 1);
    ksu_harden_feature_default(KSU_FEATURE_ADB_ROOT, 0);
"""

REQUIRED_TOKENS = (
    "KSU_FEATURE_SELINUX_HIDE",
    "KSU_FEATURE_ADB_ROOT",
    ANCHOR_DECL,
    ANCHOR_INIT,
)


def fail(message: str) -> None:
    print(f"[-] harden_ksu: {message}", file=sys.stderr)
    sys.exit(2)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path/to/KernelSU/kernel/policy/feature.c>", file=sys.stderr)
        return 2

    path = pathlib.Path(sys.argv[1])
    if not path.is_file():
        fail(f"{path} not found - did the KernelSU setup step run?")

    raw = path.read_bytes().decode("utf-8")
    uses_crlf = "\r\n" in raw
    text = raw.replace("\r\n", "\n")

    if MARKER in text:
        print(f"[+] harden_ksu: {path} already hardened")
        return 0

    for token in REQUIRED_TOKENS:
        if token not in text:
            fail(f"anchor not found in {path}: {token!r}")
    if text.count(ANCHOR_DECL) != 1:
        fail(f"expected exactly one forced_pending declaration, found {text.count(ANCHOR_DECL)}")
    if text.count(ANCHOR_INIT) != 1:
        fail(f"expected exactly one ksu_feature_init() loop, found {text.count(ANCHOR_INIT)}")

    text = text.replace(ANCHOR_DECL, ANCHOR_DECL + HELPER, 1)
    text = text.replace(ANCHOR_INIT, ANCHOR_INIT + CALLS, 1)

    if uses_crlf:
        text = text.replace("\n", "\r\n")
    path.write_bytes(text.encode("utf-8"))

    print(f"[+] harden_ksu: forced selinux_hide=1 and adb_root=0 in {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
