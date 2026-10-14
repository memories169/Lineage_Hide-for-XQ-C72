#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# selinux_hide_patch.sh - block privileged SELinux context probes from
# application UIDs in KernelSU's selinux_hide feature
# (kernel/feature/selinux_hide.c).
#
# The change adds three guards that make the backup-policy fallback refuse
# to answer for privileged domains, so an app (uid >= 10000) cannot deduce
# the hidden SELinux state through /sys/fs/selinux:
#   - my_write_context(): reject "u:r:adbroot:s0"
#   - my_write_access():  reject "u:r:shell:s0" + "u:r:su:s0",
#                         "u:r:fsck_untrusted:s0", "u:r:adbroot:s0"
#   - ksu_handle_selinux_setprocattr(): reject "u:r:adbroot:s0"
#
# The patcher is semantic (anchors on functions, not line numbers) and
# idempotent, so it also works on trees with vendor or SUSFS modifications.
# Edited files are backed up next to the originals as *.selinux_hide.bak.
#
# Usage:
#   scripts/selinux_hide_patch.sh [--check|--revert] <tree>
#
# <tree> is either the kernel source root (KernelSU is cloned at
# <tree>/KernelSU and symlinked as drivers/kernelsu) or the KernelSU repo
# root itself (<tree>/kernel/feature/selinux_hide.c).
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: selinux_hide_patch.sh [--check|--revert] <tree>

  (no option)  add the SELinux context guards to selinux_hide.c
  --check      report whether the guards are fully in place; no changes
  --revert     remove the guards again

<tree> is the kernel source root (contains KernelSU/) or the KernelSU repo
root (contains kernel/feature/selinux_hide.c).

Examples:
  scripts/selinux_hide_patch.sh /path/to/kernel
  scripts/selinux_hide_patch.sh --check /path/to/kernel/KernelSU
  scripts/selinux_hide_patch.sh --revert /path/to/kernel

Rebuild and flash the kernel after applying.  A backup of the edited file is
written next to it as *.selinux_hide.bak.
EOF
}

MODE=apply
KDIR=
while [ $# -gt 0 ]; do
    case "$1" in
        --check) MODE=check ;;
        --revert) MODE=revert ;;
        -h|--help) usage; exit 0 ;;
        --*) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)
            if [ -n "$KDIR" ]; then
                echo "error: only one tree may be given" >&2
                exit 2
            fi
            KDIR=$1
            ;;
    esac
    shift
done

if [ -z "$KDIR" ]; then
    usage >&2
    exit 2
fi
if [ ! -d "$KDIR" ]; then
    echo "error: '$KDIR' is not a directory" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required to apply the patch" >&2
    exit 1
fi

python3 - "$MODE" "$KDIR" <<'PY'
import os
import re
import shutil
import sys

MODE = sys.argv[1]
KDIR = sys.argv[2].rstrip("/")

# The KernelSU source can be given directly (repo root) or found inside the
# kernel tree, where setup.sh clones it as KernelSU/ and symlinks it into
# drivers/kernelsu.
CANDIDATES = [
    os.path.join(KDIR, "KernelSU/kernel/feature/selinux_hide.c"),
    os.path.join(KDIR, "kernel/feature/selinux_hide.c"),
    os.path.join(KDIR, "drivers/kernelsu/feature/selinux_hide.c"),
]

TARGET = None
for path in CANDIDATES:
    if os.path.isfile(path):
        TARGET = path
        break
if TARGET is None:
    print(
        "error: selinux_hide.c not found under '%s'\n"
        "       pass the kernel root (with KernelSU/) or the KernelSU repo root" % KDIR,
        file=sys.stderr,
    )
    sys.exit(1)
# Resolve symlinks (drivers/kernelsu -> KernelSU/kernel) so the backup and
# status refer to the real file.
TARGET = os.path.realpath(TARGET)

SNIPPET_CONTEXT = (
    '    if (strstr(buf, "u:r:adbroot:s0")) {\n'
    "        return -EINVAL;\n"
    "    }\n"
)
SNIPPET_ACCESS = (
    '    if ((strstr(buf, "u:r:shell:s0") && strstr(buf, "u:r:su:s0")) || strstr(buf, "u:r:fsck_untrusted:s0") || strstr(buf, "u:r:adbroot:s0")) {\n'
    "        length = -EINVAL;\n"
    "        goto out;\n"
    "    }\n"
)
SNIPPET_SETPROC = (
    '        if (strstr(str, "u:r:adbroot:s0")) {\n'
    "            return -EINVAL;\n"
    "        }\n"
)

HUNKS = [
    {
        "name": "my_write_context()",
        "snippet": SNIPPET_CONTEXT,
        # after the uid gate:  return orig_context_write(file, buf, size);\n    }
        "anchor": re.compile(
            r"([ \t]*)return orig_context_write\(file, buf, size\);\n\1\}\n"
        ),
        "position": "after",
        "markers": ("u:r:adbroot:s0",),
    },
    {
        "name": "my_write_access()",
        "snippet": SNIPPET_ACCESS,
        # before the COMPUTE_AV permission check
        "anchor": re.compile(
            r"[ \t]*length = ksu_avc_has_perm_compat\(current_sid\(\), "
            r"SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL\);\n"
        ),
        "position": "before",
        "markers": ("u:r:shell:s0", "u:r:fsck_untrusted:s0", "u:r:adbroot:s0"),
    },
    {
        "name": "ksu_handle_selinux_setprocattr()",
        "snippet": SNIPPET_SETPROC,
        # after the trailing-newline cleanup inside the setprocattr hook
        "anchor": re.compile(
            r"([ \t]*)if \(str\[size - 1\] == '\\n'\) \{\n"
            r"[ \t]*str\[size - 1\] = 0;\n"
            r"[ \t]*size--;\n"
            r"[ \t]*\}\n"
        ),
        "position": "after",
        "markers": ("u:r:adbroot:s0",),
    },
]


def read(path):
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as fh:
        return fh.read()


def write(path, text):
    bak = path + ".selinux_hide.bak"
    if os.path.exists(path) and not os.path.exists(bak):
        shutil.copy2(path, bak)
    tmp = path + ".selinux_hide.tmp"
    with open(tmp, "w", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write(text)
    os.replace(tmp, path)


def hunk_status(text, hunk):
    if text.count(hunk["snippet"]) == 1:
        return "applied"
    match = hunk["anchor"].search(text)
    if not match:
        return "anchor-missing"
    if hunk["position"] == "after":
        region = text[match.end(): match.end() + 400]
    else:
        region = text[max(0, match.start() - 400): match.start()]
    if any(marker in region for marker in hunk["markers"]):
        return "applied-differently"
    return "pending"


def apply_hunk(text, hunk):
    status = hunk_status(text, hunk)
    if status == "applied":
        return text, "already applied"
    if status == "anchor-missing":
        raise RuntimeError(
            "cannot find the insertion point inside %s; the file was edited "
            "or reformatted - patch it manually" % hunk["name"]
        )
    if status == "applied-differently":
        raise RuntimeError(
            "%s already carries a similar guard with different formatting; "
            "revert it or check it manually" % hunk["name"]
        )
    match = hunk["anchor"].search(text)
    at = match.end() if hunk["position"] == "after" else match.start()
    return text[:at] + hunk["snippet"] + text[at:], "patched"


def revert_hunk(text, hunk):
    status = hunk_status(text, hunk)
    if status == "pending":
        return text, "not applied"
    if status == "applied":
        index = text.index(hunk["snippet"])
        return text[:index] + text[index + len(hunk["snippet"]):], "reverted"
    if status == "anchor-missing":
        raise RuntimeError(
            "cannot find the guard anchor inside %s; revert it manually"
            % hunk["name"]
        )
    raise RuntimeError(
        "%s carries a similar guard with different formatting; "
        "revert it manually" % hunk["name"]
    )


try:
    text = read(TARGET)

    if MODE == "apply":
        results = []
        for hunk in HUNKS:
            text, status = apply_hunk(text, hunk)
            results.append((hunk["name"], status))
        if all(status == "already applied" for _, status in results):
            print("already applied; nothing to do")
            sys.exit(0)
        write(TARGET, text)
    elif MODE == "revert":
        results = []
        for hunk in HUNKS:
            text, status = revert_hunk(text, hunk)
            results.append((hunk["name"], status))
        if all(status == "not applied" for _, status in results):
            print("not applied; nothing to do")
            sys.exit(0)
        write(TARGET, text)
    elif MODE == "check":
        results = [(hunk["name"], hunk_status(text, hunk)) for hunk in HUNKS]
        print("check %s" % TARGET)
        for name, status in results:
            print("  %-36s %s" % (name, status))
        if all(status == "applied" for _, status in results):
            print("result: fully applied")
            sys.exit(0)
        print("result: not fully applied")
        sys.exit(1)
    else:
        raise RuntimeError("unknown mode %s" % MODE)
except RuntimeError as exc:
    print("error: %s" % exc, file=sys.stderr)
    sys.exit(1)

print("%s %s" % (MODE, TARGET))
for name, status in results:
    print("  %-36s %s" % (name, status))
if MODE == "apply":
    print("rebuild the kernel and flash it; no other change is needed")
PY
