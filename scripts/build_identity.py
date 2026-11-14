"""Embed source identity even for local builds; no wall-clock timestamp."""
from pathlib import Path
import json
import subprocess
from SCons.Script import Import

Import("env")
root = Path(env.subst("$PROJECT_DIR"))
build = Path(env.subst("$BUILD_DIR"))
build.mkdir(parents=True, exist_ok=True)
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
dirty = bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=root, text=True).strip())
identity = commit[:12] + ("-dirty" if dirty else "")
header = build / "source_identity.h"
text = ('#pragma once\n#undef GIT_COMMIT_HASH\n#define GIT_COMMIT_HASH ' + json.dumps(identity) +
        '\n#undef BRUCE_VERSION\n#define BRUCE_VERSION "1.17-native1"\n')
if not header.exists() or header.read_text() != text:
    header.write_text(text)
env.Append(CCFLAGS=["-include", str(header)])
(build / "source_identity.json").write_text(json.dumps({
    "commit": commit, "dirty": dirty, "build_id": identity,
    "environment": env.subst("$PIOENV"), "version": "1.17-native1",
}, indent=2) + "\n")
