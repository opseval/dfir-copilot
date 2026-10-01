"""tools/link-launcher.sh: puts the launcher on PATH under its names without sudo and without ever
clobbering something that is not ours. Driven with a throwaway HOME, PATH and a fake `brew`."""
import os
import stat
import subprocess

import pytest

SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools", "link-launcher.sh"))


@pytest.fixture
def env(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    launcher = tmp_path / "repo" / "dfir-copilot"
    launcher.parent.mkdir()
    launcher.write_text("#!/bin/sh\necho launcher\n")
    launcher.chmod(0o755)
    brewprefix = tmp_path / "brew"
    (brewprefix / "bin").mkdir(parents=True)
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    brew = fakebin / "brew"
    brew.write_text(f"#!/bin/sh\n[ \"$1\" = --prefix ] && echo {brewprefix}\n")
    brew.chmod(0o755)
    return {"home": home, "launcher": launcher, "brewbin": brewprefix / "bin", "fakebin": fakebin}


def run(env, alias="clue", path_dirs=(), brew_ok=True):
    path = os.pathsep.join([str(env["fakebin"]) if brew_ok else "/nonexistent-brew", "/usr/bin", "/bin",
                            *[str(p) for p in path_dirs]])
    args = ["bash", SCRIPT, str(env["launcher"])] + ([alias] if alias is not None else [])
    return subprocess.run(args, env={"HOME": str(env["home"]), "PATH": path}, capture_output=True, text=True)


def test_prefers_local_bin_when_on_path(env):
    local = env["home"] / ".local" / "bin"                          # does not exist yet: must be created
    r = run(env, path_dirs=[local])
    assert r.returncode == 0 and r.stdout.strip() == str(local), r.stderr
    for name in ("clue", "dfir-copilot"):
        assert os.readlink(local / name) == str(env["launcher"])


def test_falls_back_to_homebrew_bin(env):
    r = run(env, path_dirs=[env["brewbin"]])
    assert r.returncode == 0 and r.stdout.strip() == str(env["brewbin"]), r.stderr
    assert os.readlink(env["brewbin"] / "clue") == str(env["launcher"])


def test_no_directory_when_brew_fails_and_local_bin_is_off_path(env):
    r = run(env, brew_ok=False)
    assert r.returncode == 3 and "no writable directory" in r.stderr and r.stdout == ""
    assert not (env["home"] / ".local").exists()


def test_homebrew_bin_off_path_or_unwritable_is_not_used(env):
    assert run(env).returncode == 3                                  # brew bin exists but is not on PATH
    os.chmod(env["brewbin"], stat.S_IRUSR | stat.S_IXUSR)
    try:
        assert run(env, path_dirs=[env["brewbin"]]).returncode == 3  # on PATH but read-only
    finally:
        os.chmod(env["brewbin"], 0o755)


@pytest.mark.parametrize("alias", ["../evil", "a/b", "-x", ".hidden", "", "has space"])
def test_bad_aliases_are_rejected_before_anything_is_touched(env, alias):
    if alias == "":
        r = run(env, alias="", path_dirs=[env["brewbin"]])          # empty = skip the short name
        assert r.returncode == 0 and not (env["brewbin"] / "clue").exists()
        assert os.readlink(env["brewbin"] / "dfir-copilot") == str(env["launcher"])
        return
    r = run(env, alias=alias, path_dirs=[env["brewbin"]])
    assert r.returncode == 2 and "invalid alias" in r.stderr
    assert list(env["brewbin"].iterdir()) == []


def test_existing_foreign_file_is_never_overwritten(env):
    foreign = env["brewbin"] / "clue"
    foreign.write_text("#!/bin/sh\necho someone else's clue\n")
    r = run(env, path_dirs=[env["brewbin"]])
    assert r.returncode == 1 and "something else is already there" in r.stderr
    assert foreign.read_text().endswith("someone else's clue\n") and not foreign.is_symlink()
    assert os.readlink(env["brewbin"] / "dfir-copilot") == str(env["launcher"]), "the other name is still linked"


def test_foreign_symlink_is_never_overwritten(env):
    other = env["brewbin"] / "dfir-copilot"
    other.symlink_to("/usr/bin/true")
    r = run(env, path_dirs=[env["brewbin"]])
    assert r.returncode == 1 and os.readlink(other) == "/usr/bin/true"


def test_idempotent_when_our_links_already_exist(env):
    assert run(env, path_dirs=[env["brewbin"]]).returncode == 0
    r = run(env, path_dirs=[env["brewbin"]])
    assert r.returncode == 0 and r.stderr == ""


def test_relative_or_missing_launcher_is_rejected(env, tmp_path):
    r = subprocess.run(["bash", SCRIPT, "dfir-copilot", "clue"], env={"HOME": str(env["home"]), "PATH": "/usr/bin:/bin"},
                       capture_output=True, text=True)
    assert r.returncode == 2 and "absolute" in r.stderr
