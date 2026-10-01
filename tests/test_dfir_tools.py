"""tools/dfir-tools.sh mounts the case directory read-only and a writable /out only when asked for."""
import os
import stat
import subprocess

import pytest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "dfir-tools.sh")


@pytest.fixture
def fake_docker(tmp_path):
    """A `docker` on PATH that accepts `info` and records the argv of `run`, one item per line."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "docker.log"
    exe = bindir / "docker"
    exe.write_text("#!/bin/sh\n"
                   f"[ \"$1\" = info ] && exit 0\n"
                   f"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > '{log}'\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    case = tmp_path / "case"
    case.mkdir()
    case = case.resolve()                   # the script mounts the physical path (pwd -P)

    def run(args, **env):
        e = {"PATH": f"{bindir}:{os.environ['PATH']}", "HOME": str(tmp_path)}
        e.update(env)
        r = subprocess.run(["bash", SCRIPT, *args], cwd=case, env=e, capture_output=True, text=True)
        argv = log.read_text().splitlines() if log.exists() else []
        return r, argv

    run.case = case
    return run


def _mounts(argv):
    return [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]


def test_evidence_is_read_only_and_nothing_else_is_mounted(fake_docker):
    r, argv = fake_docker(["vol3", "-f", "/data/mem.raw", "windows.pstree"])
    assert r.returncode == 0
    assert argv[:2] == ["run", "--rm"]
    assert _mounts(argv) == [f"{fake_docker.case}:/data:ro"]
    assert argv[-4:] == ["sk4la/volatility3:latest", "-f", "/data/mem.raw", "windows.pstree"]
    assert not (fake_docker.case / "out").exists()


@pytest.mark.parametrize("args", [
    ["plaso", "psort.py", "-o", "dynamic", "-w", "/out/timeline.csv", "/out/case.plaso"],
    ["plaso", "log2timeline.py", "--storage-file=/out/case.plaso", "/data/image.E01"],
    ["plaso", "psort.py", "--output-dir=/out"],
    ["remnux", "ls", "/out"],
])
def test_out_is_mounted_and_created_when_the_command_names_it(fake_docker, args):
    r, argv = fake_docker(args)
    assert r.returncode == 0
    out = fake_docker.case / "out"
    assert out.is_dir()
    assert _mounts(argv) == [f"{fake_docker.case}:/data:ro", f"{out}:/out"]


@pytest.mark.parametrize("args", [
    ["vol3", "-f", "/data/outlook.pst", "windows.pstree"],
    ["remnux", "cat", "/output/report"],
    ["remnux", "grep", "out", "/data/notes.txt"],
    ["remnux", "curl", "https://host/?next=/out/file"],
    ["remnux", "cat", "/data/out", "/data/out/x"],
])
def test_out_is_not_mounted_for_arguments_that_merely_contain_out(fake_docker, args):
    r, argv = fake_docker(args)
    assert r.returncode == 0
    assert _mounts(argv) == [f"{fake_docker.case}:/data:ro"]
    assert not (fake_docker.case / "out").exists()


def test_evidence_directory_is_never_mounted_writable(fake_docker, tmp_path):
    """DFIR_OUT equal to, above, or a symlink to the case directory is refused before docker runs."""
    link = tmp_path / "caselink"
    link.symlink_to(fake_docker.case)
    for bad in (str(fake_docker.case), str(tmp_path), str(link), ".", "..", "/"):
        r, argv = fake_docker(["plaso", "psort.py", "-w", "/out/t.csv"], DFIR_OUT=bad)
        assert r.returncode == 1, bad
        assert "refusing to mount" in r.stderr and "contains the evidence directory" in r.stderr
        assert argv == []


def test_a_subdirectory_of_the_evidence_directory_is_allowed(fake_docker):
    r, argv = fake_docker(["vol3", "-f", "/data/mem.raw", "windows.pstree"], DFIR_OUT="results")
    assert r.returncode == 0
    assert _mounts(argv) == [f"{fake_docker.case}:/data:ro", f"{fake_docker.case}/results:/out"]


def test_dfir_out_starting_with_a_dash_is_a_directory_not_an_option(fake_docker):
    r, argv = fake_docker(["vol3", "-f", "/data/mem.raw", "windows.pstree"], DFIR_OUT="-results")
    assert r.returncode == 0, r.stderr
    assert (fake_docker.case / "-results").is_dir()
    assert _mounts(argv) == [f"{fake_docker.case}:/data:ro", f"{fake_docker.case}/-results:/out"]


def test_dfir_out_with_spaces_stays_one_argument(fake_docker, tmp_path):
    spaced = tmp_path / "my results"
    r, argv = fake_docker(["vol3", "-f", "/data/mem.raw", "windows.pstree"], DFIR_OUT=str(spaced))
    assert r.returncode == 0
    assert spaced.is_dir()
    assert _mounts(argv) == [f"{fake_docker.case}:/data:ro", f"{spaced.resolve()}:/out"]


def test_dfir_out_symlink_is_mounted_as_its_physical_target(fake_docker, tmp_path):
    real = tmp_path / "real-out"
    real.mkdir()
    link = tmp_path / "link-out"
    link.symlink_to(real)
    r, argv = fake_docker(["vol3", "-f", "/data/mem.raw", "windows.pstree"], DFIR_OUT=str(link))
    assert r.returncode == 0
    assert _mounts(argv) == [f"{fake_docker.case}:/data:ro", f"{real.resolve()}:/out"]


def test_dfir_out_overrides_the_default_and_is_made_absolute(fake_docker, tmp_path):
    r, argv = fake_docker(["vol3", "-f", "/data/mem.raw", "windows.pstree"], DFIR_OUT="../results")
    assert r.returncode == 0
    results = (tmp_path / "results").resolve()
    assert results.is_dir()
    assert _mounts(argv) == [f"{fake_docker.case}:/data:ro", f"{results}:/out"]
    assert not (fake_docker.case / "out").exists()


def test_output_dir_that_cannot_be_created_fails_before_docker_runs(fake_docker, tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a regular file where the output directory should be\n")
    r, argv = fake_docker(["plaso", "psort.py", "-w", "/out/t.csv"], DFIR_OUT=str(blocker))
    assert r.returncode == 1
    assert "cannot create output directory" in r.stderr
    assert argv == []
