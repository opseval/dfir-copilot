"""Apple Foundation Models backend (macOS 27+): the on-device system model through the `fm` CLI.

Role-scoped by design. It classifies analyst questions into closed sets (the router) and narrates
deterministic findings. It never writes SQL, never adjudicates a verdict, and is never required:
every caller falls through to the Granite path when it is unavailable, times out, or errors.

Transport: one `fm respond` subprocess per call (zero install; the upgrade path is `fm serve
--socket`). Pinned on every call: `--model system` (never Private Cloud Compute), `--use-case
general` (content-tagging scored far worse on question classification and hung), guardrails from
config, an explicit timeout, and the prompt on STDIN so analyst text can never be parsed as a flag.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

from . import config


class AFMError(RuntimeError):
    """The fm call failed (non-zero exit, an `Error:` line, malformed output, or a timeout)."""


class AFMUnavailable(AFMError):
    """The on-device model cannot be used on this Mac (no fm, licence not agreed, model unavailable)."""


_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")      # any CSI sequence (colours, cursor moves, modes)
_avail = None      # cached (ok, reason) for this process
_prov = None       # cached provenance dict


def _run(args, stdin_text=None, timeout=None):
    """Run `fm <args>` with argv (never a shell), capture text, strip ANSI. Returns (rc, out, err)."""
    env = dict(os.environ, NO_COLOR="1", TERM="dumb")
    try:
        p = subprocess.run([config.FM_BIN, *args], input=stdin_text if stdin_text is not None else "",
                           capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout or config.AFM_TIMEOUT, env=env, shell=False)
    except FileNotFoundError:
        raise AFMUnavailable(f"{config.FM_BIN} not found (Apple Foundation Models need macOS 27+)")
    except subprocess.TimeoutExpired:
        raise AFMError(f"fm {args[0]} timed out after {timeout or config.AFM_TIMEOUT:g}s")
    except OSError as e:
        raise AFMUnavailable(f"cannot run {config.FM_BIN}: {e}")
    return p.returncode, _ANSI.sub("", p.stdout), _ANSI.sub("", p.stderr)


def _error_line(*streams):
    for s in streams:
        for line in s.splitlines():
            if line.lstrip().startswith("Error:"):
                return line.strip()
    return None


def available(refresh=False):
    """(ok, reason). Licence first -- an unagreed licence can prompt interactively, and a timeout
    must never be mistaken for 'model unavailable'. Cached per process."""
    global _avail
    if _avail is not None and not refresh:
        return _avail
    try:
        rc, out, err = _run(["license", "--status"], timeout=config.AFM_PROBE_TIMEOUT)
        if rc != 0 or not out.strip().startswith("Agreed"):
            _avail = (False, "fm licence not agreed on this Mac -- run `fm license` once")
            return _avail
        rc, out, err = _run(["available", "--model", "system"], timeout=config.AFM_PROBE_TIMEOUT)
        bad = _error_line(out, err)
        text = (out.strip() or err.strip()).splitlines()
        first = bad or (text[0] if text else f"fm available exited {rc}")
        low = first.lower()
        ok = rc == 0 and not bad and "available" in low and "unavailable" not in low and "not available" not in low
        _avail = (ok, first)
    except AFMError as e:
        _avail = (False, str(e))
    return _avail


def respond(instructions, prompt, schema=None, greedy=True, timeout=None):
    """One on-device generation. Returns the text, or a dict when `schema` (a JSON schema in the
    `fm schema object` shape) is given. Raises AFMUnavailable / AFMError -- callers fall through."""
    ok, reason = available()
    if not ok:
        raise AFMUnavailable(reason)
    args = ["respond", "--model", "system", "--no-stream", "--use-case", "general",
            "--guardrails", config.AFM_GUARDRAILS, "--instructions", instructions]
    if greedy:
        args.append("--greedy")
    tmp = None
    try:
        if schema is not None:
            tmp = tempfile.NamedTemporaryFile("w", suffix=".json", prefix="dfir-schema-", delete=False)
            json.dump(schema, tmp)
            tmp.close()
            args += ["--schema", tmp.name]
        rc, out, err = _run(args, stdin_text=prompt, timeout=timeout)
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp.name)
            except FileNotFoundError:
                pass
            except OSError as e:
                sys.stderr.write(f"[afm] could not remove temp schema {tmp.name}: {e}\n")
    bad = _error_line(out, err)
    if rc != 0 or bad:
        raise AFMError(bad or f"fm respond exited {rc}: {(err.strip() or out.strip())[:200]}")
    text = out.strip()
    if not text:
        raise AFMError("fm respond produced no output")
    if schema is None:
        return text
    try:
        obj = json.loads(text)
    except ValueError:
        raise AFMError(f"fm returned non-JSON for a schema request: {text[:120]!r}")
    if not isinstance(obj, dict):
        raise AFMError("fm returned JSON that is not an object")
    return obj


def provenance():
    """What answered: the OS build stands in for a model version (Apple exposes none; the model
    changes with OS updates, so every answer records it)."""
    global _prov
    if _prov is None:
        parts = []
        for flag in ("-productVersion", "-buildVersion"):
            try:
                p = subprocess.run(["/usr/bin/sw_vers", flag], capture_output=True, text=True, timeout=5)
                parts.append(p.stdout.strip() or "?")
            except (OSError, subprocess.TimeoutExpired):
                parts.append("?")
        _prov = {"backend": "afm", "model": "system", "macos": f"{parts[0]} ({parts[1]})"}
    return dict(_prov)
