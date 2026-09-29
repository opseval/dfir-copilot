"""Central config for the DFIR co-pilot.

Importing this module FIRST sets the MLX MPI workaround defensively: some Python
distributions (notably Anaconda, which ships MPICH) abort mlx_lm with SIGABRT when
an MPI library mismatch is present. Pointing MLX at a non-existent MPI lib disables
MPI auto-load (we never use distributed), which is harmless on a clean install and
fixes the abort where it occurs. Must run before `import mlx`.
"""
import os

os.environ.setdefault("MLX_MPI_LIBNAME", "libmpi_disabled_does_not_exist.dylib")
# keep tokenizers quiet / deterministic-ish
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

# The deployable base model: untuned Granite-4.1-3B (Apache-2.0), MXFP4 (~2.6 GB).
# The campaign showed fine-tuning HURTS; we run the base model frozen + structure.
MODEL_ID = os.environ.get("DFIR_MODEL", "mlx-community/granite-4.1-3b-mxfp4")

# Best-of-N / retry knobs for the constrained query engine (the 14/17 deploy config).
BEST_OF_N = int(os.environ.get("DFIR_BEST_OF_N", "5"))
MAX_RETRIES = int(os.environ.get("DFIR_MAX_RETRIES", "3"))
SAMPLE_TEMP = float(os.environ.get("DFIR_TEMP", "0.5"))
MAX_TOKENS = int(os.environ.get("DFIR_MAX_TOKENS", "256"))
# Optional MLX RNG seed for reproducible sampled candidates (evaluation runs record it).
SEED = int(os.environ["DFIR_SEED"]) if os.environ.get("DFIR_SEED") else None

# Which backend answers `query` and `narrate`:
#   auto     (default) Apple Foundation Models first -- in-catalog questions become deterministic SQL
#            in ~3 s, narration in 2-3 s -- falling through to granite for anything else or whenever
#            Apple's model is unavailable (older macOS, Apple Intelligence off, timeout, unsure router).
#   granite  the frozen local model + per-CSV grammar only (the campaign's measured path).
#   afm      Apple only -- errors instead of falling through (for evaluation).
BACKEND = os.environ.get("DFIR_BACKEND", "auto")

# Apple Foundation Models (macOS 27+) are reached through the `fm` CLI. Pointing DFIR_FM_BIN at a
# fake lets tests and fault-injection prove the fall-through without touching the real model.
FM_BIN = os.environ.get("DFIR_FM_BIN", "/usr/bin/fm")
AFM_TIMEOUT = float(os.environ.get("DFIR_AFM_TIMEOUT", "30"))               # per generation
AFM_PROBE_TIMEOUT = float(os.environ.get("DFIR_AFM_PROBE_TIMEOUT", "10"))   # licence / availability checks
AFM_GUARDRAILS = os.environ.get("DFIR_AFM_GUARDRAILS", "permissive-content-transformations")
ROUTER_VOTES = int(os.environ.get("DFIR_ROUTER_VOTES", "2"))                 # greedy + sampled must agree
NARRATE_MAX_CHARS = int(os.environ.get("DFIR_NARRATE_MAX_CHARS", "6000"))    # raw-output budget in the narration prompt
