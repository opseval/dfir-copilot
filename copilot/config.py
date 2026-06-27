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
