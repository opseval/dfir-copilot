"""DFIR co-pilot: an untuned small local model made reliable by a deterministic structure
stack. The model drafts queries and narrates; the harness owns correctness; the analyst
approves. See README.md for the design rationale and the evidence behind it.
"""
from . import config  # noqa: F401  -- import first to set the MLX env workaround

__all__ = ["config", "query_engine", "interp_engine", "schema"]
__version__ = "1.0.0"
