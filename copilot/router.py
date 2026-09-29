"""Question router: one closed-set classification by the on-device Apple model, validated by the
catalog and confirmed by a second vote. It returns (Route, None) or (None, reason) -- never an
exception -- so the caller's only decision is "catalog path" or "Granite path", and the reason a
question was declined travels with it.

At least two sequential votes (greedy, then sampled) must validate and agree after normalization. The
model is shown the FULL catalog, so it can name the filter the analyst asked for; if that filter's
words do not occur in this artifact the plan is rejected and Granite answers -- the model is never
steered into a different, present filter that would silently answer a different question.
"""
from dataclasses import dataclass

from . import afm, catalog, config

MIN_VOTES = 2
INSTRUCTIONS = (
    "You classify a forensic analyst's question about an OpenSSH / Linux authentication log into a "
    "query intent. Pick the event_filter, extract_field and aggregate that together answer the question. "
    "Choose all_events when the question does not name a kind of event (e.g. 'most events overall', "
    "'total events'). When the question asks WHICH value (an IP address, a username, ...) is most common, "
    "appears most often, or is responsible for the most events, the aggregate is "
    "most_frequent_value_and_count and extract_field is that value; 'how many distinct / different X' is "
    "count_distinct_values with extract_field X; a plain 'how many events / lines' is count_rows with "
    "extract_field none."
)


@dataclass(frozen=True)
class Route:
    plan: dict
    provenance: dict
    votes: int


def route(question, family, present=None, ipv6=False):
    """(Route, None) or (None, reason). `present` is the set of event filters whose words occur in
    the artifact (family.present_filters); a plan naming any other filter is declined. `ipv6` says
    the artifact carries IPv6 addresses, which the catalog's IPv4-only extractors would silently
    miss, so IP extractions are declined for it."""
    if family != catalog.FAMILY:
        return None, f"no intent catalog for family {family!r}"
    ok, reason = afm.available()
    if not ok:
        return None, f"Apple model unavailable: {reason}"
    schema = catalog.build_schema(family)
    plans = []
    for i in range(max(MIN_VOTES, config.ROUTER_VOTES)):
        try:
            raw = afm.respond(INSTRUCTIONS, question, schema=schema, greedy=(i == 0))
        except afm.AFMError as e:
            return None, f"Apple model call failed: {e}"
        plan, why = catalog.validate(raw, question)
        if plan is None:
            return None, f"invalid plan: {why}"
        if present is not None and plan["event_filter"] not in present:
            return None, f"the artifact contains no '{plan['event_filter']}' lines"
        if ipv6 and plan["extract_field"] in ("source_ip", "pam_rhost_ip"):
            return None, "the artifact carries IPv6 addresses, which the catalog's IPv4 extractors would miss"
        plans.append(plan)
    if any(p != plans[0] for p in plans[1:]):
        return None, "router votes disagreed"
    return Route(plan=plans[0], provenance=afm.provenance(), votes=len(plans)), None
