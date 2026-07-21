"""Model routing enforcement primitives.

This package is intentionally inert until a caller wires it into a server-side
hook, command wrapper, or service. It creates no keys, starts no processes, and
does not contact hosts.
"""

__all__ = [
    "advice",
    "breakglass",
    "classifier",
    "confirmation",
    "intents",
    "kill_switch",
    "lifecycle",
    "mutation",
    "redteam",
    "registry",
    "telemetry",
]
