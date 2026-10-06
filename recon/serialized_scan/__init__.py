"""Serialized-object detection recon module (plan §5).

Passive, deterministic, no DB, never deserializes. Flags serialized-object data
across every family as :Vulnerability candidates for the agent to confirm.
"""

from recon.serialized_scan.scanner import (
    run_serialized_scan,
    run_serialized_scan_isolated,
)

__all__ = ["run_serialized_scan", "run_serialized_scan_isolated"]
