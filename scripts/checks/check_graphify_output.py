#!/usr/bin/env python3
"""Validate that a Graphify code-only run produced a non-empty NetworkX node-link graph."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "graphify-out/graph.json")
    if not path.is_file():
        print(f"ERROR: missing Graphify output: {path}", file=sys.stderr)
        return 1
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: invalid Graphify JSON: {exc}", file=sys.stderr)
        return 1

    if not isinstance(payload, dict):
        print("ERROR: Graphify graph must be a JSON object", file=sys.stderr)
        return 1
    nodes = payload.get("nodes")
    edges = payload.get("links", payload.get("edges"))
    if not isinstance(nodes, list) or not nodes:
        print("ERROR: Graphify graph contains no nodes", file=sys.stderr)
        return 1
    if not isinstance(edges, list) or not edges:
        print("ERROR: Graphify graph contains no edges", file=sys.stderr)
        return 1
    if any(not isinstance(node, dict) or not node.get("id") for node in nodes):
        print("ERROR: Graphify graph contains a node without an id", file=sys.stderr)
        return 1
    node_ids = [node["id"] for node in nodes]
    if len(set(node_ids)) != len(node_ids):
        print("ERROR: Graphify graph contains duplicate node ids", file=sys.stderr)
        return 1
    node_id_set = set(node_ids)
    for edge in edges:
        if not isinstance(edge, dict) or "source" not in edge or "target" not in edge:
            print("ERROR: Graphify graph contains an invalid edge", file=sys.stderr)
            return 1
        if edge["source"] not in node_id_set or edge["target"] not in node_id_set:
            print("ERROR: Graphify graph contains a dangling edge", file=sys.stderr)
            return 1

    sources = {
        node.get("source_file")
        for node in nodes
        if isinstance(node.get("source_file"), str) and node.get("source_file")
    }
    print(f"graphify-output nodes={len(nodes)} edges={len(edges)} source_files={len(sources)} errors=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
