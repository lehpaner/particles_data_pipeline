"""
Workflow Engine — Directed Graph Execution
==========================================

A workflow is a directed graph where each node is an Action and each
directed edge is a Transition with an optional condition.

Graph structure (stored in DB as JSON):
    {
      "nodes": {
        "start_pump":   {"type": "start_pump",   "params": {},                      "label": "Avvia pompa"},
        "wait_warmup":  {"type": "wait",          "params": {"seconds": 30},         "label": "Riscaldamento 30s"},
        "measure":      {"type": "start_manual",  "params": {},                      "label": "Campionamento"},
        "wait_sample":  {"type": "wait",          "params": {"seconds": 60},         "label": "Campiona 60s"},
        "stop_measure": {"type": "stop_manual",   "params": {},                      "label": "Stop misura"},
        "sync_db":      {"type": "sync_records",  "params": {"max_records": 10},     "label": "Scarica record"},
        "stop_pump":    {"type": "stop_pump",     "params": {},                      "label": "Ferma pompa"},
        "done":         {"type": "end",           "params": {},                      "label": "Fine"}
      },
      "edges": [
        {"from": "start_pump",   "to": "wait_warmup",  "condition": "always"},
        {"from": "wait_warmup",  "to": "measure",       "condition": "always"},
        {"from": "measure",      "to": "wait_sample",   "condition": "always"},
        {"from": "wait_sample",  "to": "stop_measure",  "condition": "always"},
        {"from": "stop_measure", "to": "sync_db",       "condition": "always"},
        {"from": "sync_db",      "to": "stop_pump",     "condition": "always"},
        {"from": "stop_pump",    "to": "done",          "condition": "always"},
        {"from": "measure",      "to": "stop_pump",     "condition": "on_error"},
        {"from": "wait_sample",  "to": "stop_pump",     "condition": "on_error"}
      ],
      "entry": "start_pump"
    }

Condition types:
    "always"         → always follow this edge (default next step)
    "on_error"       → follow only if previous node raised an error
    "on_success"     → follow only if previous node succeeded
    "on_status:<v>"  → follow if device.status.state == v  (e.g. "on_status:stopped")

Action node types:
    start_pump       → TSIClient.start_pump()
    stop_pump        → TSIClient.stop_pump()
    start_manual     → TSIClient.start_manual()
    stop_manual      → TSIClient.stop_manual()
    start_auto       → TSIClient.start_auto()
    stop_auto        → TSIClient.stop_auto()
    stop_any         → TSIClient.stop_measurement()
    sync_records     → read new records from device and save to DB
                       params: max_records (int, default 50)
    wait             → sleep N seconds
                       params: seconds (int)
    check_status     → read device status, store in context["status"]
    purge            → TSIClient.purge_start()
    sync_clock       → TSIClient.sync_clock()
    disable_local    → TSIClient.disable_local_control()
    enable_local     → TSIClient.enable_local_control()
    silence          → TSIClient.silence()
    unsilence        → TSIClient.unsilence()
    end              → terminates the workflow (success)
    fail             → terminates the workflow (failure)
    log_event        → writes a message to run log
                       params: message (str)

Execution context dict passed between nodes:
    {
      "device_id":   int,
      "ip":          str,
      "port":        int,
      "status":      dict | None,      # last read_status() result
      "records_new": int,              # records fetched in last sync_records
      "error":       str | None,       # last error message
      "ok":          bool,             # last node success flag
      "log":         list[str],        # timestamped event log
      "started_at":  str,
      "node_trace":  list[str],        # execution path (node ids)
    }
"""

import json
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger("workflow")


# ─── Graph data classes ───────────────────────────────────────────────────────

@dataclass
class Node:
    id: str
    type: str
    params: dict = field(default_factory=dict)
    label: str = ""


@dataclass
class Edge:
    from_node: str
    to_node: str
    condition: str = "always"   # always | on_error | on_success | on_status:<val>


@dataclass
class WorkflowGraph:
    nodes: dict[str, Node]        # node_id → Node
    edges: list[Edge]
    entry: str                    # id of the first node

    # adjacency: node_id → list[Edge]
    _adj: dict[str, list[Edge]] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self):
        self._adj = {}
        for e in self.edges:
            self._adj.setdefault(e.from_node, []).append(e)

    def next_node(self, current_id: str, ctx: dict) -> Optional[str]:
        """
        Choose the next node from current_id given the execution context.
        Priority: on_error / on_success edges first, then always edges.
        Returns None when no matching edge exists (graph ends here).
        """
        candidates = self._adj.get(current_id, [])
        ok   = ctx.get("ok", True)
        err  = not ok

        # evaluate specific conditions first
        for e in candidates:
            c = e.condition
            if c == "on_error"   and err:   return e.to_node
            if c == "on_success" and ok:     return e.to_node
            if c.startswith("on_status:"):
                expected = c.split(":", 1)[1]
                status = (ctx.get("status") or {}).get("state", "")
                if status == expected:
                    return e.to_node

        # fallback: first "always" edge
        for e in candidates:
            if e.condition == "always":
                return e.to_node

        return None

    @staticmethod
    def from_dict(d: dict) -> "WorkflowGraph":
        nodes = {
            nid: Node(
                id=nid,
                type=nd["type"],
                params=nd.get("params", {}),
                label=nd.get("label", nid),
            )
            for nid, nd in d["nodes"].items()
        }
        edges = [
            Edge(
                from_node=e["from"],
                to_node=e["to"],
                condition=e.get("condition", "always"),
            )
            for e in d["edges"]
        ]
        return WorkflowGraph(nodes=nodes, edges=edges, entry=d["entry"])

    def to_dict(self) -> dict:
        return {
            "nodes": {
                nid: {"type": n.type, "params": n.params, "label": n.label}
                for nid, n in self.nodes.items()
            },
            "edges": [
                {"from": e.from_node, "to": e.to_node, "condition": e.condition}
                for e in self.edges
            ],
            "entry": self.entry,
        }

    def validate(self) -> list[str]:
        """Return list of validation errors (empty = OK)."""
        errors = []
        if self.entry not in self.nodes:
            errors.append(f"entry node '{self.entry}' not in nodes")
        for e in self.edges:
            if e.from_node not in self.nodes:
                errors.append(f"edge from unknown node '{e.from_node}'")
            if e.to_node not in self.nodes:
                errors.append(f"edge to unknown node '{e.to_node}'")
        valid_conditions = {"always", "on_error", "on_success"}
        for e in self.edges:
            if e.condition not in valid_conditions and not e.condition.startswith("on_status:"):
                errors.append(f"unknown condition '{e.condition}' on edge {e.from_node}→{e.to_node}")
        valid_types = {
            "start_pump", "stop_pump", "start_manual", "stop_manual",
            "start_auto", "stop_auto", "stop_any", "sync_records",
            "wait", "check_status", "purge", "sync_clock",
            "disable_local", "enable_local", "silence", "unsilence",
            "end", "fail", "log_event",
        }
        for nid, n in self.nodes.items():
            if n.type not in valid_types:
                errors.append(f"node '{nid}' has unknown type '{n.type}'")
        return errors


# ─── Node executor ────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def execute_node(node: Node, ctx: dict, client) -> dict:
    """
    Execute a single node action.
    Updates ctx in-place with result fields.
    Returns ctx.
    client is a connected TSIClient (or None for wait/log_event/end/fail nodes).
    """
    ntype = node.type
    params = node.params
    ctx["ok"] = True
    ctx["error"] = None

    def _log(msg: str):
        entry = f"[{_ts()}] [{node.id}] {msg}"
        ctx["log"].append(entry)
        log.info(entry)

    try:
        if ntype == "end":
            _log("Workflow completed successfully")
            ctx["outcome"] = "success"

        elif ntype == "fail":
            _log("Workflow failed (explicit fail node)")
            ctx["outcome"] = "failure"
            ctx["ok"] = False

        elif ntype == "log_event":
            _log(params.get("message", "(no message)"))

        elif ntype == "wait":
            secs = int(params.get("seconds", 1))
            _log(f"Waiting {secs}s …")
            time.sleep(secs)
            _log(f"Wait done")

        elif ntype == "check_status":
            _log("Reading device status …")
            ctx["status"] = client.read_status()
            _log(f"Status: {ctx['status']['state']}")

        elif ntype == "start_pump":
            _log("CMD: start_pump")
            ok = client.start_pump()
            if not ok:
                raise RuntimeError("start_pump returned False")
            _log("Pump started")

        elif ntype == "stop_pump":
            _log("CMD: stop_pump")
            client.stop_pump()
            _log("Pump stopped")

        elif ntype == "start_manual":
            _log("CMD: start_manual")
            ok = client.start_manual()
            if not ok:
                raise RuntimeError("start_manual returned False")
            _log("Manual measurement started")

        elif ntype == "stop_manual":
            _log("CMD: stop_manual")
            client.stop_manual()
            _log("Manual measurement stopped")

        elif ntype == "start_auto":
            _log("CMD: start_auto")
            ok = client.start_auto()
            if not ok:
                raise RuntimeError("start_auto returned False")
            _log("Auto cycle started")

        elif ntype == "stop_auto":
            _log("CMD: stop_auto")
            client.stop_auto()
            _log("Auto cycle stopped")

        elif ntype == "stop_any":
            _log("CMD: stop_any (manual+auto)")
            client.stop_measurement()
            _log("Measurement stopped")

        elif ntype == "sync_records":
            from tsi_modbus import TSIClient
            from database import save_device_data, db_session, get_device, DB_PATH
            max_rec = int(params.get("max_records", 50))
            _log(f"Syncing up to {max_rec} records from device …")

            # Re-use existing client connection to read records
            device_id = ctx["device_id"]
            with db_session(DB_PATH) as conn:
                dev_row = get_device(conn, device_id)

            num_on_device = client.read_num_samples()
            num_channels  = dev_row["num_channels"] if dev_row else 8
            has_di        = bool(dev_row["has_data_integrity"]) if dev_row else False

            # read only the last max_rec records
            start_idx = max(0, num_on_device - max_rec)
            new_count = 0
            from database import insert_record, upsert_device
            from tsi_modbus import TSIDevice
            dummy_dev = TSIDevice(
                ip=ctx["ip"], port=ctx["port"],
                num_channels=num_channels,
                has_data_integrity=has_di,
            )
            with db_session(DB_PATH) as conn:
                dev_id = upsert_device(conn, dummy_dev)
                for i in range(start_idx, num_on_device):
                    rec = client.read_record(i, num_channels, has_di)
                    if rec:
                        rid = insert_record(conn, dev_id, rec)
                        if rid is not None:
                            new_count += 1

            ctx["records_new"] = new_count
            _log(f"Sync done: {new_count} new records saved")

        elif ntype == "purge":
            _log("CMD: purge_start")
            client.purge_start()
            _log("Purge started")

        elif ntype == "sync_clock":
            _log("CMD: sync_clock")
            client.sync_clock()
            _log("Clock synchronized")

        elif ntype == "disable_local":
            _log("CMD: disable_local_control")
            client.disable_local_control()

        elif ntype == "enable_local":
            _log("CMD: enable_local_control")
            client.enable_local_control()

        elif ntype == "silence":
            _log("CMD: silence")
            client.silence()

        elif ntype == "unsilence":
            _log("CMD: unsilence")
            client.unsilence()

        else:
            raise ValueError(f"Unknown node type: {ntype}")

    except Exception as exc:
        ctx["ok"] = False
        ctx["error"] = str(exc)
        _log(f"ERROR: {exc}")

    return ctx


# ─── Graph runner ─────────────────────────────────────────────────────────────

def run_workflow(graph: WorkflowGraph, ctx: dict, client) -> dict:
    """
    Walk the directed graph from the entry node until an end/fail node or
    no more outgoing edges. Returns the final ctx dict.

    ctx must be pre-populated with at least:
        device_id, ip, port, log (list), started_at
    """
    current_id = graph.entry
    ctx.setdefault("node_trace", [])
    ctx.setdefault("outcome", "unknown")
    ctx.setdefault("records_new", 0)
    ctx.setdefault("status", None)
    ctx.setdefault("ok", True)
    ctx.setdefault("error", None)

    max_steps = 200   # safety circuit-breaker against infinite loops
    steps = 0

    while current_id is not None and steps < max_steps:
        node = graph.nodes.get(current_id)
        if node is None:
            ctx["log"].append(f"[{_ts()}] ERROR: node '{current_id}' not found in graph")
            ctx["ok"] = False
            ctx["outcome"] = "failure"
            break

        ctx["node_trace"].append(current_id)
        steps += 1

        execute_node(node, ctx, client)

        # terminal nodes
        if node.type in ("end", "fail"):
            break

        current_id = graph.next_node(current_id, ctx)

    if steps >= max_steps:
        ctx["log"].append(f"[{_ts()}] Safety stop: reached {max_steps} steps limit")
        ctx["outcome"] = "failure"
        ctx["ok"] = False

    ctx["finished_at"] = datetime.now(timezone.utc).isoformat()
    return ctx


# ─── Built-in workflow templates ──────────────────────────────────────────────

TEMPLATES: dict[str, dict] = {
    "manual_sample_60s": {
        "description": "Pump warm-up 30s → manual measurement 60s → sync last 10 records",
        "graph": {
            "entry": "disable_local",
            "nodes": {
                "disable_local": {"type": "disable_local", "label": "Blocca display"},
                "start_pump":    {"type": "start_pump",    "label": "Avvia pompa"},
                "warmup":        {"type": "wait",          "params": {"seconds": 30}, "label": "Preriscaldamento 30s"},
                "measure":       {"type": "start_manual",  "label": "Avvia misura"},
                "sample_time":   {"type": "wait",          "params": {"seconds": 60}, "label": "Campiona 60s"},
                "stop_measure":  {"type": "stop_manual",   "label": "Ferma misura"},
                "sync":          {"type": "sync_records",  "params": {"max_records": 10}, "label": "Scarica record"},
                "stop_pump":     {"type": "stop_pump",     "label": "Ferma pompa"},
                "enable_local":  {"type": "enable_local",  "label": "Riabilita display"},
                "done":          {"type": "end",           "label": "Fine"},
                "err_stop":      {"type": "stop_any",      "label": "Stop d'emergenza"},
                "err_pump":      {"type": "stop_pump",     "label": "Ferma pompa (err)"},
                "err_local":     {"type": "enable_local",  "label": "Riabilita display (err)"},
                "failed":        {"type": "fail",          "label": "Fallito"},
            },
            "edges": [
                {"from": "disable_local", "to": "start_pump",   "condition": "always"},
                {"from": "start_pump",    "to": "warmup",        "condition": "on_success"},
                {"from": "start_pump",    "to": "err_local",     "condition": "on_error"},
                {"from": "warmup",        "to": "measure",       "condition": "always"},
                {"from": "measure",       "to": "sample_time",   "condition": "on_success"},
                {"from": "measure",       "to": "err_stop",      "condition": "on_error"},
                {"from": "sample_time",   "to": "stop_measure",  "condition": "always"},
                {"from": "stop_measure",  "to": "sync",          "condition": "always"},
                {"from": "sync",          "to": "stop_pump",     "condition": "always"},
                {"from": "stop_pump",     "to": "enable_local",  "condition": "always"},
                {"from": "enable_local",  "to": "done",          "condition": "always"},
                {"from": "err_stop",      "to": "err_pump",      "condition": "always"},
                {"from": "err_pump",      "to": "err_local",     "condition": "always"},
                {"from": "err_local",     "to": "failed",        "condition": "always"},
            ],
        }
    },

    "auto_cycle_sync": {
        "description": "Auto cycle (recipe) → wait for stop → sync records",
        "graph": {
            "entry": "disable_local",
            "nodes": {
                "disable_local": {"type": "disable_local", "label": "Blocca display"},
                "start_auto":    {"type": "start_auto",    "label": "Avvia ciclo auto"},
                "wait_cycle":    {"type": "wait",          "params": {"seconds": 120}, "label": "Attendi ciclo 120s"},
                "stop_auto":     {"type": "stop_auto",     "label": "Stop ciclo auto"},
                "sync":          {"type": "sync_records",  "params": {"max_records": 20}, "label": "Scarica record"},
                "enable_local":  {"type": "enable_local",  "label": "Riabilita display"},
                "done":          {"type": "end",           "label": "Fine"},
                "err_stop":      {"type": "stop_any",      "label": "Stop d'emergenza"},
                "err_local":     {"type": "enable_local",  "label": "Riabilita display (err)"},
                "failed":        {"type": "fail",          "label": "Fallito"},
            },
            "edges": [
                {"from": "disable_local", "to": "start_auto",   "condition": "always"},
                {"from": "start_auto",    "to": "wait_cycle",    "condition": "on_success"},
                {"from": "start_auto",    "to": "err_local",     "condition": "on_error"},
                {"from": "wait_cycle",    "to": "stop_auto",     "condition": "always"},
                {"from": "stop_auto",     "to": "sync",          "condition": "always"},
                {"from": "sync",          "to": "enable_local",  "condition": "always"},
                {"from": "enable_local",  "to": "done",          "condition": "always"},
                {"from": "err_stop",      "to": "err_local",     "condition": "always"},
                {"from": "err_local",     "to": "failed",        "condition": "always"},
            ],
        }
    },

    "purge_and_sample": {
        "description": "Optical purge 60s → manual sample 60s → sync",
        "graph": {
            "entry": "disable_local",
            "nodes": {
                "disable_local": {"type": "disable_local", "label": "Blocca display"},
                "purge":         {"type": "purge",         "label": "Pulizia ottica"},
                "purge_wait":    {"type": "wait",          "params": {"seconds": 60}, "label": "Attendi purge 60s"},
                "start_pump":    {"type": "start_pump",    "label": "Avvia pompa"},
                "warmup":        {"type": "wait",          "params": {"seconds": 15}, "label": "Stabilizzazione 15s"},
                "measure":       {"type": "start_manual",  "label": "Avvia misura"},
                "sample_time":   {"type": "wait",          "params": {"seconds": 60}, "label": "Campiona 60s"},
                "stop_measure":  {"type": "stop_manual",   "label": "Ferma misura"},
                "sync":          {"type": "sync_records",  "params": {"max_records": 5}, "label": "Scarica record"},
                "stop_pump":     {"type": "stop_pump",     "label": "Ferma pompa"},
                "enable_local":  {"type": "enable_local",  "label": "Riabilita display"},
                "done":          {"type": "end",           "label": "Fine"},
                "err_cleanup":   {"type": "stop_any",      "label": "Stop d'emergenza"},
                "err_pump":      {"type": "stop_pump",     "label": "Ferma pompa (err)"},
                "err_local":     {"type": "enable_local",  "label": "Riabilita display (err)"},
                "failed":        {"type": "fail",          "label": "Fallito"},
            },
            "edges": [
                {"from": "disable_local", "to": "purge",         "condition": "always"},
                {"from": "purge",         "to": "purge_wait",    "condition": "always"},
                {"from": "purge_wait",    "to": "start_pump",    "condition": "always"},
                {"from": "start_pump",    "to": "warmup",        "condition": "on_success"},
                {"from": "start_pump",    "to": "err_local",     "condition": "on_error"},
                {"from": "warmup",        "to": "measure",       "condition": "always"},
                {"from": "measure",       "to": "sample_time",   "condition": "on_success"},
                {"from": "measure",       "to": "err_cleanup",   "condition": "on_error"},
                {"from": "sample_time",   "to": "stop_measure",  "condition": "always"},
                {"from": "stop_measure",  "to": "sync",          "condition": "always"},
                {"from": "sync",          "to": "stop_pump",     "condition": "always"},
                {"from": "stop_pump",     "to": "enable_local",  "condition": "always"},
                {"from": "enable_local",  "to": "done",          "condition": "always"},
                {"from": "err_cleanup",   "to": "err_pump",      "condition": "always"},
                {"from": "err_pump",      "to": "err_local",     "condition": "always"},
                {"from": "err_local",     "to": "failed",        "condition": "always"},
            ],
        }
    },

    "status_check_only": {
        "description": "Read device status only, no measurement",
        "graph": {
            "entry": "check",
            "nodes": {
                "check": {"type": "check_status", "label": "Leggi stato"},
                "done":  {"type": "end",          "label": "Fine"},
            },
            "edges": [
                {"from": "check", "to": "done", "condition": "always"},
            ],
        }
    },
}
