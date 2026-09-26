"""Provenance graph (Step 5, part A).

Turns fused event records into a "who touched what" graph:
nodes = agent runs, processes, files, network endpoints, tools;
edges  = read / write / exec / connect / send / call actions.

Every edge carries WHERE the observation came from (sensor and its
declared privilege) and HOW WELL the actor identity is resolved
(identity_source + confidence). The graph is the shared substrate for
the rule engine and the human-readable report: a finding can always
point at concrete nodes and edges instead of prose.

Node ids are stable strings: run:<id>, pid:<n>, file:<path>,
endpoint:<ip:port>, tool:<name>.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.fusion import ts_to_epoch

NODE_KINDS = {"run", "process", "file", "endpoint", "tool"}


@dataclass
class Node:
    id: str
    kind: str
    label: str
    classification: str | None = None


@dataclass
class Edge:
    src: str
    dst: str
    verb: str
    ts_epoch: float
    event_id: str
    sensor: str
    sensor_privilege: str
    identity_source: str
    confidence: float | None


class ProvenanceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        if node.classification and not existing.classification:
            existing.classification = node.classification
        return existing

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def edges_from(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.src == node_id]

    def edges_to(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.dst == node_id]

    def node(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    def stats(self) -> dict:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "by_kind": {
                k: sum(1 for n in self.nodes.values() if n.kind == k)
                for k in NODE_KINDS
            },
        }


def _actor_node_ids(rec: dict) -> list[str]:
    actor = rec.get("actor", {})
    ids = []
    run_id = actor.get("agent_run_id")
    if run_id:
        ids.append(f"run:{run_id}")
    ids.append(f"pid:{actor.get('pid')}")
    return ids


def build_graph(records: list[dict]) -> ProvenanceGraph:
    g = ProvenanceGraph()

    # Pre-pass: net.egress (SEND) records carry no destination; attach
    # each to the most recent net.connect of the SAME PROCESS INSTANCE
    # (R21: (pid, pid_start_ts), never pid alone) or the SAME RUN.
    # Sends with an unconfirmable process identity stay unattached.
    by_instance: dict[tuple, str] = {}
    by_run: dict[str, str] = {}
    send_endpoint: dict[str, str] = {}  # event_id -> endpoint
    for rec in records:
        actor = rec.get("actor", {})
        if rec.get("event_type") == "net.connect":
            peer = rec.get("peer") or {}
            endpoint = peer.get("id", "")
            key = (actor.get("pid"), actor.get("pid_start_ts"))
            if None not in key:
                by_instance[key] = endpoint
            run = actor.get("agent_run_id")
            if run:
                by_run[run] = endpoint
        elif rec.get("event_type") == "net.egress":
            key = (actor.get("pid"), actor.get("pid_start_ts"))
            endpoint = ""
            if None not in key:
                endpoint = by_instance.get(key, "")
            if not endpoint:
                run = actor.get("agent_run_id")
                if run:
                    endpoint = by_run.get(run, "")
            if endpoint:
                send_endpoint[rec.get("event_id", "")] = endpoint

    for rec in records:
        actor = rec.get("actor", {})
        sensor = rec.get("sensor", "")
        priv = rec.get("sensor_privilege", "")
        idsrc = actor.get("identity_source", "UNKNOWN")
        conf = actor.get("identity_confidence")
        ts = ts_to_epoch(rec.get("ts_wall", "")) or 0.0
        actor_ids = _actor_node_ids(rec)
        et = rec.get("event_type", "")

        if et == "sensor.health":
            continue  # telemetry, not a behavior edge

        for nid in actor_ids:
            g.add_node(Node(nid, "run" if nid.startswith("run:") else "process",
                            nid.split(":", 1)[1]))

        if et == "process.exec":
            for ent in rec.get("entities") or []:
                child = f"pid:{actor.get('pid')}"
                g.add_node(Node(child, "process", str(actor.get("pid"))))
                for nid in actor_ids:
                    if nid != child:
                        g.add_edge(Edge(nid, child, "exec", ts,
                                        rec["event_id"], sensor, priv,
                                        idsrc, conf))

        for ent in rec.get("entities") or []:
            kind = ent.get("kind")
            eid = ent.get("id", "")
            if kind == "file":
                nid = g.add_node(Node(f"file:{eid}", "file", eid,
                                      ent.get("classification"))).id
                verb = rec.get("action", {}).get("verb", "read")
                for aid in actor_ids:
                    g.add_edge(Edge(aid, nid, verb, ts, rec["event_id"],
                                    sensor, priv, idsrc, conf))
            elif kind == "tool":
                nid = g.add_node(Node(f"tool:{eid}", "tool", eid)).id
                for aid in actor_ids:
                    g.add_edge(Edge(aid, nid, rec.get("action", {}).get("verb", "call"),
                                    ts, rec["event_id"], sensor, priv, idsrc, conf))
            else:
                # claims and other abstract objects become nodes too,
                # so "agent said X" is a first-class graph citizen
                nid = g.add_node(Node(f"{kind or 'object'}:{eid}", "object",
                                      eid)).id
                for aid in actor_ids:
                    g.add_edge(Edge(aid, nid, rec.get("action", {}).get("verb", "relate"),
                                    ts, rec["event_id"], sensor, priv, idsrc, conf))

        peer = rec.get("peer")
        if peer and peer.get("id"):
            nid = g.add_node(Node(f"endpoint:{peer['id']}", "endpoint",
                                  peer["id"])).id
            for aid in actor_ids:
                g.add_edge(Edge(aid, nid, rec.get("action", {}).get("verb", "net"),
                                ts, rec["event_id"], sensor, priv, idsrc, conf))
        elif rec.get("event_type") == "net.egress":
            endpoint = send_endpoint.get(rec.get("event_id", ""), "")
            if endpoint:
                nid = g.add_node(Node(f"endpoint:{endpoint}", "endpoint",
                                      endpoint)).id
                for aid in actor_ids:
                    g.add_edge(Edge(aid, nid, "send", ts, rec["event_id"],
                                    sensor, priv, idsrc, conf))

    return g
