import {
  ReactFlow,
  Background,
  Controls,
  Position,
  type Node,
  type Edge,
} from "@xyflow/react";
import type { Status } from "./types";
import "@xyflow/react/dist/style.css";
export function Architecture({
  status,
  onSelect,
  theme,
}: {
  status: Status | null;
  onSelect: (s: string) => void;
  theme: "light" | "dark";
}) {
  const worker = (name: string) =>
    status?.workers?.find((w) => w.name === name);
  const active = (name: string) =>
    ["running", "scanning", "exporting"].includes(worker(name)?.state || "") &&
    !worker(name)?.stale;
  const specs = [
    ["cve-upstream", "CVE List repository", 0, 0],
    ["nvd-upstream", "NVD API", 0, 150],
    ["cve", "CVE synchronization", 270, 0],
    ["nvd", "NVD synchronization", 270, 150],
    ["database", "PostgreSQL intelligence", 540, 75],
    ["scheduler", "Project schedules", 0, 360],
    ["queue", "Report job queue", 270, 360],
    ["report-worker", "Scan → export", 540, 360],
    ["storage", "Project reports", 810, 360],
  ];
  const nodes: Node[] = specs.map(([id, label, x, y]) => ({
    id: String(id),
    position: { x: Number(x), y: Number(y) },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    data: {
      label: (
        <div>
          <small>
            {String(id).includes("upstream")
              ? "UPSTREAM"
              : worker(String(id))?.stale
                ? "STALE"
                : worker(String(id))?.state?.toUpperCase() || "MODULE"}
          </small>
          <strong>{label}</strong>
        </div>
      ),
    },
    className: active(String(id)) ? "node-active" : "",
  }));
  const links = [
    ["cve-upstream", "cve", "cve"],
    ["nvd-upstream", "nvd", "nvd"],
    ["cve", "database", "cve"],
    ["nvd", "database", "nvd"],
    ["scheduler", "queue", "scheduler"],
    ["queue", "report-worker", "report-worker"],
    ["database", "report-worker", "report-worker"],
    ["report-worker", "storage", "report-worker"],
  ];
  const edges: Edge[] = links.map(([source, target, name]) => ({
    id: source + target,
    source,
    target,
    animated: active(name),
    style: { stroke: active(name) ? "#59dfcb" : "#52606d" },
    type: "smoothstep",
  }));
  return (
    <div className="architecture">
      <div className="diagram-caption">
        <span>SOURCE SYNCHRONIZATION</span>
        <small>Click a module to inspect its settings</small>
      </div>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        nodesDraggable={false}
        nodesConnectable={false}
        onNodeClick={(_, n) => onSelect(n.id.replace("-upstream", ""))}
        colorMode={theme}
      >
        <Background color="#35404b" gap={24} />
        <Controls showInteractive={false} />
      </ReactFlow>
      <div className="diagram-bottom">
        PROJECT REPORTING <span>Independent schedules · shared local data</span>
      </div>
    </div>
  );
}
