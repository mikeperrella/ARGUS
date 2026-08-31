type NodeKind = "input" | "script" | "artifact" | "artifact-accent" | "gate"

interface DiagramNode {
  id: string
  kind: NodeKind
  x: number
  y: number
  width: number
  height: number
  title: string
  subtitle?: string
  tag?: string
}

interface DiagramEdge {
  id: string
  from: string
  to: string
  path: string
  label?: string
  labelX?: number
  labelY?: number
  variant?: "default" | "feedback"
}

const nodes: DiagramNode[] = [
  { id: "sample", kind: "input", x: 320, y: 16, width: 160, height: 48, title: "Sample" },
  {
    id: "extract",
    kind: "script",
    x: 210,
    y: 105,
    width: 380,
    height: 90,
    title: "extract_features.py",
    subtitle: "DIE entropy gate → CAPA → FLOSS",
    tag: "in VM",
  },
  {
    id: "context",
    kind: "artifact",
    x: 290,
    y: 237,
    width: 220,
    height: 46,
    title: "pipeline_context.json",
  },
  {
    id: "draft",
    kind: "script",
    x: 210,
    y: 325,
    width: 380,
    height: 90,
    title: "draft_rule.py",
    subtitle: "Claude API drafts candidate YARA-X rule",
    tag: "on host · needs internet",
  },
  {
    id: "validate",
    kind: "script",
    x: 210,
    y: 455,
    width: 380,
    height: 90,
    title: "validate_rule.py",
    subtitle: "true-positive + false-positive tests",
    tag: "in VM",
  },
  {
    id: "failure",
    kind: "artifact",
    x: 10,
    y: 537,
    width: 200,
    height: 46,
    title: "failure_report.json",
  },
  {
    id: "gate",
    kind: "gate",
    x: 210,
    y: 605,
    width: 380,
    height: 90,
    title: "human_gate.py",
    subtitle: "Accept / Modify / Reject",
    tag: "in VM",
  },
  {
    id: "detections",
    kind: "artifact-accent",
    x: 150,
    y: 773,
    width: 260,
    height: 54,
    title: "detections.yar",
  },
  {
    id: "decisions",
    kind: "artifact",
    x: 430,
    y: 773,
    width: 260,
    height: 54,
    title: "decisions_log.json",
  },
]

const edges: DiagramEdge[] = [
  { id: "sample-extract", from: "sample", to: "extract", path: "M400,64 L400,105" },
  { id: "extract-context", from: "extract", to: "context", path: "M400,195 L400,237" },
  { id: "context-draft", from: "context", to: "draft", path: "M400,283 L400,325" },
  { id: "draft-validate", from: "draft", to: "validate", path: "M400,415 L400,455" },
  {
    id: "validate-failure",
    from: "validate",
    to: "failure",
    path: "M250,545 C220,568 170,548 112,538",
    label: "fail",
    labelX: 190,
    labelY: 518,
  },
  {
    id: "failure-draft",
    from: "failure",
    to: "draft",
    path: "M210,556 C105,542 105,388 210,372",
    label: "--previous-rule --feedback",
    labelX: 122,
    labelY: 435,
    variant: "feedback",
  },
  {
    id: "validate-gate",
    from: "validate",
    to: "gate",
    path: "M400,545 L400,605",
    label: "pass",
    labelX: 416,
    labelY: 578,
  },
  {
    id: "gate-detections",
    from: "gate",
    to: "detections",
    path: "M320,695 C300,725 290,745 280,773",
    label: "accept",
    labelX: 236,
    labelY: 736,
  },
  {
    id: "gate-decisions",
    from: "gate",
    to: "decisions",
    path: "M480,695 C500,725 510,745 520,773",
    label: "reject",
    labelX: 524,
    labelY: 736,
  },
]

const nodeStyles: Record<NodeKind, string> = {
  input: "fill-card stroke-border",
  script: "fill-card stroke-primary/40",
  artifact: "fill-muted stroke-border",
  "artifact-accent": "fill-muted stroke-primary",
  gate: "fill-card stroke-primary",
}

function DiagramNodeShape({ node }: { node: DiagramNode }) {
  const isPill = node.kind === "artifact" || node.kind === "artifact-accent" || node.kind === "input"
  const rx = isPill ? node.height / 2 : 10
  const titleY = node.subtitle
    ? node.y + node.height / 2 - 10
    : node.y + node.height / 2 + 5

  return (
    <g data-node={node.id}>
      <rect
        x={node.x}
        y={node.y}
        width={node.width}
        height={node.height}
        rx={rx}
        strokeWidth={node.kind === "gate" || node.kind === "artifact-accent" ? 1.5 : 1}
        className={nodeStyles[node.kind]}
      />
      <text
        x={node.x + node.width / 2}
        y={titleY}
        textAnchor="middle"
        className={
          node.kind === "artifact" || node.kind === "artifact-accent" || node.kind === "input"
            ? "fill-foreground text-[13px]"
            : "fill-foreground font-mono text-[13px]"
        }
      >
        {node.title}
      </text>
      {node.subtitle && (
        <text
          x={node.x + node.width / 2}
          y={titleY + 18}
          textAnchor="middle"
          className="fill-muted-foreground text-[11px]"
        >
          {node.subtitle}
        </text>
      )}
      {node.tag && (
        <text
          x={node.x + node.width / 2}
          y={node.y + node.height - 10}
          textAnchor="middle"
          className="fill-muted-foreground font-mono text-[10px] uppercase tracking-[0.08em]"
        >
          {node.tag}
        </text>
      )}
    </g>
  )
}

function DiagramEdgePath({ edge }: { edge: DiagramEdge }) {
  const isFeedback = edge.variant === "feedback"
  return (
    <g data-edge={edge.id}>
      <path
        d={edge.path}
        fill="none"
        strokeWidth={1.5}
        strokeDasharray={isFeedback ? "4 3" : undefined}
        markerEnd="url(#pipeline-arrowhead)"
        className={isFeedback ? "stroke-muted-foreground" : "stroke-foreground/70"}
      />
      {edge.label && (
        <text
          x={edge.labelX}
          y={edge.labelY}
          textAnchor="middle"
          className={
            isFeedback
              ? "fill-muted-foreground font-mono text-[10px]"
              : "fill-muted-foreground font-mono text-[11px] uppercase tracking-[0.06em]"
          }
        >
          {edge.label}
        </text>
      )}
    </g>
  )
}

export function PipelineDiagram() {
  return (
    <svg
      viewBox="0 0 720 900"
      role="img"
      aria-label="ARGUS detection pipeline: a sample flows through extract_features.py, draft_rule.py, validate_rule.py, and human_gate.py, with a feedback loop from a failed validation back into rule drafting."
      className="h-auto w-full max-w-2xl text-foreground"
    >
      <defs>
        <marker
          id="pipeline-arrowhead"
          viewBox="0 0 10 10"
          refX="8"
          refY="5"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path d="M0,0 L10,5 L0,10 Z" className="fill-foreground/70" />
        </marker>
      </defs>
      {edges.map((edge) => (
        <DiagramEdgePath key={edge.id} edge={edge} />
      ))}
      {nodes.map((node) => (
        <DiagramNodeShape key={node.id} node={node} />
      ))}
    </svg>
  )
}
