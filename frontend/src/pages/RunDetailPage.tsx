import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { motion } from "motion/react";
import {
  ArrowLeft,
  AlertCircle,
  Loader2,
  Clock,
  Zap,
  FileInput,
  FileOutput,
  Copy,
  Check,
} from "lucide-react";

import { api } from "@/lib/api";
import type { AgentRunDetail } from "@/lib/api/types";

const AGENT_LABELS: Record<string, string> = {
  triage:        "Triage Agent",
  threat_intel:  "Threat Intel Agent",
  investigation: "Investigation Agent",
  response:      "Response Agent",
  forensics:     "Forensics Agent",
  compliance:    "Compliance Agent",
  hunt:          "Hunt Agent",
};

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function formatLatency(ms: number | null): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-3">
      {children}
    </div>
  );
}

function MetaSlot({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1">
        {label}
      </div>
      <div className="text-[14px] font-medium text-foreground tabular">{children}</div>
    </div>
  );
}

interface CopyableJsonProps {
  label: string;
  icon: React.ElementType;
  data: unknown;
  emptyText?: string;
}

function CopyableJson({ label, icon: Icon, data, emptyText = "Empty" }: CopyableJsonProps) {
  const [copied, setCopied] = useState(false);
  const isEmpty =
    !data || (typeof data === "object" && Object.keys(data as object).length === 0);
  const json = isEmpty ? null : JSON.stringify(data, null, 2);

  function copy() {
    if (!json) return;
    navigator.clipboard.writeText(json);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-border">
        <div className="flex items-center gap-2">
          <Icon className="w-4 h-4 text-muted-foreground" />
          <span className="text-[13px] font-semibold text-foreground">{label}</span>
        </div>
        {!isEmpty && (
          <button
            onClick={copy}
            className="inline-flex items-center gap-1 font-mono text-[11px] text-muted-foreground hover:text-foreground transition-colors"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3" />
                Copied
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                Copy
              </>
            )}
          </button>
        )}
      </div>
      <div className="p-5">
        {isEmpty ? (
          <p className="text-[12.5px] text-muted-foreground italic">{emptyText}</p>
        ) : (
          <pre className="font-mono text-[11.5px] text-foreground/80 bg-muted/40 rounded-lg p-3.5 overflow-auto max-h-96 whitespace-pre-wrap">
            {json}
          </pre>
        )}
      </div>
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const s = status.toLowerCase();
  const isOk = s === "completed" || s === "success" || s === "ok";
  const isFail = s === "failed" || s === "error";
  const color = isOk
    ? "bg-severity-low"
    : isFail
    ? "bg-severity-critical"
    : "bg-muted-foreground/30";

  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`w-2 h-2 rounded-full ${color}`} />
      <span className="font-mono text-[11px] text-muted-foreground">{status}</span>
    </span>
  );
}

export default function RunDetailPage() {
  const { runId } = useParams<{ runId: string }>();
  const [run, setRun] = useState<AgentRunDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!runId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);

    api.agents
      .getAgentRun(runId)
      .then((res) => { if (!cancelled) setRun(res); })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, [runId]);

  const backLink = (
    <Link
      to="/runs"
      className="inline-flex items-center gap-1.5 text-[13px] text-muted-foreground hover:text-foreground transition-colors"
    >
      <ArrowLeft className="w-4 h-4" />
      Back to runs
    </Link>
  );

  if (loading) {
    return (
      <div className="space-y-5">
        {backLink}
        <div className="flex items-center gap-2 text-muted-foreground text-[13px] py-8">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading run...
        </div>
      </div>
    );
  }

  if (error || !run) {
    return (
      <div className="space-y-5">
        {backLink}
        <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical shrink-0 mt-0.5" />
          <span className="text-[13px] text-foreground">{error || "Run not found"}</span>
        </div>
      </div>
    );
  }

  const agentLabel = AGENT_LABELS[run.agent_key] ?? run.agent_key;

  return (
    <div className="space-y-6 pb-12">
      {/* Back */}
      {backLink}

      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <div className="flex flex-wrap items-center gap-2.5 mb-3">
          <span className="font-mono text-[11px] bg-muted text-muted-foreground px-2 py-0.5 rounded">
            {run.id.slice(0, 8)}...
          </span>
          <StatusDot status={run.status} />
          <Link
            to={`/agents/${run.agent_key}`}
            className="font-mono text-[11px] text-muted-foreground hover:text-foreground transition-colors"
          >
            {run.agent_key}
          </Link>
        </div>
        <h1 className="text-[26px] font-semibold tracking-[-0.025em] text-foreground">
          {agentLabel} run
        </h1>
        <p className="text-[13px] text-muted-foreground mt-1">
          {formatDate(run.created_at)}
        </p>
      </motion.div>

      {/* 4-stat strip */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.06 }}
        className="bg-card border border-border rounded-xl p-5 grid grid-cols-2 sm:grid-cols-4 gap-5"
      >
        <MetaSlot label="Latency">
          <span className="font-mono">{formatLatency(run.latency_ms)}</span>
        </MetaSlot>
        <MetaSlot label="Total tokens">
          <span className="font-mono">{run.total_tokens > 0 ? run.total_tokens.toLocaleString() : "—"}</span>
        </MetaSlot>
        <MetaSlot label="Prompt tokens">
          <span className="font-mono">{run.prompt_tokens > 0 ? run.prompt_tokens.toLocaleString() : "—"}</span>
        </MetaSlot>
        <MetaSlot label="Completion tokens">
          <span className="font-mono">{run.completion_tokens > 0 ? run.completion_tokens.toLocaleString() : "—"}</span>
        </MetaSlot>
      </motion.div>

      {/* Metadata */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
        className="bg-card border border-border rounded-xl p-5"
      >
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-5">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1">
              Trigger type
            </div>
            <div className="font-mono text-[12.5px] text-foreground">{run.trigger_type}</div>
          </div>
          {run.trigger_id && (
            <div>
              <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1">
                Trigger ID
              </div>
              <div className="font-mono text-[12.5px] text-foreground truncate">
                {run.trigger_id.slice(0, 8)}...
              </div>
            </div>
          )}
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1">
              Model
            </div>
            <div className="font-mono text-[12.5px] text-foreground truncate">
              {run.model || "—"}
            </div>
          </div>
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1">
              Started
            </div>
            <div className="text-[12.5px] text-foreground">{formatDate(run.started_at)}</div>
          </div>
        </div>

        {run.error_message && (
          <div className="mt-4 pt-4 border-t border-border">
            <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
              <AlertCircle className="w-4 h-4 text-severity-critical shrink-0 mt-0.5" />
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-severity-critical font-semibold mb-1">
                  Error
                </div>
                <div className="font-mono text-[12px] text-foreground/80">{run.error_message}</div>
              </div>
            </div>
          </div>
        )}
      </motion.div>

      {/* Input + Output */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.14 }}
        className="grid grid-cols-1 lg:grid-cols-2 gap-5"
      >
        <CopyableJson
          label="Input"
          icon={FileInput}
          data={run.input}
          emptyText="No input recorded"
        />
        <CopyableJson
          label="Output"
          icon={FileOutput}
          data={run.output}
          emptyText="No output (run may have failed)"
        />
      </motion.div>

      {/* Reasoning pull-quote */}
      {run.reasoning && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.18 }}
          className="bg-card border border-border rounded-xl p-6"
        >
          <SectionLabel>Agent reasoning</SectionLabel>
          <div className="flex gap-2 items-start">
            <div className="flex items-center gap-2 shrink-0 pt-1 text-muted-foreground">
              <Clock className="w-4 h-4" />
              <Zap className="w-4 h-4" />
            </div>
            <blockquote className="border-l-2 border-severity-info pl-4 flex-1">
              <p className="font-serif text-[15px] italic text-foreground/80 leading-[1.7] whitespace-pre-wrap">
                {run.reasoning}
              </p>
            </blockquote>
          </div>
        </motion.div>
      )}
    </div>
  );
}
