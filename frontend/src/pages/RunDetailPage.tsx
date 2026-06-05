import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Clock,
  Zap,
  FileInput,
  FileOutput,
  Brain,
  Copy,
  Check,
} from "lucide-react";

import { api } from "@/lib/api";
import type { AgentRunDetail } from "@/lib/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

const AGENT_LABELS: Record<string, string> = {
  triage: "Triage Agent",
  threat_intel: "Threat Intel Agent",
  investigation: "Investigation Agent",
  response: "Response Agent",
  forensics: "Forensics Agent",
  compliance: "Compliance Agent",
  hunt: "Hunt Agent",
};

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatLatency(ms: number | null): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function statusStyle(status: string) {
  if (status === "completed" || status === "success") {
    return {
      bg: "bg-green-50",
      border: "border-green-200",
      text: "text-green-700",
      Icon: CheckCircle2,
    };
  }
  if (status === "failed" || status === "error") {
    return {
      bg: "bg-red-50",
      border: "border-red-200",
      text: "text-red-700",
      Icon: XCircle,
    };
  }
  return {
    bg: "bg-slate-50",
    border: "border-slate-200",
    text: "text-slate-600",
    Icon: Clock,
  };
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
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle className="text-base flex items-center gap-2">
          <Icon className="w-4 h-4 text-slate-500" />
          {label}
        </CardTitle>
        {!isEmpty && (
          <Button
            variant="ghost"
            size="sm"
            onClick={copy}
            className="text-xs h-auto py-1 px-2"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3 mr-1" /> Copied
              </>
            ) : (
              <>
                <Copy className="w-3 h-3 mr-1" /> Copy
              </>
            )}
          </Button>
        )}
      </CardHeader>
      <CardContent>
        {isEmpty ? (
          <p className="text-sm text-slate-400 italic">{emptyText}</p>
        ) : (
          <pre className="text-xs text-slate-700 bg-slate-50 rounded-md p-3 border border-slate-200 overflow-auto max-h-96 whitespace-pre-wrap break-words">
            {json}
          </pre>
        )}
      </CardContent>
    </Card>
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
      .then((res) => {
        if (!cancelled) setRun(res);
      })
      .catch((err) => {
        if (!cancelled) {
          const msg = err instanceof Error ? err.message : String(err);
          setError(msg);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [runId]);

  if (loading) {
    return (
      <div className="space-y-4">
        <Link
          to="/runs"
          className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to runs
        </Link>
        <Card>
          <CardContent className="p-8 text-center text-slate-500">
            Loading run…
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error || !run) {
    return (
      <div className="space-y-4">
        <Link
          to="/runs"
          className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to runs
        </Link>
        <Card className="border-severity-critical/30 bg-severity-critical/5">
          <CardContent className="p-6 flex items-center gap-3 text-severity-critical">
            <AlertCircle className="w-5 h-5" />
            <p className="text-sm font-medium">{error || "Run not found"}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const style = statusStyle(run.status);
  const agentLabel = AGENT_LABELS[run.agent_key] || run.agent_key;

  return (
    <div className="space-y-6">
      {/* Back */}
      <Link
        to="/runs"
        className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to runs
      </Link>

      {/* Header */}
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <span className="font-mono text-xs text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
            {run.id.slice(0, 8)}…
          </span>
          <span
            className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium border ${style.bg} ${style.border} ${style.text}`}
          >
            <style.Icon className="w-3.5 h-3.5" />
            {run.status}
          </span>
          <Link
            to={`/agents/${run.agent_key}`}
            className="text-xs text-slate-500 hover:text-primary-700 hover:underline"
          >
            {run.agent_key}
          </Link>
        </div>
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
          {agentLabel} run
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          {formatDate(run.created_at)}
        </p>
      </div>

      {/* Telemetry grid */}
      <Card>
        <CardContent className="p-5 grid grid-cols-2 md:grid-cols-4 gap-5">
          <div className="flex items-start gap-2">
            <Clock className="w-4 h-4 text-slate-400 mt-0.5" />
            <div>
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Latency
              </div>
              <div className="text-sm font-mono text-slate-900 mt-0.5">
                {formatLatency(run.latency_ms)}
              </div>
            </div>
          </div>
          <div className="flex items-start gap-2">
            <Zap className="w-4 h-4 text-slate-400 mt-0.5" />
            <div>
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Total tokens
              </div>
              <div className="text-sm font-mono text-slate-900 mt-0.5">
                {run.total_tokens > 0 ? run.total_tokens : "—"}
              </div>
            </div>
          </div>
          <div className="flex items-start gap-2">
            <FileInput className="w-4 h-4 text-slate-400 mt-0.5" />
            <div>
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Prompt tokens
              </div>
              <div className="text-sm font-mono text-slate-900 mt-0.5">
                {run.prompt_tokens > 0 ? run.prompt_tokens : "—"}
              </div>
            </div>
          </div>
          <div className="flex items-start gap-2">
            <FileOutput className="w-4 h-4 text-slate-400 mt-0.5" />
            <div>
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Completion tokens
              </div>
              <div className="text-sm font-mono text-slate-900 mt-0.5">
                {run.completion_tokens > 0 ? run.completion_tokens : "—"}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Metadata + error */}
      <Card>
        <CardContent className="p-5 space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
            <div>
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Trigger type
              </div>
              <div className="text-sm font-mono text-slate-900 mt-0.5">
                {run.trigger_type}
              </div>
            </div>
            {run.trigger_id && (
              <div>
                <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                  Trigger ID
                </div>
                <div className="text-sm font-mono text-slate-700 mt-0.5 truncate">
                  {run.trigger_id.slice(0, 8)}…
                </div>
              </div>
            )}
            <div>
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Model
              </div>
              <div className="text-sm font-mono text-slate-700 mt-0.5 truncate">
                {run.model || "—"}
              </div>
            </div>
            <div>
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Started
              </div>
              <div className="text-xs text-slate-700 mt-0.5">
                {formatDate(run.started_at)}
              </div>
            </div>
          </div>

          {run.error_message && (
            <>
              <Separator />
              <div className="bg-red-50 border border-red-200 rounded-md p-3">
                <div className="text-[10px] font-semibold text-red-700 uppercase tracking-wider mb-1">
                  Error
                </div>
                <div className="text-sm text-red-900 font-mono break-words">
                  {run.error_message}
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Input + Output side-by-side on wide screens */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
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
      </div>

      {/* Reasoning */}
      {run.reasoning && (
        <Card className="border-primary-200 bg-gradient-to-br from-primary-50/30 to-transparent">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Brain className="w-4 h-4 text-primary-600" />
              Agent reasoning
            </CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="text-sm text-slate-700 bg-white rounded-md p-3 border border-slate-200 overflow-auto max-h-96 whitespace-pre-wrap">
              {run.reasoning}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}