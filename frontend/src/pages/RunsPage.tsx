import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  Search,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronRight,
} from "lucide-react";

import { api } from "@/lib/api";
import type { AgentRunSummary, PaginatedResponse } from "@/lib/api/types";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

const STATUS_OPTIONS = [
  { value: "all", label: "All statuses" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
];

const AGENT_LABELS: Record<string, string> = {
  triage: "Triage",
  threat_intel: "Threat Intel",
  investigation: "Investigation",
  response: "Response",
  forensics: "Forensics",
  compliance: "Compliance",
  hunt: "Hunt",
};

function formatRelativeTime(iso: string | null): string {
  if (!iso) return "—";
  const diffMs = Date.now() - new Date(iso).getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  if (diffSecs < 60) return `${diffSecs}s ago`;
  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${Math.floor(diffHours / 24)}d ago`;
}

function formatLatency(ms: number | null): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function RunStatusIcon({ status }: { status: string }) {
  if (status === "completed" || status === "succeeded" || status === "success" || status === "ok") {
    return <CheckCircle2 className="w-4 h-4 text-green-600" />;
  }
  if (status === "failed" || status === "error") {
    return <XCircle className="w-4 h-4 text-red-600" />;
  }
  return <Clock className="w-4 h-4 text-slate-400" />;
}

export default function RunsPage() {
  const [data, setData] = useState<PaginatedResponse<AgentRunSummary> | null>(
    null
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const pageSize = 25;

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    api.agents
      .listRecentRuns({
        page,
        page_size: pageSize,
        run_status: statusFilter === "all" ? undefined : statusFilter,
      })
      .then((res) => {
        if (!cancelled) setData(res);
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
  }, [page, statusFilter]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            Run history
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Every AI agent call, with full input, output, and timing — an
            audit trail of every decision made.
          </p>
        </div>
        <div className="text-sm text-slate-500">
          {data?.pagination ? (
            <span>
              <span className="font-medium text-slate-900">
                {data.pagination.total}
              </span>{" "}
              total
            </span>
          ) : null}
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Select
          value={statusFilter}
          onValueChange={(v) => {
            setStatusFilter(v);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            {STATUS_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {statusFilter !== "all" && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setStatusFilter("all");
              setPage(1);
            }}
          >
            Clear filters
          </Button>
        )}
      </div>

      {/* Loading */}
      {loading && (
        <Card>
          <CardContent className="p-8 flex flex-col items-center text-slate-500">
            <Search className="w-8 h-8 mb-2 text-slate-400 animate-pulse" />
            <p className="text-sm">Loading runs…</p>
          </CardContent>
        </Card>
      )}

      {/* Error */}
      {error && !loading && (
        <Card className="border-severity-critical/30 bg-severity-critical/5">
          <CardContent className="p-6 flex items-center gap-3 text-severity-critical">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <p className="text-sm font-medium">{error}</p>
          </CardContent>
        </Card>
      )}

      {/* Empty */}
      {!loading && !error && data && data.items.length === 0 && (
        <Card className="border-dashed">
          <CardContent className="p-10 flex flex-col items-center text-center text-slate-500">
            <Activity className="w-10 h-10 mb-3 text-slate-400" />
            <p className="text-sm">No runs match your filters.</p>
          </CardContent>
        </Card>
      )}

      {/* Table */}
      {!loading && !error && data && data.items.length > 0 && (
        <>
          <Card className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-slate-50 border-b border-slate-200">
                  <tr className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
                    <th className="px-4 py-3 w-12"></th>
                    <th className="px-4 py-3">Agent</th>
                    <th className="px-4 py-3">Trigger</th>
                    <th className="px-4 py-3">Model</th>
                    <th className="px-4 py-3 text-right">Latency</th>
                    <th className="px-4 py-3 text-right">Tokens</th>
                    <th className="px-4 py-3">When</th>
                    <th className="px-4 py-3 w-12"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {data.items.map((run) => (
                    <tr
                      key={run.id}
                      className="hover:bg-slate-50 transition-colors"
                    >
                      <td className="px-4 py-3">
                        <RunStatusIcon status={run.status} />
                      </td>
                      <td className="px-4 py-3">
                        <Link
                          to={`/runs/${run.id}`}
                          className="font-medium text-slate-900 hover:text-primary-700"
                        >
                          {AGENT_LABELS[run.agent_key] || run.agent_key}
                        </Link>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs px-1.5 py-0.5 bg-slate-100 text-slate-600 rounded font-mono">
                          {run.trigger_type}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-600 max-w-[200px] truncate">
                        {run.model || "—"}
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-xs text-slate-700">
                        {formatLatency(run.latency_ms)}
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-xs text-slate-700">
                        {run.total_tokens > 0 ? run.total_tokens : "—"}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500 whitespace-nowrap">
                        {formatRelativeTime(run.created_at)}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Link
                          to={`/runs/${run.id}`}
                          className="text-slate-400 hover:text-slate-700"
                        >
                          <ChevronRight className="w-4 h-4" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          {/* Pagination */}
          {data.pagination && data.pagination.total_pages > 1 && (
            <div className="flex items-center justify-between text-sm">
              <div className="text-slate-500">
                Page{" "}
                <span className="font-medium text-slate-900">
                  {data.pagination.page}
                </span>{" "}
                of {data.pagination.total_pages}
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => p + 1)}
                  disabled={page >= data.pagination.total_pages}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}