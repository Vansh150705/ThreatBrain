import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "motion/react";
import { Activity, AlertCircle, Loader2, ArrowUpRight } from "lucide-react";

import { api, withColdStartRetry } from "@/lib/api";
import type { AgentRunSummary, PaginatedResponse } from "@/lib/api/types";
import { Button } from "@/components/ui/button";
import ColdStartNotice from "@/components/ColdStartNotice";

const STATUS_OPTS = [
  { value: "all",       label: "All" },
  { value: "completed", label: "Completed" },
  { value: "failed",    label: "Failed" },
  { value: "running",   label: "Running" },
];

const AGENT_LABELS: Record<string, string> = {
  triage:        "Triage",
  threat_intel:  "Threat Intel",
  investigation: "Investigation",
  response:      "Response",
  forensics:     "Forensics",
  compliance:    "Compliance",
  hunt:          "Hunt",
};

function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const diffMs = Date.now() - new Date(iso).getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  if (diffSecs < 60) return `${diffSecs}s ago`;
  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins}m ago`;
  const h = Math.floor(diffMins / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function formatLatency(ms: number | null): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function StatusDot({ status }: { status: string }) {
  const s = status.toLowerCase();
  if (s === "completed" || s === "succeeded" || s === "success" || s === "ok") {
    return (
      <span className="inline-flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-severity-low" />
        <span className="font-mono text-[11px] text-muted-foreground">Completed</span>
      </span>
    );
  }
  if (s === "failed" || s === "error") {
    return (
      <span className="inline-flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-severity-critical" />
        <span className="font-mono text-[11px] text-muted-foreground">Failed</span>
      </span>
    );
  }
  if (s === "running") {
    return (
      <span className="inline-flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-severity-info animate-pulse" />
        <span className="font-mono text-[11px] text-muted-foreground">Running</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="w-1.5 h-1.5 rounded-full bg-muted-foreground/30" />
      <span className="font-mono text-[11px] text-muted-foreground">{status}</span>
    </span>
  );
}

function FilterPills({
  options,
  value,
  onChange,
}: {
  options: { value: string; label: string }[];
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {options.map((opt) => (
        <button
          key={opt.value}
          onClick={() => onChange(opt.value)}
          className={`px-3 py-1 rounded-full text-[12px] font-medium border transition-colors ${
            value === opt.value
              ? "bg-foreground text-background border-foreground"
              : "bg-card border-border text-muted-foreground hover:text-foreground"
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

export default function RunsPage() {
  const [data, setData] = useState<PaginatedResponse<AgentRunSummary> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [waking, setWaking] = useState(false);
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const pageSize = 25;

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    withColdStartRetry(
      () =>
        api.agents.listRecentRuns({
          page,
          page_size: pageSize,
          run_status: statusFilter === "all" ? undefined : statusFilter,
        }),
      { onRetry: () => { if (!cancelled) setWaking(true); } }
    )
      .then((res) => { if (!cancelled) setData(res); })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => { if (!cancelled) { setLoading(false); setWaking(false); } });

    return () => { cancelled = true; };
  }, [page, statusFilter]);

  return (
    <div className="space-y-6 sm:space-y-8 pb-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="flex items-start justify-between gap-4 sm:gap-6 flex-wrap"
      >
        <div>
          <h1 className="title-serif text-[22px] sm:text-[28px] tracking-[-0.03em] text-foreground">
            Run history
          </h1>
          <p className="text-[13.5px] text-muted-foreground mt-1">
            Every AI agent call, with a full audit trail of every decision made.
          </p>
        </div>
        {data?.pagination && (
          <div className="font-mono text-[12px] text-muted-foreground self-end pb-1">
            <span className="text-foreground font-semibold tabular">{data.pagination.total}</span> total
          </div>
        )}
      </motion.div>

      {/* Filter chips */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.04 }}
      >
        <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-2">
          Status
        </div>
        <FilterPills
          options={STATUS_OPTS}
          value={statusFilter}
          onChange={(v) => { setStatusFilter(v); setPage(1); }}
        />
      </motion.div>

      {/* Cold-start notice */}
      {waking && !error && <ColdStartNotice />}

      {/* Loading */}
      {loading && !waking && (
        <div className="flex items-center gap-2 text-muted-foreground text-[13px] py-8">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading runs...
        </div>
      )}

      {/* Error */}
      {error && !loading && (
        <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical shrink-0 mt-0.5" />
          <div className="text-[13px] text-foreground">
            <div className="font-semibold">Could not load runs</div>
            <div className="text-muted-foreground mt-0.5 font-mono text-[11px]">{error}</div>
          </div>
        </div>
      )}

      {/* Empty */}
      {!loading && !error && data && data.items.length === 0 && (
        <div className="py-16 text-center">
          <Activity className="w-8 h-8 text-muted-foreground/40 mx-auto mb-3" strokeWidth={1.5} />
          <p className="text-[13.5px] text-muted-foreground">No runs match your filters.</p>
        </div>
      )}

      {/* Table */}
      {!loading && !error && data && data.items.length > 0 && (
        <>
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.08 }}
            className="bg-card border border-border rounded-xl overflow-hidden"
          >
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-muted/40 border-b border-border">
                  <tr>
                    <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Status</th>
                    <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Agent</th>
                    <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden md:table-cell">Run ID</th>
                    <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden md:table-cell">Trigger</th>
                    <th className="px-4 sm:px-5 py-3 text-right font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden lg:table-cell">Tokens</th>
                    <th className="px-4 sm:px-5 py-3 text-right font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Latency</th>
                    <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">When</th>
                    <th className="px-2 py-3 w-8" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {data.items.map((run, i) => (
                    <motion.tr
                      key={run.id}
                      initial={{ opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.03 }}
                      className="hover:bg-accent/40 transition-colors group"
                    >
                      <td className="px-4 sm:px-5 py-3.5">
                        <StatusDot status={run.status} />
                      </td>
                      <td className="px-4 sm:px-5 py-3.5">
                        <Link
                          to={`/runs/${run.id}`}
                          className="text-[13px] font-medium text-foreground hover:text-foreground/70 transition-colors"
                        >
                          {AGENT_LABELS[run.agent_key] ?? run.agent_key}
                        </Link>
                      </td>
                      <td className="px-4 sm:px-5 py-3.5 hidden md:table-cell">
                        <span className="font-mono text-[11px] text-muted-foreground">
                          {run.id.slice(0, 8)}...
                        </span>
                      </td>
                      <td className="px-4 sm:px-5 py-3.5 hidden md:table-cell">
                        <span className="font-mono text-[10px] px-1.5 py-0.5 bg-muted text-muted-foreground rounded">
                          {run.trigger_type}
                        </span>
                      </td>
                      <td className="px-4 sm:px-5 py-3.5 text-right font-mono text-[11px] text-muted-foreground tabular hidden lg:table-cell">
                        {run.total_tokens > 0 ? run.total_tokens.toLocaleString() : "—"}
                      </td>
                      <td className="px-4 sm:px-5 py-3.5 text-right font-mono text-[11px] text-muted-foreground tabular">
                        {formatLatency(run.latency_ms)}
                      </td>
                      <td className="px-4 sm:px-5 py-3.5">
                        <span className="font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                          {timeAgo(run.created_at)}
                        </span>
                      </td>
                      <td className="px-2 py-3.5 text-right">
                        <Link to={`/runs/${run.id}`}>
                          <ArrowUpRight className="w-3.5 h-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                        </Link>
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>

          {/* Pagination */}
          {data.pagination && data.pagination.total_pages > 1 && (
            <div className="flex items-center justify-between">
              <div className="font-mono text-[12px] text-muted-foreground">
                Page{" "}
                <span className="text-foreground font-semibold tabular">{data.pagination.page}</span>
                {" "}of{" "}
                <span className="tabular">{data.pagination.total_pages}</span>
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1}
                  className="h-8 px-3 text-[12px]"
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => p + 1)}
                  disabled={page >= data.pagination.total_pages}
                  className="h-8 px-3 text-[12px]"
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
