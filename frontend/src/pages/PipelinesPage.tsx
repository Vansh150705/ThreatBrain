import { Fragment, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "motion/react";
import { AlertCircle, ChevronDown, ChevronRight, Loader2, RefreshCw } from "lucide-react";

import { api } from "@/lib/api";
import type { PipelineRunDetail, PipelineRunItem } from "@/lib/api/pipelines";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const STATUS_STYLE: Record<string, string> = {
  completed: "bg-severity-low/8 text-severity-low border-severity-low/30",
  running: "bg-severity-info/8 text-severity-info border-severity-info/30",
  queued: "bg-muted text-muted-foreground border-border",
  failed: "bg-severity-critical/8 text-severity-critical border-severity-critical/30",
  ok: "bg-severity-low/8 text-severity-low border-severity-low/30",
  degraded: "bg-severity-medium/8 text-severity-medium border-severity-medium/30",
  skipped: "bg-muted text-muted-foreground border-border",
};

function Pill({ value }: { value: string }) {
  return (
    <span
      className={cn(
        "inline-flex px-1.5 py-0.5 rounded font-mono text-[10px] font-semibold uppercase tracking-[0.06em] border",
        STATUS_STYLE[value] ?? STATUS_STYLE.queued
      )}
    >
      {value}
    </span>
  );
}

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
}

function duration(run: PipelineRunItem): string {
  if (!run.started_at || !run.completed_at) return "—";
  const s = (new Date(run.completed_at).getTime() - new Date(run.started_at).getTime()) / 1000;
  return `${s.toFixed(1)}s`;
}

function RunTrace({ id }: { id: string }) {
  const [detail, setDetail] = useState<PipelineRunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.pipelines
      .getPipelineRun(id)
      .then((d) => !cancelled && setDetail(d))
      .catch((e) => !cancelled && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (error) return <p className="text-[12.5px] text-severity-critical">{error}</p>;
  if (!detail) return <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />;
  const summary = detail.summary as Record<string, unknown>;
  const threat = summary.promoted_threat_short_id as string | undefined;
  const incident = summary.incident_short_id as string | undefined;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-x-5 gap-y-1 text-[12.5px]">
        {threat && (
          <span>
            Threat <Link className="font-mono underline" to={`/threats/${threat}`}>{threat}</Link>
          </span>
        )}
        {incident && (
          <span>
            Incident <Link className="font-mono underline" to={`/incidents/${incident}`}>{incident}</Link>
          </span>
        )}
        {summary.deduplicated === true && <span>Duplicate of <span className="font-mono">{String(summary.duplicate_of)}</span> (no agents run)</span>}
        {summary.degraded === true && <span className="text-severity-medium">Degraded mode: LLM unavailable, rules-based verdict</span>}
        {summary.final_severity != null && <span>Severity <strong>{String(summary.final_severity)}</strong></span>}
        {summary.risk_score != null && <span>Risk <strong>{String(summary.risk_score)}</strong></span>}
      </div>
      {detail.error_message && <p className="text-[12.5px] text-severity-critical">{detail.error_message}</p>}
      <div className="overflow-x-auto">
        <table className="w-full text-[12.5px]">
          <thead className="text-left text-muted-foreground">
            <tr>
              <th className="py-1.5 pr-3 font-medium">Stage</th>
              <th className="py-1.5 pr-3 font-medium">Status</th>
              <th className="py-1.5 pr-3 font-medium text-right">Duration</th>
              <th className="py-1.5 pr-3 font-medium text-right">Attempts</th>
              <th className="py-1.5 font-medium">Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {detail.trace.map((t, i) => (
              <tr key={`${t.stage}-${i}`}>
                <td className="py-1.5 pr-3 font-mono">{t.stage}</td>
                <td className="py-1.5 pr-3"><Pill value={t.status} /></td>
                <td className="py-1.5 pr-3 text-right tabular">{t.duration_ms ? `${(t.duration_ms / 1000).toFixed(1)}s` : "—"}</td>
                <td className="py-1.5 pr-3 text-right tabular">{t.attempts || "—"}</td>
                <td className="py-1.5 text-foreground/75">
                  {t.error ?? t.reason ?? ""}
                  {t.run_id && (
                    <Link className="ml-2 font-mono text-[11px] underline" to={`/runs/${t.run_id}`}>
                      agent run
                    </Link>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function PipelinesPage() {
  const [runs, setRuns] = useState<PipelineRunItem[]>([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  // bump to re-fetch (manual refresh, polling)
  const [reload, setReload] = useState(0);
  const [loadedKey, setLoadedKey] = useState<string | null>(null);
  const key = `${filter}|${reload}`;

  useEffect(() => {
    let cancelled = false;
    api.pipelines
      .listPipelineRuns(filter || undefined)
      .then((res) => {
        if (cancelled) return;
        setRuns(res.items);
        setTotal(res.total);
        setError(null);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (!cancelled) setLoadedKey(key);
      });
    return () => {
      cancelled = true;
    };
  }, [filter, reload, key]);
  const loading = loadedKey === null;

  // keep in-flight runs fresh without hammering the API
  const active = runs.some((r) => r.status === "queued" || r.status === "running");
  useEffect(() => {
    if (!active) return;
    const t = window.setInterval(() => setReload((n) => n + 1), 4000);
    return () => window.clearInterval(t);
  }, [active]);

  return (
    <div className="space-y-6 pb-12">
      <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <h1 className="title-serif text-[24px] sm:text-[30px] tracking-[-0.03em]">Pipelines</h1>
        <p className="text-[13.5px] text-muted-foreground mt-1 max-w-2xl">
          Every event the SOC ingested, with a stage-by-stage execution trace: detection rules, de-duplication, the agents,
          retries, timeouts and degraded-mode fallbacks. {total > 0 && <>({total} total)</>}
        </p>
      </motion.div>

      <div className="flex flex-wrap items-center gap-2">
        {["", "completed", "running", "queued", "failed"].map((s) => (
          <button
            key={s || "all"}
            onClick={() => setFilter(s)}
            aria-pressed={filter === s}
            className={cn(
              "px-3 py-1 rounded-lg border text-[12px] font-medium transition-colors capitalize",
              filter === s ? "bg-foreground text-background border-foreground" : "border-border text-muted-foreground hover:bg-accent"
            )}
          >
            {s || "All"}
          </button>
        ))}
        <Button variant="outline" size="sm" className="ml-auto h-8" onClick={() => setReload((n) => n + 1)}>
          <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
        </Button>
      </div>

      {loading && (
        <div className="flex items-center gap-2 text-[13px] text-muted-foreground py-8">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading pipeline runs…
        </div>
      )}
      {error && (
        <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical shrink-0 mt-0.5" />
          <span className="text-[13px]">{error}</span>
        </div>
      )}
      {!loading && !error && runs.length === 0 && (
        <div className="bg-card border border-border rounded-xl p-10 text-center">
          <p className="text-[14px] text-muted-foreground">No pipeline runs{filter ? ` with status “${filter}”` : ""} yet.</p>
          <p className="text-[12.5px] text-muted-foreground/80 mt-1">
            Trigger one from the dashboard, run a collector, or send a SIEM webhook (see Settings → Integrations).
          </p>
        </div>
      )}

      {runs.length > 0 && (
        <div className="bg-card border border-border rounded-xl overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead className="text-left text-muted-foreground border-b border-border">
              <tr>
                <th className="w-8" />
                <th className="px-3 py-2.5 font-medium">Event</th>
                <th className="px-3 py-2.5 font-medium">Source</th>
                <th className="px-3 py-2.5 font-medium">Status</th>
                <th className="px-3 py-2.5 font-medium">Started</th>
                <th className="px-3 py-2.5 font-medium text-right">Took</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => {
                const isOpen = open === r.id;
                return (
                  <Fragment key={r.id}>
                    <tr
                      className="border-b border-border last:border-0 hover:bg-accent/40 cursor-pointer"
                      onClick={() => setOpen(isOpen ? null : r.id)}
                    >
                      <td className="pl-3">
                        <button aria-label={isOpen ? "Hide trace" : "Show trace"} aria-expanded={isOpen}>
                          {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                        </button>
                      </td>
                      <td className="px-3 py-2.5 max-w-[26rem] truncate">{r.title ?? "—"}</td>
                      <td className="px-3 py-2.5 font-mono text-[11.5px] text-muted-foreground">{r.source ?? "—"}</td>
                      <td className="px-3 py-2.5"><Pill value={r.status} /></td>
                      <td className="px-3 py-2.5 text-muted-foreground whitespace-nowrap">{when(r.started_at ?? r.created_at)}</td>
                      <td className="px-3 py-2.5 text-right tabular text-muted-foreground">{duration(r)}</td>
                    </tr>
                    {isOpen && (
                      <tr className="bg-muted/20">
                        <td />
                        <td colSpan={5} className="px-3 py-4">
                          <RunTrace id={r.id} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
