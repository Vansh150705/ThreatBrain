import { useCallback, useEffect, useState } from "react";
import { motion } from "motion/react";
import { AlertCircle, CheckCircle2, Loader2, RefreshCw, XCircle } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { JobRow, SystemStatus } from "@/lib/api/ops";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

function Pill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1 font-mono text-[10.5px] uppercase", ok ? "text-severity-low" : "text-severity-high")}>
      {ok ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />} {label}
    </span>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="bg-card border border-border rounded-xl p-4 space-y-2">
      <h2 className="text-[14px] font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 text-[12.5px]">
      <span className="text-muted-foreground">{k}</span>
      <span className="font-mono text-[11.5px] text-right">{v}</span>
    </div>
  );
}

export default function OperationsPage() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [dead, setDead] = useState<JobRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    let live = true;
    Promise.all([api.ops.getSystemStatus(), api.ops.listJobs("dead")])
      .then(([s, d]) => {
        if (!live) return;
        setStatus(s);
        setDead(d);
        setError(null);
      })
      .catch((e) => live && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      live = false;
    };
  }, [tick]);

  async function requeue(j: JobRow) {
    try {
      await api.ops.requeueJob(j.id);
      toast.success("Job requeued");
      reload();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not requeue");
    }
  }

  const c = status?.readiness.checks;
  return (
    <div className="space-y-6 pb-12 max-w-5xl">
      <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }} className="flex items-start justify-between gap-3">
        <div>
          <h1 className="title-serif text-[24px] sm:text-[30px] tracking-[-0.03em]">Operations</h1>
          <p className="text-[13.5px] text-muted-foreground mt-1">Health of the platform itself: database, queue, workers, versions and limits.</p>
        </div>
        <Button variant="outline" size="sm" onClick={reload}><RefreshCw className="w-3.5 h-3.5 mr-1.5" />Refresh</Button>
      </motion.div>

      {error && <div role="alert" className="flex items-start gap-2 text-[13px] text-severity-critical"><AlertCircle className="w-4 h-4 mt-0.5" /> {error}</div>}
      {!status && !error && <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />}

      {status && c && (
        <>
          <div className="flex flex-wrap items-center gap-4">
            <Pill ok={status.readiness.ready} label={status.readiness.ready ? "ready" : "not ready"} />
            <span className="font-mono text-[11px] text-muted-foreground">v{status.version} · {status.environment}</span>
          </div>
          {status.readiness.warnings.length > 0 && (
            <ul role="status" className="rounded-lg border border-severity-medium/40 bg-severity-medium/8 p-3 text-[12.5px] space-y-0.5">
              {status.readiness.warnings.map((w) => (
                <li key={w}>⚠ {w}</li>
              ))}
            </ul>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            <Card title="Database">
              <Row k="Reachable" v={<Pill ok={c.database.ok} label={c.database.ok ? `${c.database.latency_ms} ms` : "down"} />} />
              {c.schema && <Row k="Schema" v={<Pill ok={c.schema.ok} label={c.schema.ok ? "current" : `missing ${c.schema.missing_tables.join(", ")}`} />} />}
              {c.schema && <Row k="Required migration" v={c.schema.required} />}
              {c.schema?.ledger_has_required === null && <Row k="Ledger" v="not found (not migrated with migrate.sh)" />}
            </Card>
            <Card title="Queue">
              {c.queue && (
                <>
                  <Row k="Queued" v={c.queue.queued} />
                  <Row k="Running" v={c.queue.running} />
                  <Row k="Dead-lettered" v={<span className={cn(c.queue.dead > 0 && "text-severity-high")}>{c.queue.dead}</span>} />
                  <Row k="Oldest waiting" v={`${c.queue.oldest_queued_seconds}s`} />
                </>
              )}
              <Row k="Backpressure at" v={`${status.ingest.queue_max_depth_per_org} per org / ${status.ingest.queue_max_depth} total`} />
            </Card>
            <Card title="Workers">
              {c.workers && (
                <>
                  <Row k="Live" v={<Pill ok={c.workers.ok} label={`${c.workers.live}${c.workers.embedded ? " (+embedded)" : ""}`} />} />
                  {c.workers.workers.map((w) => (
                    <Row key={w.worker_id} k={`${w.role}`} v={`${w.worker_id.slice(0, 22)} · ${w.age_seconds}s ago`} />
                  ))}
                </>
              )}
            </Card>
            <Card title="Detection &amp; AI">
              <Row k="Rule set" v={`${status.detection.rules_version} (${status.detection.rules} rules, ${status.detection.correlations} correlations)`} />
              <Row k="Language model" v={<Pill ok={status.llm.configured} label={`${status.llm.provider}${status.llm.configured ? "" : " · rules-only mode"}`} />} />
              <Row k="Triage of ingested events" v={status.ingest.triage_mode} />
            </Card>
            <Card title="Security posture">
              <Row k="Signed ingestion" v={<Pill ok={status.security.signed_ingest_available} label={status.security.signed_ingest_available ? "available" : "APP_SECRET not set"} />} />
              <Row k="OIDC sign-in" v={status.security.oidc_configured ? "configured" : "not configured"} />
              <Row k="Public sign-up" v={<Pill ok={!status.security.public_signup} label={status.security.public_signup ? "open" : "closed"} />} />
              <Row k="Max token age" v={status.security.max_token_age_minutes ? `${status.security.max_token_age_minutes} min` : "token expiry only"} />
            </Card>
            <Card title="Retention">
              <Row k="Unlinked events" v={`${status.retention_days.events} days`} />
              <Row k="Evidence events" v={`${status.retention_days.evidence} days`} />
              <Row k="Finished jobs" v={`${status.retention_days.jobs} days`} />
              <Row k="Pipeline runs" v={`${status.retention_days.pipeline_runs} days`} />
            </Card>
          </div>

          <Card title={`Dead-lettered jobs (${dead.length})`}>
            {dead.length === 0 ? (
              <p className="text-[12.5px] text-muted-foreground italic">None. Every job that exhausted its retries would appear here with its last error.</p>
            ) : (
              <ul className="divide-y divide-border">
                {dead.map((j) => (
                  <li key={j.id} className="py-2 flex items-start justify-between gap-3 text-[12.5px]">
                    <div className="min-w-0">
                      <div className="font-mono text-[11px]">{j.kind} · {j.attempts}/{j.max_attempts} attempts · {new Date(j.created_at).toLocaleString()}</div>
                      <div className="text-severity-high break-words">{j.last_error}</div>
                    </div>
                    <Button size="sm" variant="outline" onClick={() => void requeue(j)}>Requeue</Button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
