import { useEffect, useState } from "react";
import { Loader2, AlertCircle } from "lucide-react";

import { api } from "@/lib/api";
import type { SocMetrics as Metrics, DailyPoint } from "@/lib/api/soc";
import { cn } from "@/lib/utils";

const SEV = ["critical", "high", "medium", "low", "info"] as const;
const SEV_BG: Record<(typeof SEV)[number], string> = {
  critical: "bg-severity-critical",
  high: "bg-severity-high",
  medium: "bg-severity-medium",
  low: "bg-severity-low",
  info: "bg-severity-info",
};

function minutes(v: number | null): string {
  if (v == null) return "—";
  if (v < 1) return "<1m";
  if (v < 90) return `${Math.round(v)}m`;
  if (v < 60 * 48) return `${(v / 60).toFixed(1)}h`;
  return `${(v / 1440).toFixed(1)}d`;
}

function Tile({ label, value, hint, tone }: { label: string; value: string | number; hint?: string; tone?: "bad" }) {
  return (
    <div className="bg-card border border-border rounded-xl p-4">
      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">{label}</div>
      <div className={cn("text-[26px] font-semibold tabular tracking-tight mt-1", tone === "bad" && "text-severity-critical")}>
        {value}
      </div>
      {hint && <div className="text-[11.5px] text-muted-foreground mt-0.5">{hint}</div>}
    </div>
  );
}

function DailyChart({ daily }: { daily: DailyPoint[] }) {
  const max = Math.max(1, ...daily.map((d) => d.total));
  return (
    <div>
      <div
        className="flex items-end gap-1.5 h-36"
        role="img"
        aria-label={`Threats per day, ${daily.reduce((a, d) => a + d.total, 0)} in total`}
      >
        {daily.map((d) => (
          <div key={d.date} className="flex-1 min-w-0 flex flex-col justify-end h-full group relative">
            <div className="flex flex-col-reverse rounded-t overflow-hidden" style={{ height: `${(d.total / max) * 100}%` }}>
              {SEV.slice()
                .reverse()
                .map((s) =>
                  d[s] ? <div key={s} className={SEV_BG[s]} style={{ flexGrow: d[s] }} title={`${s}: ${d[s]}`} /> : null
                )}
            </div>
            <div className="pointer-events-none absolute -top-7 left-1/2 -translate-x-1/2 hidden group-hover:block whitespace-nowrap rounded bg-foreground text-background text-[10.5px] px-1.5 py-0.5">
              {d.date.slice(5)} · {d.total}
            </div>
          </div>
        ))}
      </div>
      <div className="flex gap-1.5 mt-1.5">
        {daily.map((d, i) => (
          <div key={d.date} className="flex-1 text-center font-mono text-[9.5px] text-muted-foreground">
            {daily.length <= 10 || i % Math.ceil(daily.length / 8) === 0 ? d.date.slice(8) : ""}
          </div>
        ))}
      </div>
      <div className="flex flex-wrap gap-3 mt-3">
        {SEV.map((s) => (
          <span key={s} className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground capitalize">
            <span className={cn("w-2.5 h-2.5 rounded-sm", SEV_BG[s])} /> {s}
          </span>
        ))}
      </div>
    </div>
  );
}

function BarList({ rows, empty }: { rows: Array<{ label: string; value: number }>; empty: string }) {
  if (rows.length === 0) return <p className="text-[12.5px] text-muted-foreground italic">{empty}</p>;
  const max = Math.max(...rows.map((r) => r.value));
  return (
    <ul className="space-y-2">
      {rows.map((r) => (
        <li key={r.label} className="text-[12.5px]">
          <div className="flex justify-between gap-2">
            <span className="font-mono truncate">{r.label}</span>
            <span className="tabular text-muted-foreground">{r.value}</span>
          </div>
          <div className="h-1 bg-muted rounded mt-1">
            <div className="h-1 rounded bg-foreground/70" style={{ width: `${(r.value / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

export default function SocMetrics() {
  const [days, setDays] = useState(7);
  const [data, setData] = useState<Metrics | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadedDays, setLoadedDays] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.soc
      .getSocMetrics(days)
      .then((d) => {
        if (cancelled) return;
        setData(d);
        setError(null);
        setLoadedDays(days);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : String(err));
        setLoadedDays(days);
      });
    return () => {
      cancelled = true;
    };
  }, [days]);

  const loading = loadedDays !== days;

  return (
    <section aria-labelledby="soc-metrics-h" className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 id="soc-metrics-h" className="text-[15px] font-semibold tracking-[-0.015em]">
            SOC performance
          </h2>
          <p className="text-[12px] text-muted-foreground">Computed from your organization’s threats, cases and agent runs.</p>
        </div>
        <div className="inline-flex rounded-lg border border-border overflow-hidden" role="group" aria-label="Time window">
          {[7, 30].map((d) => (
            <button
              key={d}
              onClick={() => setDays(d)}
              aria-pressed={days === d}
              className={cn(
                "px-3 py-1 text-[12px] font-medium transition-colors",
                days === d ? "bg-foreground text-background" : "hover:bg-accent text-muted-foreground"
              )}
            >
              {d}d
            </button>
          ))}
        </div>
      </div>

      {loading && (
        <div className="flex items-center gap-2 text-[13px] text-muted-foreground py-6">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading metrics…
        </div>
      )}
      {!loading && error && (
        <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical shrink-0 mt-0.5" />
          <span className="text-[13px]">{error}</span>
        </div>
      )}

      {!loading && data && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <Tile label="Open cases" value={data.totals.open_incidents} hint={`${data.totals.unassigned_open_incidents} unassigned`} />
            <Tile
              label="Critical & open"
              value={data.totals.critical_open_incidents}
              tone={data.totals.critical_open_incidents > 0 ? "bad" : undefined}
            />
            <Tile
              label="Noise suppressed"
              value={data.totals.duplicates_suppressed}
              hint={`${data.totals.raw_events_folded} raw events → ${data.totals.threats} threats`}
            />
            <Tile label="Approvals pending" value={data.approvals.pending} hint={`${data.approvals.executed} executed · ${data.approvals.failed} failed`} />
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <Tile label="Detection latency" value={minutes(data.mttd.median_minutes)} hint={`median · ${data.mttd.count} threats`} />
            <Tile label="Time to case" value={minutes(data.mtta.median_minutes)} hint={`median · ${data.mtta.count} cases`} />
            <Tile label="Time to contain" value={minutes(data.mttc.median_minutes)} hint={`median · ${data.mttc.count} cases`} />
            <Tile label="Time to resolve" value={minutes(data.mttr.median_minutes)} hint={`median · ${data.mttr.count} cases`} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 bg-card border border-border rounded-xl p-4 sm:p-5">
              <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-3">
                Threats per day
              </div>
              {data.totals.threats === 0 ? (
                <p className="text-[12.5px] text-muted-foreground italic py-8 text-center">No threats in this window.</p>
              ) : (
                <DailyChart daily={data.daily} />
              )}
            </div>
            <div className="bg-card border border-border rounded-xl p-4 sm:p-5 space-y-5">
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-3">
                  Top ATT&CK techniques
                </div>
                <BarList
                  rows={data.top_techniques.map((t) => ({ label: t.technique, value: t.threats }))}
                  empty="No techniques mapped yet."
                />
              </div>
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-3">
                  Top source IPs
                </div>
                <BarList rows={data.top_source_ips.map((t) => ({ label: t.ip, value: t.threats }))} empty="No source IPs yet." />
              </div>
            </div>
          </div>

          <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="px-5 py-3 border-b border-border font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              Agent health ({data.window_days}d)
            </div>
            {data.agents.length === 0 ? (
              <p className="text-[12.5px] text-muted-foreground italic p-5">No agent runs in this window.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-[12.5px]">
                  <thead className="text-left text-muted-foreground">
                    <tr>
                      <th className="px-5 py-2 font-medium">Agent</th>
                      <th className="px-3 py-2 font-medium text-right">Runs</th>
                      <th className="px-3 py-2 font-medium text-right">Success</th>
                      <th className="px-3 py-2 font-medium text-right">Avg latency</th>
                      <th className="px-5 py-2 font-medium text-right">Tokens</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {data.agents.map((a) => (
                      <tr key={a.agent_key}>
                        <td className="px-5 py-2 font-mono">{a.agent_key}</td>
                        <td className="px-3 py-2 text-right tabular">{a.runs}</td>
                        <td className={cn("px-3 py-2 text-right tabular", a.success_rate < 90 && "text-severity-high")}>
                          {a.success_rate}%
                        </td>
                        <td className="px-3 py-2 text-right tabular">{a.avg_latency_ms != null ? `${(a.avg_latency_ms / 1000).toFixed(1)}s` : "—"}</td>
                        <td className="px-5 py-2 text-right tabular">{a.tokens.toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          {data.truncated && (
            <p className="text-[11.5px] text-muted-foreground">Very large window: metrics cover the most recent 5,000 records.</p>
          )}
        </>
      )}
    </section>
  );
}
