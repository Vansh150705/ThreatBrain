import { useCallback, useEffect, useState } from "react";
import { AlertCircle, Check, GraduationCap, Loader2, ShieldQuestion, X } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { Anomaly, BehaviorSettings, BehaviorStatus, EntityBaseline, Sensitivity } from "@/lib/api/behavior";
import { Button } from "@/components/ui/button";
import { useUserStore } from "@/store/useUserStore";
import { cn } from "@/lib/utils";

const FEATURE_LABEL: Record<string, string> = {
  "auth.source_net": "Sign-in network", "auth.hour": "Sign-in hour", "auth.host": "System signed in to", "auth.breadth": "Systems per hour",
  "priv.action": "Privileged action", "cloud.action": "Cloud/identity call", "resource.access": "Resource accessed",
  "proc.name": "Process", "proc.pair": "Process relationship", "proc.exec_path": "Run from writable path",
  "net.dest": "Destination network", "net.port": "Destination port", "net.bytes_flow": "Single transfer size", "net.bytes_out_hour": "Outbound per hour",
};

function Stat({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <div className="bg-card border border-border rounded-xl p-4">
      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">{label}</div>
      <div className="text-[22px] font-semibold mt-1">{value}</div>
      {hint && <div className="text-[11.5px] text-muted-foreground mt-0.5">{hint}</div>}
    </div>
  );
}

export default function BehaviorPage() {
  const role = useUserStore((s) => s.profile?.role);
  const isAdmin = role === "owner" || role === "admin";
  const canTriage = isAdmin || role === "analyst";
  const [status, setStatus] = useState<BehaviorStatus | null>(null);
  const [rows, setRows] = useState<Anomaly[]>([]);
  const [settings, setSettings] = useState<BehaviorSettings | null>(null);
  const [onlyAlerts, setOnlyAlerts] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [baseline, setBaseline] = useState<EntityBaseline | null>(null);
  const [lookup, setLookup] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    let live = true;
    Promise.all([
      api.behavior.getStatus(),
      canTriage ? api.behavior.listAnomalies({ alerted: onlyAlerts ? true : undefined, limit: 100 }) : Promise.resolve([] as Anomaly[]),
      canTriage ? api.behavior.getSettings() : Promise.resolve(null),
    ])
      .then(([s, a, cfg]) => {
        if (!live) return;
        setStatus(s);
        setRows(a);
        setSettings(cfg);
        setError(null);
      })
      .catch((e) => live && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      live = false;
    };
  }, [tick, onlyAlerts, canTriage]);

  async function judge(a: Anomaly, d: "confirmed" | "benign" | "expected") {
    setBusy(a.id);
    try {
      await api.behavior.setDisposition(a.id, d);
      toast.success(d === "expected" ? "Marked expected: the baseline now includes it" : d === "benign" ? "Marked benign: silenced for 30 days" : "Marked as a true positive");
      reload();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Update failed");
    } finally {
      setBusy(null);
    }
  }

  async function setSensitivity(sensitivity: Sensitivity) {
    try {
      await api.behavior.putSettings({ sensitivity });
      toast.success(`Sensitivity set to ${sensitivity}`);
      reload();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Update failed");
    }
  }

  async function learn() {
    try {
      await api.behavior.learnFromHistory(14);
      toast.success("Learning from the last 14 days of stored events (runs in the background)");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not queue learning");
    }
  }

  async function show() {
    const [type, ...rest] = lookup.includes(":") ? lookup.split(":") : ["user", lookup];
    const id = rest.join(":").trim() || type;
    try {
      setBaseline(await api.behavior.getBaseline(type === "host" ? "host" : "user", id));
    } catch {
      setBaseline(null);
      toast.error("No baseline for that entity yet");
    }
  }

  if (error) {
    return (
      <div className="p-6 text-[13px] flex items-center gap-2 text-severity-high">
        <AlertCircle className="w-4 h-4" /> {error}
      </div>
    );
  }
  if (!status) {
    return (
      <div className="p-6">
        <Loader2 className="w-4 h-4 animate-spin" />
      </div>
    );
  }

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-6xl mx-auto">
      <header>
        <h1 className="text-[20px] font-semibold">Behaviour</h1>
        <p className="text-[13px] text-muted-foreground max-w-3xl mt-1">
          What is unusual <em>for this account or host</em>, learned from your own events. These are statistical deviations, not signatures: one odd thing is
          recorded but does not alert; several independent odd things together do. Every item shows what it was compared with.
        </p>
      </header>

      {status.learning && (
        <div className="p-3 rounded-lg bg-severity-info/10 border border-severity-info/30 text-[12.5px]" data-testid="learning-banner">
          <strong>Still learning.</strong> An account or host needs at least {status.maturity_requirements.min_events} events across {status.maturity_requirements.min_days} days before its
          baseline is trusted, so nothing is flagged yet. Existing events can shorten this.
          {isAdmin && (
            <Button size="sm" variant="outline" className="ml-3" onClick={learn}>
              <GraduationCap className="w-3.5 h-3.5 mr-1.5" /> Learn from history
            </Button>
          )}
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Stat label="Baselines" value={`${status.mature_profiles.user + status.mature_profiles.host}/${status.profiles.user + status.profiles.host}`} hint="mature / total (users + hosts)" />
        <Stat label="Alerts, 24 h" value={status.last_24h.alerts} hint={`${status.last_24h.anomalies} deviations recorded`} />
        <Stat label="Withheld, 24 h" value={status.last_24h.suppressed} hint="cooldown, budget or your suppressions" />
        <Stat label="Analyst-confirmed" value={status.analyst_feedback.precision == null ? "-" : `${Math.round(status.analyst_feedback.precision * 100)}%`} hint={`${status.analyst_feedback.confirmed} confirmed · ${status.analyst_feedback.benign} benign`} />
      </div>

      {settings && (
        <section className="bg-card border border-border rounded-xl p-4 flex flex-wrap items-center gap-4">
          <div>
            <div className="text-[13px] font-semibold">Sensitivity</div>
            <div className="text-[11.5px] text-muted-foreground">Changes how much evidence is needed to alert; the recorded deviations stay the same.</div>
          </div>
          <div className="flex gap-1" role="group" aria-label="Sensitivity">
            {(["low", "balanced", "high"] as Sensitivity[]).map((s) => (
              <Button key={s} size="sm" disabled={!isAdmin} variant={settings.sensitivity === s ? "default" : "outline"} onClick={() => setSensitivity(s)} aria-pressed={settings.sensitivity === s}>
                {s}
              </Button>
            ))}
          </div>
          <div className="text-[11.5px] text-muted-foreground font-mono">
            alert at risk ≥ {settings.effective.alert_score} · {settings.effective.min_families}+ independent signals
          </div>
        </section>
      )}

      {canTriage && (
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-[14px] font-semibold">Deviations</h2>
            <label className="text-[12px] flex items-center gap-2">
              <input type="checkbox" checked={onlyAlerts} onChange={(e) => setOnlyAlerts(e.target.checked)} /> alerts only
            </label>
          </div>
          {rows.length === 0 ? (
            <p className="text-[13px] text-muted-foreground">{onlyAlerts ? "No behavioural alerts." : "Nothing recorded yet."}</p>
          ) : (
            <ul className="space-y-2">
              {rows.map((a) => (
                <li key={a.id} className="bg-card border border-border rounded-lg p-3 text-[12.5px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11px] bg-muted px-1.5 py-0.5 rounded">{a.entity_type}:{a.entity_id}</span>
                    <span className="font-semibold">{FEATURE_LABEL[a.feature] ?? a.feature}</span>
                    <span className="font-mono text-[10.5px] text-muted-foreground">score {a.score.toFixed(2)}</span>
                    {a.alerted && <span className="text-[10.5px] px-1.5 py-0.5 rounded bg-severity-high/15 text-severity-high">alerted</span>}
                    {a.suppressed_reason && <span className="text-[10.5px] px-1.5 py-0.5 rounded bg-muted">withheld: {a.suppressed_reason}</span>}
                    {a.disposition !== "open" && <span className="text-[10.5px] px-1.5 py-0.5 rounded bg-muted">{a.disposition}</span>}
                    <span className="ml-auto text-[11px] text-muted-foreground">{new Date(a.observed_at).toLocaleString()}</span>
                  </div>
                  <p className="mt-1 text-foreground/85">{a.explanation.summary}</p>
                  {a.explanation.peer && (
                    <p className="text-[11.5px] text-muted-foreground">
                      Compared with {a.explanation.peer.peers} comparable entities ({a.explanation.peer.scope}): {Math.round(a.explanation.peer.prevalence * 100)}% do this.
                    </p>
                  )}
                  {a.disposition === "open" && (
                    <div className="mt-2 flex flex-wrap gap-2">
                      <Button size="sm" variant="outline" disabled={busy === a.id} onClick={() => judge(a, "confirmed")}>
                        <Check className="w-3.5 h-3.5 mr-1" /> Real
                      </Button>
                      <Button size="sm" variant="outline" disabled={busy === a.id} onClick={() => judge(a, "benign")}>
                        <X className="w-3.5 h-3.5 mr-1" /> Benign
                      </Button>
                      <Button size="sm" variant="outline" disabled={busy === a.id} onClick={() => judge(a, "expected")} title="Teach the baseline that this is normal">
                        <GraduationCap className="w-3.5 h-3.5 mr-1" /> Expected
                      </Button>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {canTriage && (
        <section className="bg-card border border-border rounded-xl p-4 space-y-3">
          <h2 className="text-[14px] font-semibold flex items-center gap-2"><ShieldQuestion className="w-4 h-4" /> What is normal for…</h2>
          <div className="flex gap-2">
            <input
              className="flex-1 bg-background border border-border rounded-md px-3 py-1.5 text-[13px]"
              placeholder="alice  or  host:web-01"
              aria-label="Entity"
              value={lookup}
              onChange={(e) => setLookup(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && show()}
            />
            <Button size="sm" onClick={show}>Show baseline</Button>
          </div>
          {baseline && (
            <div className="text-[12.5px] space-y-2" data-testid="baseline">
              <p>
                <strong>{baseline.entity.id}</strong> — {baseline.mature ? "baseline trusted" : `learning (needs ${baseline.requirements.min_events} events over ${baseline.requirements.min_days} days)`}
                : {baseline.events} events over {baseline.active_days} days{baseline.peer_group ? `, peer group ${baseline.peer_group}` : ""}.
              </p>
              <ul className="grid sm:grid-cols-2 gap-2">
                {Object.entries(baseline.features).map(([f, v]) => (
                  <li key={f} className={cn("bg-muted/40 rounded-md p-2")}>
                    <div className="font-semibold">{FEATURE_LABEL[f] ?? f}</div>
                    {v.top && <div className="text-muted-foreground font-mono text-[11px]">{v.top.map(([k, n]) => `${k} (${n})`).join(", ") || "-"}</div>}
                    {v.hour_histogram_utc && <div className="text-muted-foreground font-mono text-[11px]">busiest UTC hours: {v.hour_histogram_utc.map((c, h) => [h, c] as const).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([h]) => `${String(h).padStart(2, "0")}:00`).join(", ")}</div>}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
