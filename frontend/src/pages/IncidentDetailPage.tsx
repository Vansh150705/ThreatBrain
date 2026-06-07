import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { motion } from "motion/react";
import {
  ArrowLeft,
  AlertCircle,
  Loader2,
  ChevronRight,
  Globe,
} from "lucide-react";

import { api, type IncidentDetail, type IncidentThreatItem } from "@/lib/api";
import SeverityBadge from "@/components/SeverityBadge";
import StatusBadge from "@/components/StatusBadge";
import PriorityBadge from "@/components/PriorityBadge";

type BottomTab = "timeline" | "playbook";

function toRoman(n: number): string {
  const vals = [1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1];
  const syms = ["M", "CM", "D", "CD", "C", "XC", "L", "XL", "X", "IX", "V", "IV", "I"];
  let result = "";
  for (let i = 0; i < vals.length; i++) {
    while (n >= vals[i]) { result += syms[i]; n -= vals[i]; }
  }
  return result;
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const diffMs = Date.now() - new Date(iso).getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 60) return `${diffMins}m ago`;
  const h = Math.floor(diffMins / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function normalizeTimeline(
  timeline: IncidentDetail["timeline"]
): Array<{ ts?: string; phase?: string; event?: string; [k: string]: unknown }> {
  if (Array.isArray(timeline)) return timeline as Array<Record<string, unknown>>;
  if (timeline && typeof timeline === "object") {
    const arr = (timeline as Record<string, unknown>).events;
    if (Array.isArray(arr)) return arr as Array<Record<string, unknown>>;
  }
  return [];
}

function normalizePlaybookRuns(
  pr: IncidentDetail["playbook_runs"]
): Array<Record<string, unknown>> {
  if (Array.isArray(pr)) return pr as Array<Record<string, unknown>>;
  if (pr && typeof pr === "object") {
    const arr = (pr as Record<string, unknown>).runs;
    if (Array.isArray(arr)) return arr as Array<Record<string, unknown>>;
  }
  return [];
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
      <div className="text-[14px] font-medium text-foreground">{children}</div>
    </div>
  );
}

function InfoCard({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-card border border-border rounded-xl p-5 ${className}`}>
      {children}
    </div>
  );
}

export default function IncidentDetailPage() {
  const { identifier } = useParams<{ identifier: string }>();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [threats, setThreats] = useState<IncidentThreatItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [bottomTab, setBottomTab] = useState<BottomTab>("timeline");

  useEffect(() => {
    if (!identifier) return;
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.incidents.getIncident(identifier),
      api.incidents.getIncidentThreats(identifier),
    ])
      .then(([inc, thr]) => {
        if (cancelled) return;
        setIncident(inc);
        setThreats(thr.items);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, [identifier]);

  const backLink = (
    <Link
      to="/incidents"
      className="inline-flex items-center gap-1.5 text-[13px] text-muted-foreground hover:text-foreground transition-colors"
    >
      <ArrowLeft className="w-4 h-4" />
      Back to incidents
    </Link>
  );

  if (loading) {
    return (
      <div className="space-y-5">
        {backLink}
        <div className="flex items-center gap-2 text-muted-foreground text-[13px] py-8">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading incident...
        </div>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="space-y-5">
        {backLink}
        <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical shrink-0 mt-0.5" />
          <span className="text-[13px] text-foreground">{error || "Incident not found"}</span>
        </div>
      </div>
    );
  }

  const timelineEvents = normalizeTimeline(incident.timeline);
  const playbookRuns = normalizePlaybookRuns(incident.playbook_runs);
  const hasAiSummary = incident.ai_summary && Object.keys(incident.ai_summary).length > 0;
  const hasAttribution = incident.attribution && Object.keys(incident.attribution).length > 0;
  const hasBottomContent = timelineEvents.length > 0 || playbookRuns.length > 0;

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
        <div className="flex flex-wrap items-center gap-2 mb-3">
          <span className="font-mono text-[11px] bg-muted text-muted-foreground px-2 py-0.5 rounded">
            {incident.short_id}
          </span>
          <SeverityBadge severity={incident.severity} />
          <PriorityBadge priority={incident.priority} />
          <StatusBadge status={incident.status} />
        </div>
        <h1 className="text-[26px] font-semibold tracking-[-0.025em] text-foreground leading-[1.2]">
          {incident.title}
        </h1>
      </motion.div>

      {/* Stat strip */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.06 }}
        className="bg-card border border-border rounded-xl p-5 grid grid-cols-2 sm:grid-cols-4 gap-5"
      >
        <MetaSlot label="Confidence">
          <span className="font-mono tabular">{incident.confidence}%</span>
        </MetaSlot>
        <MetaSlot label="Risk score">
          <span className="font-mono tabular">{incident.risk_score ?? "—"}</span>
        </MetaSlot>
        <MetaSlot label="Threats">
          <span className="font-mono tabular">{incident.threat_count}</span>
        </MetaSlot>
        <MetaSlot label="Affected assets">
          <span className="font-mono tabular">{incident.asset_count}</span>
        </MetaSlot>
      </motion.div>

      {/* Main grid */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
        className="grid grid-cols-1 lg:grid-cols-3 gap-6"
      >
        {/* LEFT — 2 cols */}
        <div className="lg:col-span-2 space-y-5">
          {/* Description */}
          {incident.description && (
            <InfoCard>
              <SectionLabel>Description</SectionLabel>
              <p className="text-[13.5px] text-foreground/80 leading-[1.65]">
                {incident.description}
              </p>
            </InfoCard>
          )}

          {/* AI Summary */}
          {hasAiSummary && (
            <InfoCard>
              <SectionLabel>AI summary</SectionLabel>
              <pre className="font-mono text-[11.5px] text-foreground/80 bg-muted/40 rounded-lg p-3.5 overflow-auto max-h-72 whitespace-pre-wrap">
                {JSON.stringify(incident.ai_summary, null, 2)}
              </pre>
            </InfoCard>
          )}

          {/* Kill chain */}
          {incident.kill_chain.length > 0 && (
            <InfoCard>
              <SectionLabel>Kill chain</SectionLabel>
              <div className="flex flex-wrap items-center gap-1.5">
                {incident.kill_chain.map((stage, idx) => (
                  <div key={`${stage}-${idx}`} className="flex items-center gap-1.5">
                    <span className="inline-flex items-center gap-1.5 font-mono text-[11px] px-2.5 py-1 bg-muted text-muted-foreground border border-border rounded">
                      <span className="font-serif text-[10px] font-semibold">
                        {toRoman(idx + 1)}
                      </span>
                      {stage}
                    </span>
                    {idx < incident.kill_chain.length - 1 && (
                      <ChevronRight className="w-3.5 h-3.5 text-border" />
                    )}
                  </div>
                ))}
              </div>
            </InfoCard>
          )}

          {/* MITRE ATT&CK */}
          {(incident.mitre_tactics.length > 0 || incident.mitre_techniques.length > 0) && (
            <InfoCard>
              <SectionLabel>MITRE ATT&CK</SectionLabel>
              <div className="space-y-4">
                {incident.mitre_tactics.length > 0 && (
                  <div>
                    <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground font-semibold mb-2">
                      Tactics
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {incident.mitre_tactics.map((t) => (
                        <span
                          key={t}
                          className="font-mono text-[11px] px-2 py-0.5 bg-severity-medium/8 text-severity-medium border border-severity-medium/30 rounded"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {incident.mitre_techniques.length > 0 && (
                  <div>
                    <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground font-semibold mb-2">
                      Techniques
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {incident.mitre_techniques.map((t) => (
                        <span
                          key={t}
                          className="font-mono text-[11px] px-2 py-0.5 bg-muted text-muted-foreground border border-border rounded"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </InfoCard>
          )}

          {/* Threats in this incident */}
          {threats.length > 0 && (
            <InfoCard className="p-0 overflow-hidden">
              <div className="px-5 py-3.5 border-b border-border">
                <SectionLabel>Threats in this incident</SectionLabel>
                <span className="font-mono text-[11px] text-muted-foreground">{threats.length} total</span>
              </div>
              <div className="divide-y divide-border">
                {threats.map((threat) => (
                  <Link
                    key={threat.id}
                    to={`/threats/${threat.short_id}`}
                    className="flex items-center justify-between gap-3 px-5 py-3.5 hover:bg-accent/40 transition-colors group"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-[11px] text-muted-foreground">
                          {threat.short_id}
                        </span>
                        <SeverityBadge severity={threat.severity} />
                        <StatusBadge status={threat.status} />
                      </div>
                      <div className="text-[13px] font-medium text-foreground group-hover:text-foreground/70 truncate">
                        {threat.title}
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
                  </Link>
                ))}
              </div>
            </InfoCard>
          )}

          {/* Timeline + Playbook */}
          {hasBottomContent && (
            <InfoCard>
              <div className="flex items-center border-b border-border gap-5 mb-4">
                <button
                  onClick={() => setBottomTab("timeline")}
                  className={`pb-2 text-[12.5px] font-medium border-b-2 -mb-px transition-colors ${
                    bottomTab === "timeline"
                      ? "border-foreground text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Timeline ({timelineEvents.length})
                </button>
                <button
                  onClick={() => setBottomTab("playbook")}
                  className={`pb-2 text-[12.5px] font-medium border-b-2 -mb-px transition-colors ${
                    bottomTab === "playbook"
                      ? "border-foreground text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Playbook runs ({playbookRuns.length})
                </button>
              </div>

              {bottomTab === "timeline" && (
                timelineEvents.length === 0 ? (
                  <p className="text-[12.5px] text-muted-foreground italic">No timeline events.</p>
                ) : (
                  <ol className="relative border-l border-border ml-3 space-y-4">
                    {timelineEvents.map((evt, idx) => {
                      const ts =
                        (evt.ts as string) ||
                        (evt.timestamp as string) ||
                        "";
                      const event =
                        (evt.event as string) ||
                        (evt.action as string) ||
                        (evt.description as string) ||
                        JSON.stringify(evt);
                      const phase = evt.phase as string | undefined;
                      return (
                        <li key={idx} className="ml-4">
                          <div className="absolute -left-1.5 w-3 h-3 bg-foreground/20 rounded-full border-2 border-background" />
                          {ts && (
                            <div className="font-mono text-[10px] text-muted-foreground mb-0.5">
                              {formatDate(ts)}
                            </div>
                          )}
                          <div className="text-[13px] text-foreground/80">{event}</div>
                          {phase && (
                            <div className="font-mono text-[10px] text-muted-foreground mt-0.5">
                              {phase}
                            </div>
                          )}
                        </li>
                      );
                    })}
                  </ol>
                )
              )}

              {bottomTab === "playbook" && (
                playbookRuns.length === 0 ? (
                  <p className="text-[12.5px] text-muted-foreground italic">
                    No playbook actions recorded yet.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {playbookRuns.map((run, idx) => (
                      <div
                        key={idx}
                        className="p-3 bg-muted/40 rounded-lg"
                      >
                        <pre className="font-mono text-[11.5px] text-foreground/80 whitespace-pre-wrap overflow-auto max-h-48">
                          {JSON.stringify(run, null, 2)}
                        </pre>
                      </div>
                    ))}
                  </div>
                )
              )}
            </InfoCard>
          )}
        </div>

        {/* RIGHT sidebar — 1 col */}
        <div className="space-y-5">
          {/* Tags */}
          {incident.tags && incident.tags.length > 0 && (
            <InfoCard>
              <SectionLabel>Tags</SectionLabel>
              <div className="flex flex-wrap gap-1.5">
                {incident.tags.map((tag) => (
                  <span
                    key={tag}
                    className="font-mono text-[11px] px-2 py-0.5 bg-muted text-muted-foreground rounded border border-border"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </InfoCard>
          )}

          {/* Attribution */}
          {hasAttribution && (
            <InfoCard>
              <SectionLabel>Attribution</SectionLabel>
              <pre className="font-mono text-[11.5px] text-foreground/80 bg-muted/40 rounded-lg p-3 overflow-auto max-h-48 whitespace-pre-wrap">
                {JSON.stringify(incident.attribution, null, 2)}
              </pre>
            </InfoCard>
          )}

          {/* Source IPs */}
          {incident.source_ips.length > 0 && (
            <InfoCard>
              <SectionLabel>Source IPs</SectionLabel>
              <div className="space-y-1">
                {incident.source_ips.map((ip) => (
                  <div
                    key={ip}
                    className="flex items-center gap-2 font-mono text-[12px] text-foreground bg-muted/40 rounded-md px-3 py-1.5"
                  >
                    <Globe className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                    {ip}
                  </div>
                ))}
              </div>
            </InfoCard>
          )}

          {/* Lifecycle */}
          <InfoCard>
            <SectionLabel>Lifecycle</SectionLabel>
            <div className="space-y-3">
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground mb-0.5">
                  First seen
                </div>
                <div className="text-[12.5px] text-foreground">{formatDate(incident.first_seen_at)}</div>
              </div>
              <div className="border-t border-border pt-3">
                <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground mb-0.5">
                  Last seen
                </div>
                <div className="text-[12.5px] text-foreground">
                  {formatDate(incident.last_seen_at)}
                  <span className="text-muted-foreground ml-1.5 text-[11px]">
                    ({timeAgo(incident.last_seen_at)})
                  </span>
                </div>
              </div>
              {incident.contained_at && (
                <div className="border-t border-border pt-3">
                  <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground mb-0.5">
                    Contained
                  </div>
                  <div className="text-[12.5px] text-foreground">
                    {formatDate(incident.contained_at)}
                  </div>
                </div>
              )}
              {incident.resolved_at && (
                <div className="border-t border-border pt-3">
                  <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground mb-0.5">
                    Resolved
                  </div>
                  <div className="text-[12.5px] text-foreground">
                    {formatDate(incident.resolved_at)}
                  </div>
                </div>
              )}
            </div>
          </InfoCard>
        </div>
      </motion.div>
    </div>
  );
}
