import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { motion } from "motion/react";
import {
  ArrowLeft,
  AlertCircle,
  Loader2,
  Globe,
  Target,
  User,
  ChevronRight,
} from "lucide-react";

import { api, type ThreatDetail } from "@/lib/api";
import SeverityBadge from "@/components/SeverityBadge";
import StatusBadge from "@/components/StatusBadge";

type IocTab = "source" | "targets" | "users";

function toRoman(n: number): string {
  const vals = [1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1];
  const syms = ["M", "CM", "D", "CD", "C", "XC", "L", "XL", "X", "IX", "V", "IV", "I"];
  let result = "";
  for (let i = 0; i < vals.length; i++) {
    while (n >= vals[i]) { result += syms[i]; n -= vals[i]; }
  }
  return result;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function timeAgo(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 60) return `${diffMins}m ago`;
  const h = Math.floor(diffMins / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
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

export default function ThreatDetailPage() {
  const { identifier } = useParams<{ identifier: string }>();
  const [threat, setThreat] = useState<ThreatDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [iocTab, setIocTab] = useState<IocTab>("source");

  useEffect(() => {
    if (!identifier) return;
    let cancelled = false;
    setLoading(true);
    setError(null);

    api.threats
      .getThreat(identifier)
      .then((res) => { if (!cancelled) setThreat(res); })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, [identifier]);

  const backLink = (
    <Link
      to="/threats"
      className="inline-flex items-center gap-1.5 text-[13px] text-muted-foreground hover:text-foreground transition-colors"
    >
      <ArrowLeft className="w-4 h-4" />
      Back to threats
    </Link>
  );

  if (loading) {
    return (
      <div className="space-y-5">
        {backLink}
        <div className="flex items-center gap-2 text-muted-foreground text-[13px] py-8">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading threat...
        </div>
      </div>
    );
  }

  if (error || !threat) {
    return (
      <div className="space-y-5">
        {backLink}
        <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical shrink-0 mt-0.5" />
          <span className="text-[13px] text-foreground">{error || "Threat not found"}</span>
        </div>
      </div>
    );
  }

  const hasIocs =
    threat.source_ips.length > 0 ||
    threat.target_ips.length > 0 ||
    threat.affected_users.length > 0;

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
            {threat.short_id}
          </span>
          <SeverityBadge severity={threat.severity} />
          <StatusBadge status={threat.status} />
        </div>
        <h1 className="title-serif text-[28px] tracking-[-0.03em] text-foreground leading-[1.2]">
          {threat.title}
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
          <span className="font-mono tabular">{threat.confidence}%</span>
        </MetaSlot>
        <MetaSlot label="Risk score">
          <span className="font-mono tabular">{threat.risk_score ?? "—"}</span>
        </MetaSlot>
        <MetaSlot label="Detected">
          <span title={formatDate(threat.detected_at)}>{timeAgo(threat.detected_at)}</span>
        </MetaSlot>
        <MetaSlot label="Assigned to">
          {threat.assigned_to ? (
            <span className="font-mono text-[12px]">{threat.assigned_to.slice(0, 8)}...</span>
          ) : (
            <span className="text-muted-foreground font-normal text-[13px]">Unassigned</span>
          )}
        </MetaSlot>
      </motion.div>

      {/* Main grid */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
        className="grid grid-cols-1 lg:grid-cols-3 gap-6"
      >
        {/* left column */}
        <div className="lg:col-span-2 space-y-5">
          {/* Description */}
          {threat.description && (
            <InfoCard>
              <SectionLabel>Description</SectionLabel>
              <p className="text-[13.5px] text-foreground/80 leading-[1.65]">
                {threat.description}
              </p>
            </InfoCard>
          )}

          {/* AI Analysis */}
          {threat.ai_analysis && Object.keys(threat.ai_analysis).length > 0 && (
            <InfoCard>
              <SectionLabel>AI analysis</SectionLabel>
              <pre className="font-mono text-[11.5px] text-foreground/80 bg-muted/40 rounded-lg p-3.5 overflow-auto max-h-72 whitespace-pre-wrap">
                {JSON.stringify(threat.ai_analysis, null, 2)}
              </pre>
            </InfoCard>
          )}

          {/* MITRE ATT&CK */}
          {(threat.mitre_tactics.length > 0 || threat.mitre_techniques.length > 0) && (
            <InfoCard>
              <SectionLabel>MITRE ATT&CK</SectionLabel>
              <div className="space-y-4">
                {threat.mitre_tactics.length > 0 && (
                  <div>
                    <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground font-semibold mb-2">
                      Tactics
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {threat.mitre_tactics.map((t) => (
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
                {threat.mitre_techniques.length > 0 && (
                  <div>
                    <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground font-semibold mb-2">
                      Techniques
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {threat.mitre_techniques.map((t) => (
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

          {/* Attack Chain */}
          {threat.attack_chain.length > 0 && (
            <InfoCard>
              <SectionLabel>Attack chain</SectionLabel>
              <ol className="space-y-3">
                {threat.attack_chain.map((step, idx) => (
                  <li key={idx} className="flex items-start gap-3">
                    <span className="shrink-0 w-6 h-6 rounded-full bg-muted flex items-center justify-center font-serif text-[10px] font-semibold text-muted-foreground mt-0.5">
                      {toRoman(idx + 1)}
                    </span>
                    <span className="text-[13.5px] text-foreground/80 leading-relaxed">{step}</span>
                  </li>
                ))}
              </ol>
            </InfoCard>
          )}

          {/* IOCs */}
          {hasIocs && (
            <InfoCard>
              <SectionLabel>Indicators of compromise</SectionLabel>
              <div className="flex items-center border-b border-border gap-5 mb-4">
                <button
                  onClick={() => setIocTab("source")}
                  className={`pb-2 text-[12.5px] font-medium border-b-2 -mb-px transition-colors ${
                    iocTab === "source"
                      ? "border-foreground text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Source IPs ({threat.source_ips.length})
                </button>
                <button
                  onClick={() => setIocTab("targets")}
                  className={`pb-2 text-[12.5px] font-medium border-b-2 -mb-px transition-colors ${
                    iocTab === "targets"
                      ? "border-foreground text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Target IPs ({threat.target_ips.length})
                </button>
                <button
                  onClick={() => setIocTab("users")}
                  className={`pb-2 text-[12.5px] font-medium border-b-2 -mb-px transition-colors ${
                    iocTab === "users"
                      ? "border-foreground text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Users ({threat.affected_users.length})
                </button>
              </div>

              {iocTab === "source" && (
                threat.source_ips.length === 0 ? (
                  <p className="text-[12.5px] text-muted-foreground italic">No source IPs recorded.</p>
                ) : (
                  <div className="space-y-1">
                    {threat.source_ips.map((ip) => (
                      <div
                        key={ip}
                        className="flex items-center gap-2 font-mono text-[12px] text-foreground bg-muted/40 rounded-md px-3 py-1.5"
                      >
                        <Globe className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                        {ip}
                      </div>
                    ))}
                  </div>
                )
              )}
              {iocTab === "targets" && (
                threat.target_ips.length === 0 ? (
                  <p className="text-[12.5px] text-muted-foreground italic">No target IPs recorded.</p>
                ) : (
                  <div className="space-y-1">
                    {threat.target_ips.map((ip) => (
                      <div
                        key={ip}
                        className="flex items-center gap-2 font-mono text-[12px] text-foreground bg-muted/40 rounded-md px-3 py-1.5"
                      >
                        <Target className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                        {ip}
                      </div>
                    ))}
                  </div>
                )
              )}
              {iocTab === "users" && (
                threat.affected_users.length === 0 ? (
                  <p className="text-[12.5px] text-muted-foreground italic">No affected users recorded.</p>
                ) : (
                  <div className="space-y-1">
                    {threat.affected_users.map((user) => (
                      <div
                        key={user}
                        className="flex items-center gap-2 text-[12.5px] text-foreground bg-muted/40 rounded-md px-3 py-1.5"
                      >
                        <User className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                        {user}
                      </div>
                    ))}
                  </div>
                )
              )}
            </InfoCard>
          )}
        </div>

        {/* right sidebar */}
        <div className="space-y-5">
          {/* Tags */}
          {threat.tags.length > 0 && (
            <InfoCard>
              <SectionLabel>Tags</SectionLabel>
              <div className="flex flex-wrap gap-1.5">
                {threat.tags.map((tag) => (
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

          {/* Related */}
          <InfoCard>
            <SectionLabel>Related</SectionLabel>
            {threat.incident_id ? (
              <Link
                to={`/incidents/${threat.incident_id}`}
                className="flex items-center justify-between p-2.5 -mx-2.5 rounded-lg hover:bg-muted/50 transition-colors group"
              >
                <div>
                  <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground mb-0.5">
                    Incident
                  </div>
                  <div className="text-[13px] font-medium text-foreground group-hover:text-foreground/70">
                    View parent incident
                  </div>
                </div>
                <ChevronRight className="w-4 h-4 text-muted-foreground" />
              </Link>
            ) : (
              <p className="text-[12.5px] text-muted-foreground">No related incident.</p>
            )}
            {threat.primary_asset_id && (
              <div className="mt-3 pt-3 border-t border-border">
                <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground mb-0.5">
                  Primary asset
                </div>
                <div className="font-mono text-[12px] text-foreground">
                  {threat.primary_asset_id.slice(0, 8)}...
                </div>
              </div>
            )}
          </InfoCard>

          {/* Timeline */}
          <InfoCard>
            <SectionLabel>Timeline</SectionLabel>
            <div className="space-y-3">
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground mb-0.5">
                  Detected
                </div>
                <div className="text-[12.5px] text-foreground">{formatDate(threat.detected_at)}</div>
              </div>
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground mb-0.5">
                  Created
                </div>
                <div className="text-[12.5px] text-foreground">{formatDate(threat.created_at)}</div>
              </div>
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground mb-0.5">
                  Updated
                </div>
                <div className="text-[12.5px] text-foreground">{formatDate(threat.updated_at)}</div>
              </div>
              {threat.resolved_at && (
                <div>
                  <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground mb-0.5">
                    Resolved
                  </div>
                  <div className="text-[12.5px] text-foreground">{formatDate(threat.resolved_at)}</div>
                </div>
              )}
            </div>
          </InfoCard>
        </div>
      </motion.div>
    </div>
  );
}
