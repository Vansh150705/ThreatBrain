import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "motion/react";
import {
  ArrowUpRight,
  Loader2,
  AlertCircle,
  Activity,
  ShieldAlert,
  AlertOctagon,
  CheckCircle2,
} from "lucide-react";

import { api, type Agent, type DashboardStats } from "@/lib/api";
import { ApiError } from "@/lib/api";
import { useUserStore } from "@/store/useUserStore";
import TriggerPipelineDialog from "@/components/TriggerPipelineDialog";
import { Olivia, Henry, Nathan, Rachel, Frank, Claire } from "@/components/CrewPortraits";
import {
  useRealtimeThreats,
  type RealtimeThreatRow,
} from "@/hooks/useRealtimeThreats";

const CREW = {
  triage: { name: "Olivia", portrait: (c?: string) => <Olivia className={c} /> },
  threat_intel: { name: "Henry", portrait: (c?: string) => <Henry className={c} /> },
  investigation: { name: "Nathan", portrait: (c?: string) => <Nathan className={c} /> },
  response: { name: "Rachel", portrait: (c?: string) => <Rachel className={c} /> },
  forensics: { name: "Frank", portrait: (c?: string) => <Frank className={c} /> },
  compliance: { name: "Claire", portrait: (c?: string) => <Claire className={c} /> },
};

type CrewEntry = (typeof CREW)[keyof typeof CREW];

function getCrew(agentKey: string): CrewEntry | undefined {
  return (CREW as Record<string, CrewEntry>)[agentKey.toLowerCase().replace(/-/g, "_")];
}

const AGENT_DISPLAY: Record<string, string> = {
  triage: "Triage",
  threat_intel: "Threat Intel",
  investigation: "Investigation",
  response: "Response",
  forensics: "Forensics",
  compliance: "Compliance",
  hunt: "Hunt",
};

const SEVERITY_TONE: Record<string, string> = {
  critical: "text-severity-critical border-severity-critical/30 bg-severity-critical/8",
  high: "text-severity-high border-severity-high/30 bg-severity-high/8",
  medium: "text-severity-medium border-severity-medium/30 bg-severity-medium/8",
  low: "text-severity-low border-severity-low/30 bg-severity-low/8",
  info: "text-severity-info border-severity-info/30 bg-severity-info/8",
};

function timeAgo(iso: string): string {
  const diffMins = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const h = Math.floor(diffMins / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

// ─────────── Live indicator (connection status pill) ───────────
function LiveIndicator({
  status,
}: {
  status: "connecting" | "live" | "disconnected" | "error";
}) {
  const config = {
    live: { dotClass: "bg-severity-low", label: "Live", pulse: true },
    connecting: {
      dotClass: "bg-muted-foreground/40",
      label: "Connecting",
      pulse: false,
    },
    disconnected: {
      dotClass: "bg-muted-foreground/30",
      label: "Offline",
      pulse: false,
    },
    error: {
      dotClass: "bg-severity-critical",
      label: "Error",
      pulse: false,
    },
  }[status];

  return (
    <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
      <span className="relative flex items-center justify-center">
        <span className={`w-1.5 h-1.5 rounded-full ${config.dotClass}`} />
        {config.pulse && (
          <span
            className={`absolute w-1.5 h-1.5 rounded-full ${config.dotClass} animate-ping opacity-75`}
          />
        )}
      </span>
      <span>{config.label}</span>
    </div>
  );
}

export default function DashboardPage() {
  const profile = useUserStore((s) => s.profile);
  const orgName = useMemo(() => profile?.organization?.name ?? "your organization", [profile]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);

  // Real-time threats (seed with initial fetch, then live INSERT events stream in)
// Real-time threats (seed with initial fetch, then live INSERT events stream in)
  const { threats, status: liveStatus, setThreats, newCount } = useRealtimeThreats({
    maxItems: 50,
    highlightMs: 3000,
  });

  useEffect(() => {
    setLoading(true);
    Promise.all([
      api.agents.listAgents(),
      api.stats.getDashboardStats(),
      api.threats
        .listThreats({ page: 1, page_size: 10 })
        .then((r) => r.items as RealtimeThreatRow[])
        .catch(() => [] as RealtimeThreatRow[]),
    ])
      .then(([agentsRes, statsRes, threatsRes]) => {
        setAgents(agentsRes.items);
        setStats(statsRes);
        setThreats(threatsRes);
      })
      .catch((err) => {
        if (err instanceof ApiError) setError(`${err.status} — ${err.message}`);
        else setError(String(err));
      })
      .finally(() => setLoading(false));
  }, [setThreats]);

  const totalRuns = agents.reduce((sum, a) => sum + a.total_runs, 0);
  const successfulRuns = agents.reduce((sum, a) => sum + a.successful_runs, 0);
  const activeAgents = agents.filter((a) => a.enabled).length;
  const successRate = totalRuns > 0 ? Math.round((successfulRuns / totalRuns) * 100) : 100;

  const lastRunAt = useMemo(() => {
    const times = agents
      .map((a) => a.last_run_at)
      .filter((t): t is string => !!t)
      .map((t) => new Date(t).getTime());
    if (times.length === 0) return null;
    return new Date(Math.max(...times)).toISOString();
  }, [agents]);

  return (
    <div className="space-y-8 pb-12">
      {/* ─────── HEADER ─────── */}
      <motion.section
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="flex items-start justify-between gap-6 flex-wrap"
      >
        <div>
          <h1 className="title-serif text-[28px] tracking-[-0.03em] text-foreground">
            Operations overview
          </h1>
          <p className="text-[13.5px] text-muted-foreground mt-1">
            Live status across <span className="text-foreground font-medium">{orgName}</span>.
            {lastRunAt && (
              <>
                <span className="mx-2 text-foreground/30">·</span>
                <span className="font-mono text-[12.5px]">Last run {timeAgo(lastRunAt)}</span>
              </>
            )}
          </p>
        </div>
        <TriggerPipelineDialog />
      </motion.section>

      {/* ─────── KEY METRICS ─────── */}
      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.05 }}
      >
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            {
              label: "Active agents",
              value: loading ? "—" : `${activeAgents}/${agents.length}`,
              caption: loading ? "" : "all online",
              icon: Activity,
              iconBg: "bg-severity-low/10 text-severity-low",
            },
            {
              label: "Total runs",
              value: loading ? "—" : totalRuns.toLocaleString(),
              caption: loading ? "" : `${successRate}% success rate`,
              icon: CheckCircle2,
              iconBg: "bg-severity-info/10 text-severity-info",
            },
{
              label: "Open threats",
              value:
                loading || !stats
                  ? "—"
                  : (stats.open_threats + newCount).toString(),
              caption:
                loading || !stats
                  ? ""
                  : newCount > 0
                  ? `+${newCount} just now · ${stats.total_threats + newCount} total`
                  : `${stats.critical_threats} critical · ${stats.total_threats} total`,
              link: "/threats",
              icon: ShieldAlert,
              iconBg: "bg-severity-high/10 text-severity-high",
            },
            {
              label: "Open incidents",
              value: loading || !stats ? "—" : stats.open_incidents.toString(),
              caption: loading || !stats ? "" : "awaiting review",
              link: "/incidents",
              icon: AlertOctagon,
              iconBg: "bg-severity-critical/10 text-severity-critical",
            },
          ].map((s) => {
            const Icon = s.icon;
            const inner = (
              <div className="bg-card border border-border rounded-xl p-5 hover:border-foreground/20 transition-colors group h-full">
                <div className="flex items-start justify-between mb-4">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${s.iconBg}`}>
                    <Icon className="w-4 h-4" strokeWidth={2} />
                  </div>
                  {s.link && (
                    <ArrowUpRight className="w-3.5 h-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                  )}
                </div>
                <div className="text-[12px] text-muted-foreground font-medium mb-1.5">
                  {s.label}
                </div>
                <div className="text-[32px] leading-[1] tracking-[-0.025em] font-semibold text-foreground tabular">
                  {s.value}
                </div>
                <div className="font-mono text-[11px] text-muted-foreground mt-3 tracking-tight">
                  {s.caption || "—"}
                </div>
              </div>
            );
            return s.link ? (
              <Link key={s.label} to={s.link} className="block">
                {inner}
              </Link>
            ) : (
              <div key={s.label}>{inner}</div>
            );
          })}
        </div>
      </motion.section>

      {/* ─────── TWO-COLUMN: THREATS + AGENTS ─────── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Recent threats (LIVE) */}
        <motion.section
          initial={{ opacity: 0, y: 10 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4 }}
          className="lg:col-span-3"
        >
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
              <div>
                <div className="flex items-center gap-3">
                  <h2 className="text-[15px] font-semibold tracking-[-0.015em] text-foreground">
                    Recent threats
                  </h2>
                  <LiveIndicator status={liveStatus} />
                </div>
                <p className="text-[12px] text-muted-foreground mt-0.5">
                  Streaming via Supabase Realtime.
                </p>
              </div>
              <Link
                to="/threats"
                className="inline-flex items-center gap-1 text-[12.5px] font-medium text-foreground hover:text-muted-foreground transition-colors group"
              >
                View all
                <ArrowUpRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
              </Link>
            </div>

            {loading && (
              <div className="flex items-center gap-2 text-muted-foreground text-[13px] p-8">
                <Loader2 className="w-4 h-4 animate-spin" />
                Loading threats…
              </div>
            )}

            {error && (
              <div className="m-5 flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
                <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />
                <div className="text-[13px] text-foreground">
                  <div className="font-semibold">Could not load threats</div>
                  <div className="text-muted-foreground mt-0.5 font-mono text-[11px]">{error}</div>
                </div>
              </div>
            )}

            {!loading && !error && threats.length === 0 && (
              <div className="py-12 text-center px-6">
                <ShieldAlert className="w-8 h-8 text-muted-foreground/40 mx-auto mb-3" strokeWidth={1.5} />
                <p className="text-[13.5px] text-muted-foreground">No threats detected.</p>
                <p className="text-[12px] text-muted-foreground/70 mt-1">
                  New threats will appear here automatically.
                </p>
              </div>
            )}

            {!loading && !error && threats.length > 0 && (
              <div className="divide-y divide-border">
                <AnimatePresence initial={false}>
                  {threats.slice(0, 6).map((t) => (
                    <motion.div
                      key={t.id}
                      layout
                      initial={{ opacity: 0, y: -8, scale: 0.98 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      exit={{ opacity: 0, x: 8 }}
                      transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
                    >
                      <Link
                        to={`/threats/${t.short_id}`}
                        className={`relative flex items-center gap-3 px-5 py-3.5 transition-colors group ${
                          t._isNew
                            ? "bg-severity-low/5 hover:bg-severity-low/10"
                            : "hover:bg-accent/40"
                        }`}
                      >
                        {/* Pulse stripe on the left edge for newly arrived threats */}
                        {t._isNew && (
                          <motion.span
                            initial={{ opacity: 0, scaleY: 0.5 }}
                            animate={{ opacity: 1, scaleY: 1 }}
                            className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-7 rounded-r bg-severity-low"
                          />
                        )}
                        <span
                          className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] uppercase tracking-[0.06em] font-mono font-semibold border ${
                            SEVERITY_TONE[t.severity.toLowerCase()] ?? SEVERITY_TONE.info
                          }`}
                        >
                          {t.severity}
                        </span>
                        <span className="font-mono text-[11px] text-muted-foreground w-20 flex-shrink-0 tabular">
                          {t.short_id}
                        </span>
                        <span className="text-[13.5px] text-foreground font-medium flex-1 truncate group-hover:text-foreground/70 transition-colors">
                          {t.title}
                        </span>
                        {t._isNew ? (
                          <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-severity-low font-semibold whitespace-nowrap hidden md:inline">
                            new
                          </span>
                        ) : (
                          <span className="font-mono text-[11px] text-muted-foreground whitespace-nowrap hidden md:inline">
                            {timeAgo(t.detected_at)}
                          </span>
                        )}
                        <ArrowUpRight className="w-3.5 h-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                      </Link>
                    </motion.div>
                  ))}
                </AnimatePresence>
              </div>
            )}
          </div>
        </motion.section>

        {/* Pipeline status */}
        <motion.section
          initial={{ opacity: 0, y: 10 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4, delay: 0.05 }}
          className="lg:col-span-2"
        >
          <div className="bg-card border border-border rounded-xl overflow-hidden h-full">
            <div className="px-5 py-4 border-b border-border">
              <h2 className="text-[15px] font-semibold tracking-[-0.015em] text-foreground">
                Pipeline health
              </h2>
              <p className="text-[12px] text-muted-foreground mt-0.5">
                Per-agent runtime.
              </p>
            </div>

            {loading ? (
              <div className="flex items-center gap-2 text-muted-foreground text-[13px] p-8">
                <Loader2 className="w-4 h-4 animate-spin" />
                Loading…
              </div>
            ) : (
              <div className="p-5 space-y-3">
                {agents.slice(0, 6).map((a, i) => {
                  const displayKey = a.agent_key.toLowerCase().replace(/-/g, "_");
                  const displayName = AGENT_DISPLAY[displayKey] ?? a.name;
                  const maxLatency = 4000;
                  const widthPct = Math.min(
                    100,
                    Math.max(8, ((a.avg_latency_ms ?? 0) / maxLatency) * 100)
                  );
                  return (
                    <motion.div
                      key={a.id}
                      initial={{ opacity: 0, x: -4 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.04 }}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <div className="flex items-center gap-2">
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              a.enabled ? "bg-severity-low" : "bg-muted-foreground/30"
                            }`}
                          />
                          <span className="text-[12.5px] font-medium text-foreground">
                            {displayName}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 font-mono text-[10.5px] text-muted-foreground tabular">
                          <span>{a.total_runs} runs</span>
                          <span className="text-foreground font-semibold">
                            {a.avg_latency_ms ?? "—"}ms
                          </span>
                        </div>
                      </div>
                      <div className="h-1 rounded-full bg-muted overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${widthPct}%` }}
                          transition={{ duration: 0.6, delay: i * 0.05 }}
                          className="h-full bg-foreground/80 rounded-full"
                        />
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            )}
          </div>
        </motion.section>
      </div>

      {/* ─────── AGENT ROSTER ─────── */}
      <motion.section
        initial={{ opacity: 0, y: 10 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.4 }}
      >
        <div className="flex items-end justify-between mb-4">
          <div>
            <h2 className="text-[15px] font-semibold tracking-[-0.015em] text-foreground">
              Agent roster
            </h2>
            <p className="text-[12px] text-muted-foreground mt-0.5">
              Six specialists, one orchestrator.
            </p>
          </div>
          <Link
            to="/agents"
            className="inline-flex items-center gap-1 text-[12.5px] font-medium text-foreground hover:text-muted-foreground transition-colors group whitespace-nowrap"
          >
            View all
            <ArrowUpRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
          </Link>
        </div>

        {loading ? (
          <div className="flex items-center gap-2 text-muted-foreground text-[13px] py-8">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading agents…
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            {agents.slice(0, 6).map((agent, i) => {
              const crew = getCrew(agent.agent_key);
              const displayKey = agent.agent_key.toLowerCase().replace(/-/g, "_");
              const displayName = AGENT_DISPLAY[displayKey] ?? agent.name;
              return (
                <motion.div
                  key={agent.id}
                  initial={{ opacity: 0, y: 6 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.04 }}
                  whileHover={{ y: -2 }}
                >
                  <Link
                    to={`/agents/${agent.agent_key}`}
                    className="block bg-card border border-border rounded-xl p-4 hover:border-foreground/25 transition-all group h-full"
                  >
                    <div className="flex items-start gap-3">
                      <div className="w-10 h-10 rounded-full bg-muted overflow-hidden flex-shrink-0 ring-1 ring-border">
                        {crew ? (
                          crew.portrait("w-full h-full")
                        ) : (
                          <div className="w-full h-full flex items-center justify-center text-[14px] text-muted-foreground">
                            {agent.name.charAt(0)}
                          </div>
                        )}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="text-[13px] font-semibold text-foreground tracking-[-0.01em] leading-tight">
                          {displayName}
                        </div>
                        <div className="font-mono text-[10px] text-muted-foreground mt-0.5 truncate">
                          {crew?.name ?? agent.agent_key}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center justify-between mt-3 pt-3 border-t border-border font-mono text-[10.5px] text-muted-foreground tabular">
                      <span className="flex items-center gap-1.5">
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            agent.enabled ? "bg-severity-low" : "bg-muted-foreground/30"
                          }`}
                        />
                        {agent.enabled ? "Online" : "Offline"}
                      </span>
                      <span>{agent.total_runs} runs</span>
                    </div>
                  </Link>
                </motion.div>
              );
            })}
          </div>
        )}
      </motion.section>
    </div>
  );
}