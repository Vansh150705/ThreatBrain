import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { motion } from "motion/react";
import { Loader2, AlertCircle, ArrowUpRight, ArrowLeft, Activity } from "lucide-react";

import { api, type Agent, ApiError, withColdStartRetry } from "@/lib/api";
import type { AgentRunSummary } from "@/lib/api/types";
import { CREW_PORTRAITS, CREW_META } from "@/components/CrewPortraits";
import ColdStartNotice from "@/components/ColdStartNotice";

function formatLatency(ms: number | null): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

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

function successRateNum(agent: Agent): number | null {
  if (agent.total_runs === 0) return null;
  return Math.round((agent.successful_runs / agent.total_runs) * 100);
}

// Canonical order alerts flow through the pipeline; `hunt` runs proactively, so
// it trails the linear stages. Agents not listed fall to the end.
const PIPELINE_ORDER = [
  "triage",
  "threat_intel",
  "investigation",
  "response",
  "forensics",
  "compliance",
  "hunt",
];

function pipelineRank(key: string): number {
  const i = PIPELINE_ORDER.indexOf(key);
  return i === -1 ? PIPELINE_ORDER.length : i;
}

// Restrained per-agent accents drawn from the SOC severity palette, so the crew
// reads as distinct specialists without turning the grid into a rainbow.
const AGENT_ACCENTS: Record<string, string> = {
  triage: "oklch(0.68 0.155 75)", // amber
  threat_intel: "oklch(0.55 0.155 245)", // blue
  investigation: "oklch(0.55 0.16 292)", // violet
  response: "oklch(0.52 0.13 158)", // signal green
  forensics: "oklch(0.60 0.11 218)", // cyan
  compliance: "oklch(0.62 0.18 35)", // rose
  hunt: "oklch(0.60 0.12 190)", // teal
};
const DEFAULT_ACCENT = "oklch(0.55 0.02 250)";

// Mix an accent with transparency for tinted fills/rings without extra tokens.
function tint(accent: string, pct: number): string {
  return `color-mix(in oklch, ${accent} ${pct}%, transparent)`;
}

function SuccessMeter({ rate, accent }: { rate: number | null; accent: string }) {
  return (
    <div className="h-1 rounded-full bg-muted overflow-hidden">
      <motion.div
        className="h-full rounded-full"
        style={{ backgroundColor: accent }}
        initial={{ width: 0 }}
        animate={{ width: rate == null ? "0%" : `${rate}%` }}
        transition={{ duration: 0.7, ease: "easeOut", delay: 0.2 }}
      />
    </div>
  );
}

function FleetSummary({ agents }: { agents: Agent[] }) {
  const active = agents.filter((a) => a.enabled).length;
  const totalRuns = agents.reduce((s, a) => s + a.total_runs, 0);
  const totalOk = agents.reduce((s, a) => s + a.successful_runs, 0);
  const overall = totalRuns ? Math.round((totalOk / totalRuns) * 100) : null;

  // Latency weighted by run count, so busy agents count for more.
  const withLat = agents.filter((a) => a.avg_latency_ms != null && a.total_runs > 0);
  const latRuns = withLat.reduce((s, a) => s + a.total_runs, 0);
  const avgLat = latRuns
    ? Math.round(withLat.reduce((s, a) => s + (a.avg_latency_ms as number) * a.total_runs, 0) / latRuns)
    : null;

  const tiles = [
    { label: "Agents online", value: `${active}/${agents.length}` },
    { label: "Pipeline runs", value: totalRuns.toLocaleString() },
    { label: "Success rate", value: overall == null ? "—" : `${overall}%` },
    { label: "Avg latency", value: formatLatency(avgLat) },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: 0.04 }}
      className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4"
    >
      {tiles.map((t) => (
        <div key={t.label} className="bg-card border border-border rounded-xl p-4 sm:p-5">
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1.5">
            {t.label}
          </div>
          <div className="text-[22px] sm:text-[24px] font-semibold text-foreground tabular tracking-[-0.02em]">
            {t.value}
          </div>
        </div>
      ))}
    </motion.div>
  );
}

function StatusDot({ status }: { status: string }) {
  const s = status.toLowerCase();
  const isOk = s === "completed" || s === "success" || s === "ok";
  const isFail = s === "failed" || s === "error";
  const color = isOk
    ? "bg-severity-low"
    : isFail
    ? "bg-severity-critical"
    : "bg-severity-info";

  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`w-1.5 h-1.5 rounded-full ${color}`} />
      <span className="font-mono text-[11px] text-muted-foreground">{status}</span>
    </span>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-3">
      {children}
    </div>
  );
}

function AgentCard({ agent, index, step }: { agent: Agent; index: number; step: number }) {
  const Portrait = CREW_PORTRAITS[agent.agent_key];
  const meta = CREW_META[agent.agent_key];
  const accent = AGENT_ACCENTS[agent.agent_key] ?? DEFAULT_ACCENT;
  const name = meta?.name ?? agent.name;
  const rate = successRateNum(agent);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05, duration: 0.35 }}
      className="group relative bg-card border border-border rounded-xl p-4 sm:p-5 transition-all hover:border-foreground/15 hover:shadow-[0_1px_2px_rgba(16,24,40,0.04),0_14px_30px_-16px_rgba(16,24,40,0.14)]"
    >
      {/* accent hairline bleeding in from the left edge */}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-px rounded-t-xl"
        style={{ background: `linear-gradient(90deg, ${tint(accent, 60)}, transparent 65%)` }}
      />

      <div className="flex items-start gap-4">
        {/* portrait with pipeline step badge */}
        <div className="relative shrink-0">
          <div
            className="w-14 h-14 rounded-full overflow-hidden flex items-center justify-center"
            style={{ backgroundColor: tint(accent, 10), boxShadow: `inset 0 0 0 1.5px ${tint(accent, 32)}` }}
          >
            {Portrait ? (
              <Portrait className="w-14 h-14" />
            ) : (
              <span className="font-mono text-[18px] font-semibold" style={{ color: accent }}>
                {name.charAt(0)}
              </span>
            )}
          </div>
          <span
            className="absolute -top-1.5 -left-1.5 w-5 h-5 rounded-full flex items-center justify-center font-mono text-[9px] font-semibold text-white ring-2 ring-card"
            style={{ backgroundColor: accent }}
          >
            {String(step).padStart(2, "0")}
          </span>
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="text-[15px] font-semibold text-foreground tracking-[-0.01em] truncate">
                {name}
              </div>
              <div className="text-[12px] text-muted-foreground truncate">
                {meta?.role ?? "SOC agent"}
              </div>
            </div>
            {agent.enabled ? (
              <span
                className="inline-flex items-center gap-1.5 font-mono text-[10px] px-2 py-0.5 rounded-full border shrink-0"
                style={{ color: accent, borderColor: tint(accent, 32), backgroundColor: tint(accent, 8) }}
              >
                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: accent }} />
                active
              </span>
            ) : (
              <span className="inline-flex items-center font-mono text-[10px] px-2 py-0.5 rounded-full border border-border bg-muted text-muted-foreground shrink-0">
                disabled
              </span>
            )}
          </div>
          <div className="font-mono text-[10.5px] text-muted-foreground mt-1.5 truncate">
            {agent.agent_key}
            {agent.model && <span className="opacity-50"> · {agent.model}</span>}
          </div>
        </div>
      </div>

      {/* Reserve two lines so cards sitting side by side keep their stat rows aligned. */}
      <p className="text-[12.5px] text-foreground/70 leading-[1.6] mt-4 line-clamp-2 min-h-[2.5rem]">
        {agent.description}
      </p>

      <div className="pt-4 mt-4 border-t border-border">
        <div className="grid grid-cols-3 gap-4">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground font-semibold mb-1">
              Runs
            </div>
            <div className="text-[16px] font-semibold text-foreground tabular">
              {agent.total_runs.toLocaleString()}
            </div>
          </div>
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground font-semibold mb-1">
              Success
            </div>
            <div className="text-[16px] font-semibold text-foreground tabular">
              {rate == null ? "—" : `${rate}%`}
            </div>
          </div>
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground font-semibold mb-1">
              Latency
            </div>
            <div className="text-[16px] font-semibold text-foreground tabular">
              {formatLatency(agent.avg_latency_ms)}
            </div>
          </div>
        </div>
        {/* Full-width success meter keeps the three stats visually balanced. */}
        <div className="mt-3.5">
          <SuccessMeter rate={rate} accent={accent} />
        </div>
      </div>

      <div className="mt-4 pt-4 border-t border-border flex items-center justify-between">
        <span className="font-mono text-[10.5px] text-muted-foreground">
          {agent.last_run_at ? `last run ${timeAgo(agent.last_run_at)}` : "no runs yet"}
        </span>
        <Link
          to={`/agents/${agent.agent_key}`}
          className="inline-flex items-center gap-1 text-[12px] font-medium text-muted-foreground group-hover:text-foreground transition-colors"
        >
          Run history
          <ArrowUpRight className="w-3.5 h-3.5" />
        </Link>
      </div>
    </motion.div>
  );
}

function AgentDetail({ agentKey }: { agentKey: string }) {
  const [agent, setAgent] = useState<Agent | null>(null);
  const [runs, setRuns] = useState<AgentRunSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [waking, setWaking] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    withColdStartRetry(
      () =>
        Promise.all([
          api.agents.getAgent(agentKey),
          api.agents.listAgentRuns(agentKey, { page_size: 10 }),
        ]),
      { onRetry: () => { if (!cancelled) setWaking(true); } }
    )
      .then(([a, r]) => {
        if (cancelled) return;
        setAgent(a);
        setRuns(r.items);
      })
      .catch((err) => {
        if (!cancelled) {
          if (err instanceof ApiError) setError(`${err.status}: ${err.message}`);
          else setError(String(err));
        }
      })
      .finally(() => { if (!cancelled) { setLoading(false); setWaking(false); } });

    return () => { cancelled = true; };
  }, [agentKey]);

  const backLink = (
    <Link
      to="/agents"
      className="inline-flex items-center gap-1.5 text-[13px] text-muted-foreground hover:text-foreground transition-colors"
    >
      <ArrowLeft className="w-4 h-4" />
      All agents
    </Link>
  );

  if (loading) {
    return (
      <div className="space-y-5">
        {backLink}
        {waking ? (
          <ColdStartNotice />
        ) : (
          <div className="flex items-center gap-2 text-muted-foreground text-[13px] py-8">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading agent...
          </div>
        )}
      </div>
    );
  }

  if (error || !agent) {
    return (
      <div className="space-y-5">
        {backLink}
        <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical shrink-0 mt-0.5" />
          <span className="text-[13px] text-foreground">{error || "Agent not found"}</span>
        </div>
      </div>
    );
  }

  const Portrait = CREW_PORTRAITS[agent.agent_key];
  const meta = CREW_META[agent.agent_key];

  return (
    <div className="space-y-6 pb-12">
      {backLink}

      {/* Hero */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="flex items-start gap-4 sm:gap-6"
      >
        <div className="shrink-0">
          {Portrait ? (
            <Portrait className="w-20 h-20" />
          ) : (
            <div className="w-20 h-20 rounded-full bg-muted flex items-center justify-center">
              <Activity className="w-8 h-8 text-muted-foreground" />
            </div>
          )}
        </div>
        <div className="flex-1 min-w-0 pt-1">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span
              className={`font-mono text-[10px] px-2 py-0.5 rounded border ${
                agent.enabled
                  ? "bg-severity-low/8 text-severity-low border-severity-low/30"
                  : "bg-muted text-muted-foreground border-border"
              }`}
            >
              {agent.enabled ? "active" : "disabled"}
            </span>
          </div>
          <h1 className="title-serif text-[22px] sm:text-[28px] tracking-[-0.03em] text-foreground">
            {meta?.name ?? agent.name}
          </h1>
          {meta && (
            <p className="text-[13.5px] text-muted-foreground mt-0.5">{meta.role}</p>
          )}
          <p className="font-mono text-[11px] text-muted-foreground mt-1">
            {agent.agent_key}
            {agent.model && <span className="ml-2 opacity-60">{agent.model}</span>}
          </p>
        </div>
      </motion.div>

      {/* Stats */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.06 }}
        className="bg-card border border-border rounded-xl p-4 sm:p-5 grid grid-cols-2 sm:grid-cols-4 gap-4 sm:gap-5"
      >
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1">
            Total runs
          </div>
          <div className="text-[22px] font-semibold text-foreground tabular">
            {agent.total_runs.toLocaleString()}
          </div>
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1">
            Successful
          </div>
          <div className="text-[22px] font-semibold text-severity-low tabular">
            {agent.successful_runs.toLocaleString()}
          </div>
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1">
            Failed
          </div>
          <div className="text-[22px] font-semibold text-severity-critical tabular">
            {agent.failed_runs.toLocaleString()}
          </div>
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1">
            Avg latency
          </div>
          <div className="text-[22px] font-semibold text-foreground tabular">
            {formatLatency(agent.avg_latency_ms)}
          </div>
        </div>
      </motion.div>

      {/* Description */}
      {agent.description && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          className="bg-card border border-border rounded-xl p-4 sm:p-5"
        >
          <SectionLabel>About this agent</SectionLabel>
          <p className="text-[13.5px] text-foreground/80 leading-[1.65]">
            {agent.description}
          </p>
        </motion.div>
      )}

      {/* Recent runs */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.14 }}
      >
        <SectionLabel>Recent runs</SectionLabel>
        {runs.length === 0 ? (
          <div className="py-10 text-center">
            <Activity className="w-6 h-6 text-muted-foreground/40 mx-auto mb-2" strokeWidth={1.5} />
            <p className="text-[13px] text-muted-foreground">No runs recorded yet.</p>
          </div>
        ) : (
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-muted/40 border-b border-border">
                <tr>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Status</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden md:table-cell">Run ID</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden md:table-cell">Trigger</th>
                  <th className="px-4 sm:px-5 py-3 text-right font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Latency</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">When</th>
                  <th className="px-2 py-3 w-8" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {runs.map((run, i) => (
                  <motion.tr
                    key={run.id}
                    initial={{ opacity: 0, y: 3 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.03 }}
                    className="hover:bg-accent/40 transition-colors group"
                  >
                    <td className="px-4 sm:px-5 py-3.5">
                      <StatusDot status={run.status} />
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
                    <td className="px-4 sm:px-5 py-3.5 text-right font-mono text-[11px] text-muted-foreground tabular">
                      {formatLatency(run.latency_ms)}
                    </td>
                    <td className="px-4 sm:px-5 py-3.5">
                      <span className="font-mono text-[11px] text-muted-foreground">
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
          </div>
        )}
      </motion.div>
    </div>
  );
}

export default function AgentsPage() {
  const { agentKey } = useParams<{ agentKey?: string }>();

  if (agentKey) {
    return <AgentDetail agentKey={agentKey} />;
  }

  return <AgentList />;
}

function AgentList() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [waking, setWaking] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    withColdStartRetry(() => api.agents.listAgents(), {
      onRetry: () => { if (!cancelled) setWaking(true); },
    })
      .then((res) => { if (!cancelled) setAgents(res.items); })
      .catch((err) => {
        if (!cancelled) {
          if (err instanceof ApiError) setError(`${err.status}: ${err.message}`);
          else setError(String(err));
        }
      })
      .finally(() => { if (!cancelled) { setLoading(false); setWaking(false); } });

    return () => { cancelled = true; };
  }, []);

  return (
    <div className="space-y-6 sm:space-y-8 pb-12">
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <h1 className="title-serif text-[22px] sm:text-[28px] tracking-[-0.03em] text-foreground">
          Agents
        </h1>
        <p className="text-[13.5px] text-muted-foreground mt-1">
          Seven specialized AI agents power the SOC pipeline — each an expert at a single job.
        </p>
      </motion.div>

      {waking && !error && <ColdStartNotice />}

      {loading && !waking && (
        <div className="flex items-center gap-2 text-muted-foreground text-[13px] py-8">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading agents...
        </div>
      )}

      {error && !loading && (
        <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical shrink-0 mt-0.5" />
          <span className="text-[13px] text-foreground">{error}</span>
        </div>
      )}

      {!loading && !error && agents.length > 0 && (
        <>
          <FleetSummary agents={agents} />

          <div>
            <SectionLabel>The crew · in execution order</SectionLabel>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-5">
              {[...agents]
                .sort((a, b) => pipelineRank(a.agent_key) - pipelineRank(b.agent_key))
                .map((agent, i) => (
                  <AgentCard key={agent.id} agent={agent} index={i} step={i + 1} />
                ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
