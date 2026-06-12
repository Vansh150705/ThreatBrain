import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { motion } from "motion/react";
import { Loader2, AlertCircle, ArrowUpRight, ArrowLeft, Activity } from "lucide-react";

import { api, type Agent, ApiError } from "@/lib/api";
import type { AgentRunSummary } from "@/lib/api/types";
import { CREW_PORTRAITS, CREW_META } from "@/components/CrewPortraits";

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

function successRate(agent: Agent): string {
  if (agent.total_runs === 0) return "—";
  return `${Math.round((agent.successful_runs / agent.total_runs) * 100)}%`;
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

function AgentCard({ agent, index }: { agent: Agent; index: number }) {
  const Portrait = CREW_PORTRAITS[agent.agent_key];
  const meta = CREW_META[agent.agent_key];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05 }}
      className="bg-card border border-border rounded-xl p-5"
    >
      <div className="flex items-start gap-4 mb-4">
        <div className="shrink-0">
          {Portrait ? (
            <Portrait className="w-14 h-14" />
          ) : (
            <div className="w-14 h-14 rounded-full bg-muted flex items-center justify-center">
              <Activity className="w-6 h-6 text-muted-foreground" />
            </div>
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div>
              <div className="text-[15px] font-semibold text-foreground tracking-[-0.01em]">
                {meta?.name ?? agent.name}
              </div>
              {meta && (
                <div className="text-[12px] text-muted-foreground">{meta.role}</div>
              )}
            </div>
            <span
              className={`inline-flex items-center gap-1 font-mono text-[10px] px-2 py-0.5 rounded border ${
                agent.enabled
                  ? "bg-severity-low/8 text-severity-low border-severity-low/30"
                  : "bg-muted text-muted-foreground border-border"
              }`}
            >
              {agent.enabled ? "active" : "disabled"}
            </span>
          </div>
          <div className="font-mono text-[11px] text-muted-foreground mt-1">
            {agent.agent_key}
            {agent.model && (
              <span className="ml-2 opacity-60">{agent.model}</span>
            )}
          </div>
        </div>
      </div>

      {agent.description && (
        <p className="text-[13px] text-foreground/70 leading-[1.6] mb-4">
          {agent.description}
        </p>
      )}

      <div className="grid grid-cols-3 gap-4 pt-4 border-t border-border">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground font-semibold mb-1">
            Total runs
          </div>
          <div className="text-[16px] font-semibold text-foreground tabular">
            {agent.total_runs.toLocaleString()}
          </div>
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground font-semibold mb-1">
            Success rate
          </div>
          <div className="text-[16px] font-semibold text-foreground tabular">
            {successRate(agent)}
          </div>
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground font-semibold mb-1">
            Avg latency
          </div>
          <div className="text-[16px] font-semibold text-foreground tabular">
            {formatLatency(agent.avg_latency_ms)}
          </div>
        </div>
      </div>

      <div className="mt-4 pt-4 border-t border-border">
        <Link
          to={`/agents/${agent.agent_key}`}
          className="inline-flex items-center gap-1 text-[12.5px] font-medium text-muted-foreground hover:text-foreground transition-colors"
        >
          View run history
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

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.agents.getAgent(agentKey),
      api.agents.listAgentRuns(agentKey, { page_size: 10 }),
    ])
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
      .finally(() => { if (!cancelled) setLoading(false); });

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
        <div className="flex items-center gap-2 text-muted-foreground text-[13px] py-8">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading agent...
        </div>
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
        className="flex items-start gap-6"
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
          <h1 className="title-serif text-[28px] tracking-[-0.03em] text-foreground">
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
        className="bg-card border border-border rounded-xl p-5 grid grid-cols-2 sm:grid-cols-4 gap-5"
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
          className="bg-card border border-border rounded-xl p-5"
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
            <table className="w-full">
              <thead className="bg-muted/40 border-b border-border">
                <tr>
                  <th className="px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Status</th>
                  <th className="px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden md:table-cell">Run ID</th>
                  <th className="px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden md:table-cell">Trigger</th>
                  <th className="px-5 py-3 text-right font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Latency</th>
                  <th className="px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">When</th>
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
                    <td className="px-5 py-3.5">
                      <StatusDot status={run.status} />
                    </td>
                    <td className="px-5 py-3.5 hidden md:table-cell">
                      <span className="font-mono text-[11px] text-muted-foreground">
                        {run.id.slice(0, 8)}...
                      </span>
                    </td>
                    <td className="px-5 py-3.5 hidden md:table-cell">
                      <span className="font-mono text-[10px] px-1.5 py-0.5 bg-muted text-muted-foreground rounded">
                        {run.trigger_type}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-right font-mono text-[11px] text-muted-foreground tabular">
                      {formatLatency(run.latency_ms)}
                    </td>
                    <td className="px-5 py-3.5">
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

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    api.agents
      .listAgents()
      .then((res) => { if (!cancelled) setAgents(res.items); })
      .catch((err) => {
        if (!cancelled) {
          if (err instanceof ApiError) setError(`${err.status}: ${err.message}`);
          else setError(String(err));
        }
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, []);

  return (
    <div className="space-y-8 pb-12">
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <h1 className="title-serif text-[28px] tracking-[-0.03em] text-foreground">
          Agents
        </h1>
        <p className="text-[13.5px] text-muted-foreground mt-1">
          Six specialized AI agents that make up the SOC pipeline.
        </p>
      </motion.div>

      {loading && (
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

      {!loading && !error && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {agents.map((agent, i) => (
            <AgentCard key={agent.id} agent={agent} index={i} />
          ))}
        </div>
      )}
    </div>
  );
}
