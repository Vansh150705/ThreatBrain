import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "motion/react";
import { ArrowUpRight, Loader2, AlertCircle } from "lucide-react";
import type { JSX } from "react";

import { api, type Agent, type DashboardStats } from "@/lib/api";
import { ApiError } from "@/lib/api";
import { useUserStore } from "@/store/useUserStore";
import TriggerPipelineDialog from "@/components/TriggerPipelineDialog";

// Bitmoji crew portraits matching the landing page
const CREW: Record<
  string,
  { name: string; role: string; portrait: (className?: string) => JSX.Element }
> = {
  triage: {
    name: "Olivia",
    role: "Sorter",
    portrait: (c = "") => (
      <svg className={c} viewBox="0 0 48 48" fill="none">
        <circle cx="24" cy="22" r="11" fill="#f5d0b8" />
        <path d="M13 18 Q13 9 24 9 Q35 9 35 18 L35 14 L33 12 L15 12 L13 14 Z" fill="#c0392b" />
        <rect x="15" y="11" width="18" height="3" rx="1" fill="#a93226" />
        <circle cx="20" cy="22" r="1.2" fill="#1a1a1f" />
        <circle cx="28" cy="22" r="1.2" fill="#1a1a1f" />
        <path d="M20 27 Q24 29 28 27" stroke="#1a1a1f" strokeWidth="1.2" strokeLinecap="round" fill="none" />
        <path d="M14 35 Q24 30 34 35 L34 48 L14 48 Z" fill="#2c3e50" />
      </svg>
    ),
  },
  threat_intel: {
    name: "Henry",
    role: "Investigator",
    portrait: (c = "") => (
      <svg className={c} viewBox="0 0 48 48" fill="none">
        <circle cx="24" cy="22" r="11" fill="#e8c4a0" />
        <path d="M12 17 Q12 12 24 12 Q36 12 36 17 L36 15 L33 13 L15 13 L12 15 Z" fill="#5d4037" />
        <ellipse cx="24" cy="13" rx="14" ry="2.5" fill="#3e2723" />
        <circle cx="20" cy="22" r="1.2" fill="#1a1a1f" />
        <circle cx="28" cy="22" r="1.2" fill="#1a1a1f" />
        <path d="M22 27 L26 27" stroke="#1a1a1f" strokeWidth="1.2" strokeLinecap="round" />
        <path d="M14 35 Q24 30 34 35 L34 48 L14 48 Z" fill="#34495e" />
      </svg>
    ),
  },
  investigation: {
    name: "Nathan",
    role: "Connector",
    portrait: (c = "") => (
      <svg className={c} viewBox="0 0 48 48" fill="none">
        <circle cx="24" cy="22" r="11" fill="#d4a574" />
        <path d="M14 16 Q14 11 24 11 Q34 11 34 16 L34 19 Q30 14 24 14 Q18 14 14 19 Z" fill="#2c3e50" />
        <rect x="16" y="20" width="6" height="4" rx="1.5" fill="none" stroke="#1a1a1f" strokeWidth="0.8" />
        <rect x="26" y="20" width="6" height="4" rx="1.5" fill="none" stroke="#1a1a1f" strokeWidth="0.8" />
        <line x1="22" y1="22" x2="26" y2="22" stroke="#1a1a1f" strokeWidth="0.8" />
        <circle cx="19" cy="22" r="0.9" fill="#1a1a1f" />
        <circle cx="29" cy="22" r="0.9" fill="#1a1a1f" />
        <path d="M21 28 Q24 29 27 28" stroke="#1a1a1f" strokeWidth="1" strokeLinecap="round" fill="none" />
        <path d="M14 35 Q24 30 34 35 L34 48 L14 48 Z" fill="#1a3a52" />
        <circle cx="20" cy="40" r="0.8" fill="#7a9cc6" />
        <circle cx="24" cy="42" r="0.8" fill="#7a9cc6" />
        <circle cx="28" cy="40" r="0.8" fill="#7a9cc6" />
      </svg>
    ),
  },
  response: {
    name: "Rachel",
    role: "Responder",
    portrait: (c = "") => (
      <svg className={c} viewBox="0 0 48 48" fill="none">
        <circle cx="24" cy="22" r="11" fill="#f0c8b0" />
        <path d="M13 14 Q14 9 24 9 Q34 9 35 14 Q36 22 33 30 L31 28 Q33 22 32 16 Q30 12 24 12 Q18 12 16 16 Q15 22 17 28 L15 30 Q12 22 13 14 Z" fill="#8b4513" />
        <circle cx="20" cy="22" r="1.2" fill="#1a1a1f" />
        <circle cx="28" cy="22" r="1.2" fill="#1a1a1f" />
        <path d="M21 28 Q24 30 27 28" stroke="#c0392b" strokeWidth="1.4" strokeLinecap="round" fill="none" />
        <path d="M14 35 Q24 30 34 35 L34 48 L14 48 Z" fill="#5d2e2e" />
        <path d="M22 38 L24 42 L26 38 Z" fill="#f4d03f" stroke="#c0392b" strokeWidth="0.8" />
      </svg>
    ),
  },
  forensics: {
    name: "Frank",
    role: "Forensicist",
    portrait: (c = "") => (
      <svg className={c} viewBox="0 0 48 48" fill="none">
        <circle cx="24" cy="22" r="11" fill="#e8c5a0" />
        <path d="M14 15 Q14 10 24 10 Q34 10 34 15 L34 18 Q28 14 24 14 Q20 14 14 18 Z" fill="#1a1a1f" />
        <circle cx="19" cy="22" r="3" fill="none" stroke="#1a1a1f" strokeWidth="1" />
        <circle cx="29" cy="22" r="3" fill="none" stroke="#1a1a1f" strokeWidth="1" />
        <line x1="22" y1="22" x2="26" y2="22" stroke="#1a1a1f" strokeWidth="0.8" />
        <circle cx="19" cy="22" r="0.8" fill="#1a1a1f" />
        <circle cx="29" cy="22" r="0.8" fill="#1a1a1f" />
        <path d="M21 28 L27 28" stroke="#1a1a1f" strokeWidth="1.2" strokeLinecap="round" />
        <path d="M14 35 Q24 30 34 35 L34 48 L14 48 Z" fill="#ffffff" stroke="#bdc3c7" strokeWidth="0.5" />
        <rect x="22" y="36" width="4" height="8" rx="1" fill="#7ddc9c" opacity="0.7" />
      </svg>
    ),
  },
  compliance: {
    name: "Claire",
    role: "Compliance",
    portrait: (c = "") => (
      <svg className={c} viewBox="0 0 48 48" fill="none">
        <circle cx="24" cy="22" r="11" fill="#f2d4b8" />
        <path d="M13 15 Q14 10 24 10 Q34 10 35 15 Q36 19 34 22 L32 20 Q33 16 32 14 Q29 11 24 11 Q19 11 16 14 Q15 16 16 20 L14 22 Q12 19 13 15 Z" fill="#34495e" />
        <circle cx="20" cy="22" r="1.2" fill="#1a1a1f" />
        <circle cx="28" cy="22" r="1.2" fill="#1a1a1f" />
        <path d="M21 28 Q24 29 27 28" stroke="#1a1a1f" strokeWidth="1" strokeLinecap="round" fill="none" />
        <path d="M14 35 Q24 30 34 35 L34 48 L14 48 Z" fill="#2c3e50" />
        <rect x="21" y="38" width="6" height="2" fill="#a07a4d" />
        <rect x="23" y="37" width="2" height="6" fill="#a07a4d" />
      </svg>
    ),
  },
};

// Map agent_key variants to crew entries (handles both threat_intel and threat-intel etc.)
function getCrew(agentKey: string) {
  const k = agentKey.toLowerCase().replace(/-/g, "_");
  return CREW[k];
}

// Greeting that adapts to local time
function greeting() {
  const h = new Date().getHours();
  if (h < 5) return "Working late";
  if (h < 12) return "Good morning";
  if (h < 17) return "Good afternoon";
  if (h < 21) return "Good evening";
  return "Working late";
}

// Format time as "Friday, 7 June"
function formattedDate() {
  return new Date().toLocaleDateString("en-US", {
    weekday: "long",
    day: "numeric",
    month: "long",
  });
}

interface RecentThreat {
  id: string;
  short_id: string;
  title: string;
  severity: string;
  detected_at: string;
}

function timeAgo(iso: string): string {
  const diffMins = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const h = Math.floor(diffMins / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

const SEVERITY_TONE: Record<string, string> = {
  critical: "text-severity-critical",
  high: "text-severity-high",
  medium: "text-severity-medium",
  low: "text-severity-low",
  info: "text-severity-info",
};

export default function DashboardPage() {
  const profile = useUserStore((s) => s.profile);
  const firstName = useMemo(() => {
    if (!profile?.full_name) return "there";
    return profile.full_name.split(" ")[0];
  }, [profile?.full_name]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentThreats, setRecentThreats] = useState<RecentThreat[]>([]);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      api.agents.listAgents(),
      api.stats.getDashboardStats(),
      api.threats
        .listThreats({ page: 1, page_size: 3 })
        .then((r) => r.items as RecentThreat[])
        .catch(() => [] as RecentThreat[]),
    ])
      .then(([agentsRes, statsRes, threatsRes]) => {
        setAgents(agentsRes.items);
        setStats(statsRes);
        setRecentThreats(threatsRes);
      })
      .catch((err) => {
        if (err instanceof ApiError) setError(`${err.status} — ${err.message}`);
        else setError(String(err));
      })
      .finally(() => setLoading(false));
  }, []);

  const totalRuns = agents.reduce((sum, a) => sum + a.total_runs, 0);
  const activeAgents = agents.filter((a) => a.enabled).length;

  return (
    <div className="space-y-16 pb-12">
      {/* ─────── HEADER — Editorial masthead ─────── */}
      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <div className="flex items-baseline justify-between gap-6 mb-2">
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground font-semibold">
            The neural SOC · Briefing
          </span>
          <span className="font-mono text-[11px] text-muted-foreground">
            {formattedDate()}
          </span>
        </div>
        <div className="border-t border-foreground/15 pt-8">
          <h1 className="font-serif text-[52px] md:text-[68px] leading-[0.98] tracking-[-0.04em] font-semibold text-foreground">
            {greeting()},{" "}
            <span className="italic font-medium">{firstName}.</span>
          </h1>
          <p className="font-serif text-[20px] md:text-[22px] text-muted-foreground italic mt-5 max-w-2xl leading-[1.4]">
            Your six agents have been working. Here is what they found.
          </p>

          <div className="mt-8 flex flex-wrap items-center gap-3">
            <TriggerPipelineDialog />
            <Link
              to="/runs"
              className="inline-flex items-center gap-1.5 text-[13.5px] font-medium text-foreground hover:text-muted-foreground transition-colors group"
            >
              See last run
              <ArrowUpRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
            </Link>
          </div>
        </div>
      </motion.section>

      {/* ─────── HERO STATS — Big Fraunces numerals ─────── */}
      <motion.section
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
      >
        <div className="grid grid-cols-2 md:grid-cols-4 divide-x divide-foreground/10 border-y border-foreground/10">
          {[
            {
              label: "Active agents",
              value: loading ? "—" : `${activeAgents}/${agents.length}`,
              footnote: "all online",
              tone: "text-foreground",
            },
            {
              label: "Total runs",
              value: loading ? "—" : totalRuns.toLocaleString(),
              footnote: "across pipeline",
              tone: "text-foreground",
            },
            {
              label: "Open threats",
              value: loading || !stats ? "—" : stats.open_threats.toString(),
              footnote: `${stats?.critical_threats ?? 0} critical`,
              tone: "text-severity-high",
              link: "/threats",
            },
            {
              label: "Open incidents",
              value: loading || !stats ? "—" : stats.open_incidents.toString(),
              footnote: "awaiting review",
              tone: "text-severity-critical",
              link: "/incidents",
            },
          ].map((s, i) => {
            const content = (
              <div className="px-6 py-8 first:pl-0 group">
                <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground font-semibold mb-3">
                  {s.label}
                </div>
                <div
                  className={`stat-number text-[64px] leading-[0.9] tracking-[-0.045em] ${s.tone}`}
                >
                  {s.value}
                </div>
                <div className="font-mono text-[11px] text-muted-foreground mt-3 flex items-center gap-1">
                  {s.footnote}
                  {s.link && (
                    <ArrowUpRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                  )}
                </div>
              </div>
            );
            return s.link ? (
              <Link key={s.label} to={s.link} className="block hover:bg-accent/40 transition-colors">
                {content}
              </Link>
            ) : (
              <div key={s.label}>{content}</div>
            );
          })}
        </div>
      </motion.section>

      {/* ─────── RECENT THREATS — Three-column editorial spread ─────── */}
      <motion.section
        initial={{ opacity: 0, y: 12 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-80px" }}
        transition={{ duration: 0.6 }}
      >
        <div className="flex items-baseline justify-between mb-8">
          <div>
            <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground font-semibold">
              The desk · Latest
            </span>
            <h2 className="font-serif text-[32px] tracking-[-0.03em] mt-2 font-semibold">
              From the watch floor.
            </h2>
          </div>
          <Link
            to="/threats"
            className="inline-flex items-center gap-1.5 text-[13px] font-medium text-foreground hover:text-muted-foreground transition-colors group whitespace-nowrap"
          >
            All threats
            <ArrowUpRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
          </Link>
        </div>

        {loading && (
          <div className="flex items-center gap-2 text-muted-foreground text-sm py-8">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading the desk…
          </div>
        )}

        {error && (
          <div className="flex items-start gap-2 p-4 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
            <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />
            <span className="text-sm text-foreground">{error}</span>
          </div>
        )}

        {!loading && !error && recentThreats.length === 0 && (
          <div className="py-16 text-center">
            <p className="font-serif italic text-[22px] text-muted-foreground">
              No threats. Quiet right now.
            </p>
          </div>
        )}

        {!loading && !error && recentThreats.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-foreground/10">
            {recentThreats.slice(0, 3).map((t, i) => (
              <motion.div
                key={t.id}
                initial={{ opacity: 0, y: 8 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.08 }}
                className="bg-background"
              >
                <Link
                  to={`/threats/${t.short_id}`}
                  className="block p-6 hover:bg-accent/30 transition-colors h-full group"
                >
                  <div className="flex items-center justify-between mb-4">
                    <span
                      className={`font-mono text-[10px] uppercase tracking-[0.14em] font-semibold ${
                        SEVERITY_TONE[t.severity.toLowerCase()] ?? "text-foreground"
                      }`}
                    >
                      {t.severity}
                    </span>
                    <span className="font-mono text-[10px] text-muted-foreground">
                      {timeAgo(t.detected_at)}
                    </span>
                  </div>
                  <h3 className="font-serif text-[22px] leading-[1.15] tracking-[-0.02em] font-semibold text-foreground group-hover:text-foreground/70 transition-colors line-clamp-3">
                    {t.title}
                  </h3>
                  <div className="font-mono text-[10px] text-muted-foreground mt-4 pt-4 border-t border-foreground/10">
                    {t.short_id}
                  </div>
                </Link>
              </motion.div>
            ))}
          </div>
        )}
      </motion.section>

      {/* ─────── THE CREW — Six-agent live status row ─────── */}
      <motion.section
        initial={{ opacity: 0, y: 12 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-80px" }}
        transition={{ duration: 0.6 }}
      >
        <div className="flex items-baseline justify-between mb-8">
          <div>
            <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground font-semibold">
              The crew · On duty
            </span>
            <h2 className="font-serif text-[32px] tracking-[-0.03em] mt-2 font-semibold">
              Six agents, <span className="italic font-medium">always working.</span>
            </h2>
          </div>
          <Link
            to="/agents"
            className="inline-flex items-center gap-1.5 text-[13px] font-medium text-foreground hover:text-muted-foreground transition-colors group whitespace-nowrap"
          >
            Roster
            <ArrowUpRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
          </Link>
        </div>

        {loading ? (
          <div className="flex items-center gap-2 text-muted-foreground text-sm py-8">
            <Loader2 className="w-4 h-4 animate-spin" />
            Roll call…
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            {agents.slice(0, 6).map((agent, i) => {
              const crew = getCrew(agent.agent_key);
              return (
                <motion.div
                  key={agent.id}
                  initial={{ opacity: 0, y: 12 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.05 }}
                  whileHover={{ y: -4 }}
                >
                  <Link
                    to={`/agents/${agent.agent_key}`}
                    className="block bg-card border border-foreground/10 rounded-2xl p-5 hover:border-foreground/30 hover:shadow-sm transition-all group h-full"
                  >
                    <div className="flex flex-col items-center text-center">
                      <div className="w-16 h-16 rounded-full bg-accent overflow-hidden mb-3 ring-1 ring-foreground/10">
                        {crew ? (
                          crew.portrait("w-full h-full")
                        ) : (
                          <div className="w-full h-full flex items-center justify-center font-serif text-2xl text-muted-foreground">
                            {agent.name.charAt(0)}
                          </div>
                        )}
                      </div>
                      <div className="font-serif text-[17px] font-semibold tracking-[-0.02em] leading-tight">
                        {crew?.name ?? agent.name.split(" ")[0]}
                      </div>
                      <div className="font-mono text-[9px] uppercase tracking-[0.12em] text-muted-foreground mt-1">
                        the {crew?.role ?? agent.agent_key}
                      </div>
                      <div className="flex items-center gap-1.5 mt-3 pt-3 border-t border-foreground/10 w-full justify-center">
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            agent.enabled ? "bg-severity-low" : "bg-muted-foreground/40"
                          }`}
                        />
                        <span className="font-mono text-[10px] text-muted-foreground">
                          {agent.total_runs} runs
                        </span>
                      </div>
                    </div>
                  </Link>
                </motion.div>
              );
            })}
          </div>
        )}
      </motion.section>

      {/* ─────── FOOTER LINE ─────── */}
      <motion.section
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        className="border-t border-foreground/10 pt-6 flex items-center justify-between"
      >
        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground font-semibold">
          End of briefing
        </span>
        <span className="font-mono text-[10px] text-muted-foreground">
          ThreatBrain · vol. I
        </span>
      </motion.section>
    </div>
  );
}