import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "motion/react";
import { ShieldAlert, AlertCircle, Loader2, ArrowUpRight } from "lucide-react";

import {
  api,
  withColdStartRetry,
  type IncidentListResponse,
} from "@/lib/api";
import SeverityBadge from "@/components/SeverityBadge";
import StatusBadge from "@/components/StatusBadge";
import PriorityBadge from "@/components/PriorityBadge";
import ColdStartNotice from "@/components/ColdStartNotice";
import {
  useRealtimeRows,
  type RealtimeBaseRow,
} from "@/hooks/useRealtimeThreats";

const SEVERITY_OPTS = [
  { value: "all", label: "All" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const STATUS_OPTS = [
  { value: "all",           label: "All" },
  { value: "open",          label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "contained",     label: "Contained" },
  { value: "resolved",      label: "Resolved" },
];

const PRIORITY_OPTS = [
  { value: "all", label: "All" },
  { value: "p1",  label: "P1" },
  { value: "p2",  label: "P2" },
  { value: "p3",  label: "P3" },
  { value: "p4",  label: "P4" },
];

// the realtime row is wider than the api incident, we trim it at render time
interface RealtimeIncidentRow extends RealtimeBaseRow {
  short_id: string;
  title: string;
  severity: string;
  status: string;
  priority: string;
  threat_count: number;
  kill_chain: string[];
  last_seen_at: string | null;
  first_seen_at: string | null;
  created_at: string;
  updated_at: string;
}

function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const diffMs = Date.now() - new Date(iso).getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const h = Math.floor(diffMins / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function FilterPills({
  options,
  value,
  onChange,
}: {
  options: { value: string; label: string }[];
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {options.map((opt) => (
        <button
          key={opt.value}
          onClick={() => onChange(opt.value)}
          className={`px-3 py-1 rounded-full text-[12px] font-medium border transition-colors ${
            value === opt.value
              ? "bg-foreground text-background border-foreground"
              : "bg-card border-border text-muted-foreground hover:text-foreground"
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

function LiveIndicator({
  status,
}: {
  status: "connecting" | "live" | "disconnected" | "error";
}) {
  const config = {
    live: { dotClass: "bg-severity-low", label: "Live", pulse: true },
    connecting: { dotClass: "bg-muted-foreground/40", label: "Connecting", pulse: false },
    disconnected: { dotClass: "bg-muted-foreground/30", label: "Offline", pulse: false },
    error: { dotClass: "bg-severity-critical", label: "Error", pulse: false },
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

export default function IncidentsPage() {
  const [data, setData] = useState<IncidentListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [waking, setWaking] = useState(false);
  const [severity, setSeverity] = useState("all");
  const [incidentStatus, setIncidentStatus] = useState("all");
  const [priority, setPriority] = useState("all");

  // Real-time incident arrivals
  const { rows: liveArrivals, status: liveStatus } = useRealtimeRows<RealtimeIncidentRow>({
    table: "incidents",
    maxItems: 50,
    highlightMs: 3000,
  });

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    withColdStartRetry(
      () =>
        api.incidents.listIncidents({
          page: 1,
          page_size: 25,
          severity: severity === "all" ? undefined : severity,
          status: incidentStatus === "all" ? undefined : incidentStatus,
          priority: priority === "all" ? undefined : priority,
        }),
      { onRetry: () => { if (!cancelled) setWaking(true); } }
    )
      .then((res) => { if (!cancelled) setData(res); })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => { if (!cancelled) { setLoading(false); setWaking(false); } });

    return () => { cancelled = true; };
  }, [severity, incidentStatus, priority]);

  // Merge live arrivals on top of the fetched page, filtered to match active filters
  const mergedItems = useMemo(() => {
    const baseItems = (data?.items ?? []) as unknown as RealtimeIncidentRow[];
    if (liveArrivals.length === 0) return baseItems;

    const baseIds = new Set(baseItems.map((i) => i.id));

    const filteredLive = liveArrivals.filter((i) => {
      if (baseIds.has(i.id)) return false;
      if (severity !== "all" && i.severity !== severity) return false;
      if (incidentStatus !== "all" && i.status !== incidentStatus) return false;
      if (priority !== "all" && i.priority !== priority) return false;
      return true;
    });

    return [...filteredLive, ...baseItems];
  }, [data, liveArrivals, severity, incidentStatus, priority]);

  const newIds = useMemo(() => {
    const ids = new Set<string>();
    for (const i of liveArrivals) {
      if (i._isNew) ids.add(i.id);
    }
    return ids;
  }, [liveArrivals]);

  return (
    <div className="space-y-6 sm:space-y-8 pb-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="flex items-start justify-between gap-4 sm:gap-6 flex-wrap"
      >
        <div>
          <div className="flex items-center gap-3">
            <h1 className="title-serif text-[22px] sm:text-[28px] tracking-[-0.03em] text-foreground">
              Incidents
            </h1>
            <LiveIndicator status={liveStatus} />
          </div>
          <p className="text-[13.5px] text-muted-foreground mt-1">
            Grouped attack campaigns under investigation. New incidents stream in via Supabase Realtime.
          </p>
        </div>
        {data && (
          <div className="font-mono text-[12px] text-muted-foreground self-end pb-1">
            <span className="text-foreground font-semibold tabular">{data.total}</span> total
          </div>
        )}
      </motion.div>

      {/* Filters */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.04 }}
        className="space-y-3"
      >
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-2">
            Severity
          </div>
          <FilterPills options={SEVERITY_OPTS} value={severity} onChange={setSeverity} />
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-2">
            Status
          </div>
          <FilterPills options={STATUS_OPTS} value={incidentStatus} onChange={setIncidentStatus} />
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-2">
            Priority
          </div>
          <FilterPills options={PRIORITY_OPTS} value={priority} onChange={setPriority} />
        </div>
      </motion.div>

      {/* Cold-start notice */}
      {waking && !error && <ColdStartNotice />}

      {/* Loading */}
      {loading && !waking && (
        <div className="flex items-center gap-2 text-muted-foreground text-[13px] py-8">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading incidents...
        </div>
      )}

      {/* Error */}
      {error && !loading && (
        <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical shrink-0 mt-0.5" />
          <div className="text-[13px] text-foreground">
            <div className="font-semibold">Could not load incidents</div>
            <div className="text-muted-foreground mt-0.5 font-mono text-[11px]">{error}</div>
          </div>
        </div>
      )}

      {/* Empty */}
      {!loading && !error && mergedItems.length === 0 && (
        <div className="py-16 text-center">
          <ShieldAlert className="w-8 h-8 text-muted-foreground/40 mx-auto mb-3" strokeWidth={1.5} />
          <p className="text-[13.5px] text-muted-foreground">No incidents match your filters.</p>
          <p className="text-[12px] text-muted-foreground/70 mt-1">
            New incidents matching these filters will appear here automatically.
          </p>
        </div>
      )}

      {/* Table */}
      {!loading && !error && mergedItems.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.08 }}
          className="bg-card border border-border rounded-xl overflow-hidden"
        >
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-muted/40 border-b border-border">
                <tr>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Sev</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Pri</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">ID</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Title</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Status</th>
                  <th className="px-4 sm:px-5 py-3 text-right font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden md:table-cell">Threats</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden lg:table-cell">Kill chain</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Last seen</th>
                  <th className="px-2 py-3 w-8" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                <AnimatePresence initial={false}>
                  {mergedItems.map((incident) => {
                    const isNew = newIds.has(incident.id);
                    return (
                      <motion.tr
                        key={incident.id}
                        layout
                        initial={{ opacity: 0, y: -8, scale: 0.99 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0, x: 8 }}
                        transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
                        className={`relative transition-colors group ${
                          isNew
                            ? "bg-severity-low/5 hover:bg-severity-low/10"
                            : "hover:bg-accent/40"
                        }`}
                      >
                        <td className="px-4 sm:px-5 py-3.5 relative">
                          {isNew && (
                            <motion.span
                              initial={{ opacity: 0, scaleY: 0.5 }}
                              animate={{ opacity: 1, scaleY: 1 }}
                              className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-7 rounded-r bg-severity-low"
                            />
                          )}
                          <SeverityBadge severity={incident.severity} />
                        </td>
                        <td className="px-4 sm:px-5 py-3.5">
                          <PriorityBadge priority={incident.priority} />
                        </td>
                        <td className="px-4 sm:px-5 py-3.5">
                          <Link
                            to={`/incidents/${incident.short_id}`}
                            className="font-mono text-[11px] text-muted-foreground hover:text-foreground transition-colors"
                          >
                            {incident.short_id}
                          </Link>
                        </td>
                        <td className="px-4 sm:px-5 py-3.5 max-w-sm">
                          <Link
                            to={`/incidents/${incident.short_id}`}
                            className="text-[13.5px] font-medium text-foreground hover:text-foreground/70 transition-colors truncate block"
                          >
                            {incident.title}
                          </Link>
                        </td>
                        <td className="px-4 sm:px-5 py-3.5">
                          <StatusBadge status={incident.status} />
                        </td>
                        <td className="px-4 sm:px-5 py-3.5 text-right font-mono text-[11px] text-muted-foreground tabular hidden md:table-cell">
                          {incident.threat_count}
                        </td>
                        <td className="px-4 sm:px-5 py-3.5 hidden lg:table-cell">
                          <div className="flex flex-wrap gap-1">
                            {incident.kill_chain.slice(0, 2).map((stage) => (
                              <span
                                key={stage}
                                className="font-mono text-[10px] px-1.5 py-0.5 bg-muted text-muted-foreground rounded"
                              >
                                {stage}
                              </span>
                            ))}
                            {incident.kill_chain.length > 2 && (
                              <span className="font-mono text-[10px] text-muted-foreground">
                                +{incident.kill_chain.length - 2}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 sm:px-5 py-3.5">
                          {isNew ? (
                            <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-severity-low font-semibold whitespace-nowrap">
                              new
                            </span>
                          ) : (
                            <span className="font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                              {timeAgo(incident.last_seen_at)}
                            </span>
                          )}
                        </td>
                        <td className="px-2 py-3.5 text-right">
                          <Link to={`/incidents/${incident.short_id}`}>
                            <ArrowUpRight className="w-3.5 h-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                          </Link>
                        </td>
                      </motion.tr>
                    );
                  })}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        </motion.div>
      )}
    </div>
  );
}