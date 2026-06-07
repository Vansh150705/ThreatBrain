import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "motion/react";
import { ShieldAlert, AlertCircle, Loader2, ArrowUpRight } from "lucide-react";

import { api, type IncidentListResponse } from "@/lib/api";
import SeverityBadge from "@/components/SeverityBadge";
import StatusBadge from "@/components/StatusBadge";
import PriorityBadge from "@/components/PriorityBadge";

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

export default function IncidentsPage() {
  const [data, setData] = useState<IncidentListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState("all");
  const [incidentStatus, setIncidentStatus] = useState("all");
  const [priority, setPriority] = useState("all");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    api.incidents
      .listIncidents({
        page: 1,
        page_size: 25,
        severity: severity === "all" ? undefined : severity,
        status: incidentStatus === "all" ? undefined : incidentStatus,
        priority: priority === "all" ? undefined : priority,
      })
      .then((res) => { if (!cancelled) setData(res); })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, [severity, incidentStatus, priority]);

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="flex items-start justify-between gap-6 flex-wrap"
      >
        <div>
          <h1 className="text-[26px] tracking-[-0.025em] font-semibold text-foreground">
            Incidents
          </h1>
          <p className="text-[13.5px] text-muted-foreground mt-1">
            Grouped attack campaigns under investigation across your organization.
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

      {/* Loading */}
      {loading && (
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
      {!loading && !error && data && data.items.length === 0 && (
        <div className="py-16 text-center">
          <ShieldAlert className="w-8 h-8 text-muted-foreground/40 mx-auto mb-3" strokeWidth={1.5} />
          <p className="text-[13.5px] text-muted-foreground">No incidents match your filters.</p>
        </div>
      )}

      {/* Table */}
      {!loading && !error && data && data.items.length > 0 && (
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
                  <th className="px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Sev</th>
                  <th className="px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Pri</th>
                  <th className="px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">ID</th>
                  <th className="px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Title</th>
                  <th className="px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Status</th>
                  <th className="px-5 py-3 text-right font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden md:table-cell">Threats</th>
                  <th className="px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden lg:table-cell">Kill chain</th>
                  <th className="px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Last seen</th>
                  <th className="px-2 py-3 w-8" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {data.items.map((incident, i) => (
                  <motion.tr
                    key={incident.id}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.03 }}
                    className="hover:bg-accent/40 transition-colors group"
                  >
                    <td className="px-5 py-3.5">
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td className="px-5 py-3.5">
                      <PriorityBadge priority={incident.priority} />
                    </td>
                    <td className="px-5 py-3.5">
                      <Link
                        to={`/incidents/${incident.short_id}`}
                        className="font-mono text-[11px] text-muted-foreground hover:text-foreground transition-colors"
                      >
                        {incident.short_id}
                      </Link>
                    </td>
                    <td className="px-5 py-3.5 max-w-sm">
                      <Link
                        to={`/incidents/${incident.short_id}`}
                        className="text-[13.5px] font-medium text-foreground hover:text-foreground/70 transition-colors truncate block"
                      >
                        {incident.title}
                      </Link>
                    </td>
                    <td className="px-5 py-3.5">
                      <StatusBadge status={incident.status} />
                    </td>
                    <td className="px-5 py-3.5 text-right font-mono text-[11px] text-muted-foreground tabular hidden md:table-cell">
                      {incident.threat_count}
                    </td>
                    <td className="px-5 py-3.5 hidden lg:table-cell">
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
                    <td className="px-5 py-3.5">
                      <span className="font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                        {timeAgo(incident.last_seen_at)}
                      </span>
                    </td>
                    <td className="px-2 py-3.5 text-right">
                      <Link to={`/incidents/${incident.short_id}`}>
                        <ArrowUpRight className="w-3.5 h-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                      </Link>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>
      )}
    </div>
  );
}
