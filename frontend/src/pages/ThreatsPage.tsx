import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "motion/react";
import { ShieldAlert, AlertCircle, Loader2, ArrowUpRight } from "lucide-react";

import { api, withColdStartRetry, type ThreatListResponse } from "@/lib/api";
import SeverityBadge from "@/components/SeverityBadge";
import StatusBadge from "@/components/StatusBadge";
import ColdStartNotice from "@/components/ColdStartNotice";
import {
  useRealtimeThreats,
  type RealtimeThreatRow,
} from "@/hooks/useRealtimeThreats";

const SEVERITY_OPTS = [
  { value: "all",      label: "All" },
  { value: "critical", label: "Critical" },
  { value: "high",     label: "High" },
  { value: "medium",   label: "Medium" },
  { value: "low",      label: "Low" },
  { value: "info",     label: "Info" },
];

const STATUS_OPTS = [
  { value: "all",            label: "All" },
  { value: "open",           label: "Open" },
  { value: "investigating",  label: "Investigating" },
  { value: "contained",      label: "Contained" },
  { value: "resolved",       label: "Resolved" },
  { value: "false_positive", label: "False positive" },
];

function timeAgo(iso: string): string {
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

//  Live indicator (connection status pill) 
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

export default function ThreatsPage() {
  const [data, setData] = useState<ThreatListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [waking, setWaking] = useState(false);
  const [severity, setSeverity] = useState("all");
  const [threatStatus, setThreatStatus] = useState("all");

  // only the brand new rows coming in from realtime
  // We merge these into the table view, filtered to match the current filters.
  const { threats: liveArrivals, status: liveStatus } = useRealtimeThreats({
    maxItems: 50,
    highlightMs: 3000,
  });

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    withColdStartRetry(
      () =>
        api.threats.listThreats({
          page: 1,
          page_size: 25,
          severity: severity === "all" ? undefined : severity,
          status: threatStatus === "all" ? undefined : threatStatus,
        }),
      { onRetry: () => { if (!cancelled) setWaking(true); } }
    )
      .then((res) => { if (!cancelled) setData(res); })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => { if (!cancelled) { setLoading(false); setWaking(false); } });

    return () => { cancelled = true; };
  }, [severity, threatStatus]);

  // Merge live arrivals (filtered) on top of the fetched page.
  // - Show only live rows that match the active severity/status filters
  // - De-duplicate by id (the fetched page may already contain them after refresh)
  // - Live rows go first so freshly arrived threats appear at the top
  
  const mergedItems = useMemo(() => {
    const baseItems = (data?.items ?? []) as RealtimeThreatRow[];
    if (liveArrivals.length === 0) return baseItems;

    const baseIds = new Set(baseItems.map((t) => t.id));

    const filteredLive = liveArrivals.filter((t) => {
      if (baseIds.has(t.id)) return false; // already present from the fetched page
      if (severity !== "all" && t.severity !== severity) return false;
      if (threatStatus !== "all" && t.status !== threatStatus) return false;
      return true;
    });

    // Live rows on top, keeping the _isNew flag they brought with them.
    return [...filteredLive, ...baseItems];
  }, [data, liveArrivals, severity, threatStatus]);

  // For display, only treat a row as "new" if it's in the live arrivals AND still flagged.
  const newIds = useMemo(() => {
    const ids = new Set<string>();
    for (const t of liveArrivals) {
      if (t._isNew) ids.add(t.id);
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
              Threats
            </h1>
            <LiveIndicator status={liveStatus} />
          </div>
          <p className="text-[13.5px] text-muted-foreground mt-1">
            All detected security threats. New detections stream in via Supabase Realtime.
          </p>
        </div>
        {data && (
          <div className="font-mono text-[12px] text-muted-foreground self-end pb-1">
            <span className="text-foreground font-semibold tabular">{data.total}</span> total
          </div>
        )}
      </motion.div>

      {/* Filter chips */}
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
          <FilterPills options={STATUS_OPTS} value={threatStatus} onChange={setThreatStatus} />
        </div>
      </motion.div>

      {/* Cold-start notice */}
      {waking && !error && <ColdStartNotice />}

      {/* Loading */}
      {loading && !waking && (
        <div className="flex items-center gap-2 text-muted-foreground text-[13px] py-8">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading threats...
        </div>
      )}

      {/* Error */}
      {error && !loading && (
        <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical shrink-0 mt-0.5" />
          <div className="text-[13px] text-foreground">
            <div className="font-semibold">Could not load threats</div>
            <div className="text-muted-foreground mt-0.5 font-mono text-[11px]">{error}</div>
          </div>
        </div>
      )}

      {/* Empty */}
      {!loading && !error && mergedItems.length === 0 && (
        <div className="py-16 text-center">
          <ShieldAlert className="w-8 h-8 text-muted-foreground/40 mx-auto mb-3" strokeWidth={1.5} />
          <p className="text-[13.5px] text-muted-foreground">No threats match your filters.</p>
          <p className="text-[12px] text-muted-foreground/70 mt-1">
            New detections matching these filters will appear here automatically.
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
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Severity</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">ID</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Title</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Status</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden md:table-cell">MITRE</th>
                  <th className="px-4 sm:px-5 py-3 text-right font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground hidden lg:table-cell">Confidence</th>
                  <th className="px-4 sm:px-5 py-3 text-left font-mono text-[10px] uppercase tracking-[0.1em] font-semibold text-muted-foreground">Detected</th>
                  <th className="px-2 py-3 w-8" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                <AnimatePresence initial={false}>
                  {mergedItems.map((threat) => {
                    const isNew = newIds.has(threat.id);
                    return (
                      <motion.tr
                        key={threat.id}
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
                          <SeverityBadge severity={threat.severity} />
                        </td>
                        <td className="px-4 sm:px-5 py-3.5">
                          <Link
                            to={`/threats/${threat.short_id}`}
                            className="font-mono text-[11px] text-muted-foreground hover:text-foreground transition-colors"
                          >
                            {threat.short_id}
                          </Link>
                        </td>
                        <td className="px-4 sm:px-5 py-3.5 max-w-sm">
                          <Link
                            to={`/threats/${threat.short_id}`}
                            className="text-[13.5px] font-medium text-foreground hover:text-foreground/70 transition-colors truncate block"
                          >
                            {threat.title}
                          </Link>
                        </td>
                        <td className="px-4 sm:px-5 py-3.5">
                          <StatusBadge status={threat.status} />
                        </td>
                        <td className="px-4 sm:px-5 py-3.5 hidden md:table-cell">
                          <div className="flex flex-wrap gap-1">
                            {threat.mitre_techniques.slice(0, 2).map((t) => (
                              <span
                                key={t}
                                className="font-mono text-[10px] px-1.5 py-0.5 bg-muted text-muted-foreground rounded"
                              >
                                {t}
                              </span>
                            ))}
                            {threat.mitre_techniques.length > 2 && (
                              <span className="font-mono text-[10px] text-muted-foreground">
                                +{threat.mitre_techniques.length - 2}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 sm:px-5 py-3.5 text-right font-mono text-[11px] text-muted-foreground tabular hidden lg:table-cell">
                          {threat.confidence}%
                        </td>
                        <td className="px-4 sm:px-5 py-3.5">
                          {isNew ? (
                            <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-severity-low font-semibold whitespace-nowrap">
                              new
                            </span>
                          ) : (
                            <span className="font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                              {timeAgo(threat.detected_at)}
                            </span>
                          )}
                        </td>
                        <td className="px-2 py-3.5 text-right">
                          <Link to={`/threats/${threat.short_id}`}>
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