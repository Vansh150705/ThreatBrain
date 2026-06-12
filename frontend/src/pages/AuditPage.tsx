import { useEffect, useState, useCallback } from "react";
import { motion } from "motion/react";
import { Loader2, AlertCircle, RefreshCw, Lock } from "lucide-react";

import { listAuditLogs, type AuditLogItem } from "@/lib/api/audit";
import { ApiError } from "@/lib/api";
import SeverityBadge from "@/components/SeverityBadge";
import { Button } from "@/components/ui/button";

const SEVERITY_OPTS = ["all", "info", "low", "medium", "high", "critical"];
const ACTOR_OPTS = ["all", "user", "agent", "system"];

function Pills({
  options,
  value,
  onChange,
}: {
  options: string[];
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map((opt) => (
        <button
          key={opt}
          onClick={() => onChange(opt)}
          className={`px-3 py-1 rounded-full text-[12px] font-medium border transition-colors capitalize ${
            value === opt
              ? "bg-foreground text-background border-foreground"
              : "bg-white text-muted-foreground border-border hover:border-foreground/30 hover:text-foreground"
          }`}
        >
          {opt}
        </button>
      ))}
    </div>
  );
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

const ACTOR_TONE: Record<string, string> = {
  agent: "text-signal",
  user: "text-severity-info",
  system: "text-muted-foreground",
};

export default function AuditPage() {
  const [items, setItems] = useState<AuditLogItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState("all");
  const [actorType, setActorType] = useState("all");

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listAuditLogs({
        severity: severity === "all" ? undefined : severity,
        actor_type: actorType === "all" ? undefined : actorType,
        limit: 200,
      });
      setItems(res.items);
      setTotal(res.total);
    } catch (err) {
      if (err instanceof ApiError) setError(`${err.status}: ${err.message}`);
      else setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [severity, actorType]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="flex items-start justify-between gap-6 flex-wrap"
      >
        <div>
          <div className="flex items-center gap-3">
            <h1 className="title-serif text-[28px] tracking-[-0.03em] text-foreground">
              Audit trail
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border border-border font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
              <Lock className="w-3 h-3" />
              Append-only
            </span>
          </div>
          <p className="text-[13.5px] text-muted-foreground mt-1">
            Every agent decision and user action, immutable at the database level.
            UPDATE and DELETE are rejected by a Postgres trigger.
          </p>
        </div>
        <div className="flex items-center gap-3 self-end pb-1">
          <div className="font-mono text-[12px] text-muted-foreground">
            <span className="text-foreground font-semibold tabular">{total}</span> events
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={fetchLogs}
            className="h-8 px-3 text-[12px] border-border"
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
            Refresh
          </Button>
        </div>
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
          <Pills options={SEVERITY_OPTS} value={severity} onChange={setSeverity} />
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-2">
            Actor
          </div>
          <Pills options={ACTOR_OPTS} value={actorType} onChange={setActorType} />
        </div>
      </motion.div>

      {loading && (
        <div className="flex items-center gap-2 text-muted-foreground text-[13px] py-8">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading audit trail...
        </div>
      )}

      {error && !loading && (
        <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />
          <div className="text-[13px] text-foreground">
            <span className="font-medium">Could not load the audit trail</span>
            <div className="font-mono text-[12px] text-muted-foreground mt-0.5">{error}</div>
          </div>
        </div>
      )}

      {!loading && !error && items.length === 0 && (
        <div className="text-[13.5px] text-muted-foreground py-10 text-center border border-dashed border-border rounded-xl">
          No audit events match these filters yet.
        </div>
      )}

      {/* Timeline */}
      {!loading && !error && items.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.06 }}
          className="rounded-xl border border-border overflow-hidden divide-y divide-border bg-card"
        >
          {items.map((log) => (
            <div key={log.id} className="px-5 py-3.5 flex items-start gap-4 hover:bg-muted/30 transition-colors">
              <div className="pt-1 flex-shrink-0">
                <SeverityBadge severity={log.severity} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline gap-2 flex-wrap">
                  <span className="font-mono text-[12.5px] font-semibold text-foreground">{log.action}</span>
                  <span className={`font-mono text-[11px] uppercase tracking-[0.08em] ${ACTOR_TONE[log.actor_type] ?? "text-muted-foreground"}`}>
                    {log.actor_type}
                  </span>
                  {log.actor_name && (
                    <span className="text-[12.5px] text-muted-foreground truncate">{log.actor_name}</span>
                  )}
                </div>
                {(log.target_short_id || log.target_name) && (
                  <div className="text-[12.5px] text-foreground/80 mt-0.5 truncate">
                    {log.target_short_id && (
                      <span className="font-mono text-muted-foreground mr-1.5">{log.target_short_id}</span>
                    )}
                    {log.target_name}
                  </div>
                )}
                {log.reason && (
                  <div className="text-[12.5px] text-muted-foreground mt-0.5 leading-[1.5]">{log.reason}</div>
                )}
              </div>
              <div className="flex flex-col items-end gap-1 flex-shrink-0">
                <span className="font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                  {relativeTime(log.created_at)}
                </span>
                <span className="font-mono text-[10px] text-muted-foreground/60">{log.short_id}</span>
              </div>
            </div>
          ))}
        </motion.div>
      )}
    </div>
  );
}
