import { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { motion } from "motion/react";
import { Loader2, AlertCircle, Check, X, ShieldCheck } from "lucide-react";

import { listApprovals, decideApproval, type ApprovalItem } from "@/lib/api/approvals";
import { ApiError } from "@/lib/api";
import { useUserStore } from "@/store/useUserStore";
import { Button } from "@/components/ui/button";

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

const ACTION_LABEL: Record<string, string> = {
  block_ip: "Block IP",
  disable_user: "Disable user",
  isolate_host: "Isolate host",
  notify: "Notify",
  quarantine_email: "Quarantine email",
  revoke_token: "Revoke token",
};

export default function ApprovalsPage() {
  const profile = useUserStore((s) => s.profile);
  const canDecide = profile?.role === "owner" || profile?.role === "admin";

  const [items, setItems] = useState<ApprovalItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actingOn, setActingOn] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listApprovals();
      setItems(res.items);
    } catch (err) {
      if (err instanceof ApiError) setError(`${err.status}: ${err.message}`);
      else setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  const decide = async (id: string, decision: "approved" | "rejected") => {
    setActingOn(id);
    setActionError(null);
    try {
      const updated = await decideApproval(id, decision);
      setItems((prev) => prev.map((a) => (a.id === id ? updated : a)));
    } catch (err) {
      if (err instanceof ApiError) setActionError(`${err.status}: ${err.message}`);
      else setActionError(String(err));
    } finally {
      setActingOn(null);
    }
  };

  const pending = items.filter((a) => a.status === "pending");
  const decided = items.filter((a) => a.status !== "pending");

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
              Approvals
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border border-border font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
              <ShieldCheck className="w-3 h-3" />
              Human-in-the-loop
            </span>
          </div>
          <p className="text-[13.5px] text-muted-foreground mt-1">
            The Response Agent recommends, never executes. Real actions need a
            human with the admin or owner role to sign off here.
          </p>
        </div>
        {pending.length > 0 && (
          <div className="font-mono text-[12px] text-muted-foreground self-end pb-1">
            <span className="text-severity-medium font-semibold tabular">{pending.length}</span> awaiting decision
          </div>
        )}
      </motion.div>

      {loading && (
        <div className="flex items-center gap-2 text-muted-foreground text-[13px] py-8">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading approval queue...
        </div>
      )}

      {error && !loading && (
        <div className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />
          <div className="text-[13px] text-foreground">
            <span className="font-medium">Could not load approvals</span>
            <div className="font-mono text-[12px] text-muted-foreground mt-0.5">{error}</div>
          </div>
        </div>
      )}

      {actionError && (
        <div className="flex items-start gap-2.5 p-3 border border-severity-critical/30 bg-severity-critical/5 rounded-lg text-[13px] text-foreground">
          <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />
          {actionError}
        </div>
      )}

      {/* Pending queue */}
      {!loading && !error && (
        <>
          {pending.length === 0 ? (
            <div className="text-[13.5px] text-muted-foreground py-10 text-center border border-dashed border-border rounded-xl">
              Queue is clear. New recommendations appear here after a pipeline run.
            </div>
          ) : (
            <div className="space-y-3">
              {pending.map((a, i) => (
                <motion.div
                  key={a.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.35, delay: i * 0.04 }}
                  className="rounded-xl border border-severity-medium/30 bg-severity-medium/[0.03] p-5"
                >
                  <div className="flex items-start justify-between gap-4 flex-wrap">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className="text-[15px] font-semibold tracking-[-0.01em] text-foreground">
                          {a.playbook_name}
                        </span>
                        <span className="font-mono text-[10px] uppercase tracking-[0.08em] px-2 py-0.5 rounded border border-border text-muted-foreground">
                          {ACTION_LABEL[a.action_type] ?? a.action_type}
                        </span>
                        <span className="font-mono text-[10px] uppercase tracking-[0.08em] px-2 py-0.5 rounded border border-severity-medium/35 text-severity-medium bg-severity-medium/[0.06]">
                          priority {a.priority}
                        </span>
                      </div>
                      <div className="font-mono text-[12.5px] text-foreground mt-2">
                        target <span className="font-semibold">{a.target}</span>
                      </div>
                      {a.rationale && (
                        <p className="text-[13px] text-muted-foreground mt-1.5 leading-[1.55] max-w-2xl">
                          {a.rationale}
                        </p>
                      )}
                      <div className="font-mono text-[11px] text-muted-foreground mt-2.5">
                        {a.incident_short_id && (
                          <>
                            <Link
                              to={`/incidents/${a.incident_short_id}`}
                              className="text-severity-info hover:underline"
                            >
                              {a.incident_short_id}
                            </Link>
                            <span className="mx-1.5">·</span>
                          </>
                        )}
                        requested {relativeTime(a.created_at)}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <Button
                        size="sm"
                        disabled={!canDecide || actingOn === a.id}
                        onClick={() => decide(a.id, "approved")}
                        className="h-9 px-4 text-[13px] font-medium bg-signal text-white hover:bg-signal/90"
                      >
                        {actingOn === a.id ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Check className="w-3.5 h-3.5 mr-1.5" />
                        )}
                        Approve
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={!canDecide || actingOn === a.id}
                        onClick={() => decide(a.id, "rejected")}
                        className="h-9 px-4 text-[13px] font-medium border-border hover:border-severity-critical/40 hover:text-severity-critical"
                      >
                        <X className="w-3.5 h-3.5 mr-1.5" />
                        Reject
                      </Button>
                    </div>
                  </div>
                  {!canDecide && (
                    <div className="font-mono text-[11px] text-muted-foreground mt-3 pt-3 border-t border-border/60">
                      Your role ({profile?.role ?? "viewer"}) can view this queue but cannot authorize actions.
                    </div>
                  )}
                </motion.div>
              ))}
            </div>
          )}

          {/* Decision history */}
          {decided.length > 0 && (
            <div>
              <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-3 mt-8">
                Decision history
              </div>
              <div className="rounded-xl border border-border overflow-hidden divide-y divide-border bg-card">
                {decided.map((a) => (
                  <div key={a.id} className="px-5 py-3 flex items-center gap-4">
                    <span
                      className={`inline-flex items-center gap-1 font-mono text-[10px] uppercase tracking-[0.08em] px-2 py-0.5 rounded border flex-shrink-0 ${
                        a.status === "approved"
                          ? "border-signal/35 text-signal bg-signal/[0.06]"
                          : "border-severity-critical/35 text-severity-critical bg-severity-critical/[0.05]"
                      }`}
                    >
                      {a.status === "approved" ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                      {a.status}
                    </span>
                    <div className="flex-1 min-w-0">
                      <span className="text-[13.5px] font-medium text-foreground">{a.playbook_name}</span>
                      <span className="font-mono text-[12px] text-muted-foreground ml-2">{a.target}</span>
                    </div>
                    <div className="font-mono text-[11px] text-muted-foreground flex-shrink-0">
                      {a.decided_by_name && <span>{a.decided_by_name} · </span>}
                      {a.decided_at ? relativeTime(a.decided_at) : ""}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
