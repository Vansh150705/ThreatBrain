import { useCallback, useEffect, useState } from "react";
import { Loader2, MessageSquarePlus, UserRound } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api } from "@/lib/api";
import type { IncidentDetail } from "@/lib/api/incidents";
import type {
  CaseStatus,
  IncidentNote,
  Member,
  TimelineEntry,
} from "@/lib/api/cases";
import { useUserStore } from "@/store/useUserStore";
import SeverityBadge from "@/components/SeverityBadge";
import { cn } from "@/lib/utils";

const STATUSES: Array<{ value: CaseStatus; label: string }> = [
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "contained", label: "Contained" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
  { value: "false_positive", label: "False positive" },
];
const PRIORITIES = ["p1", "p2", "p3", "p4"] as const;
const UNASSIGNED = "__unassigned__";

function fmt(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const KIND_STYLE: Record<TimelineEntry["kind"], string> = {
  threat: "bg-severity-high",
  audit: "bg-severity-info",
  note: "bg-severity-low",
  forensics: "bg-severity-medium",
};

interface Props {
  incident: IncidentDetail;
  onUpdated: (incident: IncidentDetail) => void;
}

/** Case controls (status / priority / owner), analyst notes and the evidence trail. */
export default function CasePanel({ incident, onUpdated }: Props) {
  const role = useUserStore((s) => s.profile?.role);
  const canEdit = role === "owner" || role === "admin" || role === "analyst";

  const [members, setMembers] = useState<Member[]>([]);
  const [saving, setSaving] = useState<string | null>(null);
  const [tab, setTab] = useState<"timeline" | "notes">("timeline");
  const [timeline, setTimeline] = useState<TimelineEntry[] | null>(null);
  const [notes, setNotes] = useState<IncidentNote[] | null>(null);
  const [draft, setDraft] = useState("");
  const [posting, setPosting] = useState(false);

  const id = incident.short_id;

  // bump to re-fetch the activity feeds after a change
  const [reload, setReload] = useState(0);
  const loadFeeds = useCallback(() => setReload((n) => n + 1), []);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.cases.getTimeline(id), api.cases.listNotes(id)])
      .then(([t, n]) => {
        if (cancelled) return;
        setTimeline(t);
        setNotes(n);
      })
      .catch((err) => {
        if (cancelled) return;
        toast.error(err instanceof Error ? err.message : "Could not load case activity");
        setTimeline((cur) => cur ?? []);
        setNotes((cur) => cur ?? []);
      });
    return () => {
      cancelled = true;
    };
  }, [id, reload]);

  useEffect(() => {
    if (!canEdit) return;
    api.cases.listMembers().then(setMembers).catch(() => setMembers([]));
  }, [canEdit]);

  async function patch(field: string, body: Parameters<typeof api.cases.patchIncident>[1]) {
    setSaving(field);
    try {
      const updated = (await api.cases.patchIncident(id, body)) as IncidentDetail;
      onUpdated({ ...incident, ...updated });
      toast.success("Case updated");
      loadFeeds();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Update failed");
    } finally {
      setSaving(null);
    }
  }

  async function postNote() {
    const body = draft.trim();
    if (!body) return;
    setPosting(true);
    try {
      await api.cases.addNote(id, body);
      setDraft("");
      loadFeeds();
      setTab("notes");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not add note");
    } finally {
      setPosting(false);
    }
  }

  const ownerName = incident.assigned_to
    ? members.find((m) => m.id === incident.assigned_to)?.full_name ?? "Assigned"
    : "Unassigned";

  return (
    <div className="bg-card border border-border rounded-xl p-4 sm:p-5 space-y-5">
      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
        Case management
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <label className="space-y-1">
          <span className="text-[11px] text-muted-foreground">Status</span>
          <Select
            value={incident.status}
            disabled={!canEdit || saving !== null}
            onValueChange={(v) => patch("status", { status: v as CaseStatus })}
          >
            <SelectTrigger className="w-full" aria-label="Incident status">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUSES.map((s) => (
                <SelectItem key={s.value} value={s.value}>
                  {s.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </label>

        <label className="space-y-1">
          <span className="text-[11px] text-muted-foreground">Priority</span>
          <Select
            value={incident.priority}
            disabled={!canEdit || saving !== null}
            onValueChange={(v) => patch("priority", { priority: v as (typeof PRIORITIES)[number] })}
          >
            <SelectTrigger className="w-full" aria-label="Incident priority">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PRIORITIES.map((p) => (
                <SelectItem key={p} value={p}>
                  {p.toUpperCase()}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </label>

        <label className="space-y-1">
          <span className="text-[11px] text-muted-foreground flex items-center gap-1">
            <UserRound className="w-3 h-3" /> Owner
          </span>
          <Select
            value={incident.assigned_to ?? UNASSIGNED}
            disabled={!canEdit || saving !== null}
            onValueChange={(v) => patch("assigned_to", { assigned_to: v === UNASSIGNED ? null : v })}
          >
            <SelectTrigger className="w-full" aria-label="Incident owner">
              <SelectValue>{ownerName}</SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={UNASSIGNED}>Unassigned</SelectItem>
              {members
                .filter((m) => m.role !== "viewer")
                .map((m) => (
                  <SelectItem key={m.id} value={m.id}>
                    {m.full_name || m.email}
                  </SelectItem>
                ))}
            </SelectContent>
          </Select>
        </label>
      </div>
      {!canEdit && (
        <p className="text-[12px] text-muted-foreground">
          Your role is read-only. Analysts and above can change cases and add notes.
        </p>
      )}
      {saving && (
        <div className="flex items-center gap-2 text-[12px] text-muted-foreground">
          <Loader2 className="w-3.5 h-3.5 animate-spin" /> Saving…
        </div>
      )}

      <div>
        <div className="flex gap-1 border-b border-border mb-3" role="tablist">
          {(["timeline", "notes"] as const).map((t) => (
            <button
              key={t}
              role="tab"
              aria-selected={tab === t}
              onClick={() => setTab(t)}
              className={cn(
                "px-3 py-1.5 text-[12.5px] font-medium -mb-px border-b-2 transition-colors",
                tab === t
                  ? "border-foreground text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              )}
            >
              {t === "timeline" ? `Evidence timeline${timeline ? ` (${timeline.length})` : ""}` : `Notes${notes ? ` (${notes.length})` : ""}`}
            </button>
          ))}
        </div>

        {tab === "timeline" &&
          (timeline === null ? (
            <Loading />
          ) : timeline.length === 0 ? (
            <Empty>No activity recorded yet.</Empty>
          ) : (
            <ol className="relative border-l border-border ml-1.5 space-y-3.5 max-h-96 overflow-auto pr-1">
              {timeline.map((e, i) => (
                <li key={`${e.ts}-${i}`} className="ml-4">
                  <span
                    className={cn(
                      "absolute -left-[5px] mt-1.5 w-2.5 h-2.5 rounded-full border-2 border-background",
                      KIND_STYLE[e.kind] ?? "bg-muted-foreground"
                    )}
                  />
                  <div className="flex flex-wrap items-center gap-2 font-mono text-[10px] text-muted-foreground">
                    <span>{fmt(e.ts)}</span>
                    <span className="uppercase tracking-wider">{e.kind}</span>
                    {e.actor && <span>· {e.actor}</span>}
                    {e.kind === "threat" && <SeverityBadge severity={e.severity} />}
                  </div>
                  <div className="text-[13px] text-foreground">{e.title}</div>
                  {e.detail && <div className="text-[12.5px] text-foreground/70 whitespace-pre-wrap">{e.detail}</div>}
                </li>
              ))}
            </ol>
          ))}

        {tab === "notes" && (
          <div className="space-y-3">
            {notes === null ? (
              <Loading />
            ) : notes.length === 0 ? (
              <Empty>No notes yet.</Empty>
            ) : (
              <ul className="space-y-2 max-h-72 overflow-auto pr-1">
                {notes.map((n) => (
                  <li key={n.id} className="p-3 bg-muted/40 rounded-lg">
                    <div className="font-mono text-[10px] text-muted-foreground mb-1">
                      {n.author_name ?? "Unknown"} · {fmt(n.created_at)}
                    </div>
                    <div className="text-[13px] text-foreground whitespace-pre-wrap">{n.body}</div>
                  </li>
                ))}
              </ul>
            )}
            {canEdit && (
              <div className="space-y-2">
                <textarea
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  maxLength={5000}
                  rows={3}
                  placeholder="Add an investigation note (actions taken, who you contacted, findings)…"
                  aria-label="New note"
                  className="w-full rounded-lg border border-input bg-transparent px-3 py-2 text-[13px] outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
                />
                <div className="flex items-center justify-between">
                  <span className="text-[11px] text-muted-foreground">{draft.length}/5000</span>
                  <Button size="sm" onClick={postNote} disabled={posting || !draft.trim()}>
                    {posting ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <MessageSquarePlus className="w-3.5 h-3.5 mr-1.5" />}
                    Add note
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Loading() {
  return (
    <div className="flex items-center gap-2 text-[12.5px] text-muted-foreground py-3">
      <Loader2 className="w-3.5 h-3.5 animate-spin" /> Loading…
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="text-[12.5px] text-muted-foreground italic py-2">{children}</p>;
}
