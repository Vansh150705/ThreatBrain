import { useState } from "react";
import { Loader2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import SeverityBadge from "@/components/SeverityBadge";
import { api } from "@/lib/api";
import type { ThreatDetail } from "@/lib/api/threats";
import type { CaseStatus } from "@/lib/api/cases";
import { useUserStore } from "@/store/useUserStore";

const STATUSES: Array<{ value: CaseStatus; label: string }> = [
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "contained", label: "Contained" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False positive" },
];

interface Evidence {
  source: string;
  detail: string;
  /** assigned by the platform: false = a concrete token in the detail (IP, hash, path...) is not in the event data */
  verified?: boolean | null;
}

interface Reconciliation {
  adjusted?: boolean;
  notes?: string[];
  llm_severity?: string;
  final_severity?: string;
  provenance?: {
    severity?: "model" | "rules" | "rules_floor_over_model";
    model_severity?: string | null;
    rule_severity_floor?: string | null;
    model_used?: boolean;
    evidence?: { deterministic: number; model: number; model_unverified: number };
  };
  grounding?: {
    confidence_capped?: boolean;
    unsupported_in_text?: string[];
    dropped_attack_techniques?: string[];
    secrets_or_prompt_text_redacted?: number;
  };
}

const KIND_LABEL: Record<string, { text: string; cls: string }> = {
  rule: { text: "Deterministic rule", cls: "bg-muted text-foreground/80" },
  correlation: { text: "Deterministic correlation", cls: "bg-muted text-foreground/80" },
  behavior: { text: "Behavioural (statistical)", cls: "bg-severity-info/15 text-severity-info" },
};

const SEVERITY_SOURCE: Record<string, string> = {
  model: "the AI model (no rule disagreed)",
  rules: "deterministic rules only (the AI model was unavailable)",
  rules_floor_over_model: "a deterministic rule, which overrode a lower AI rating",
};

interface Props {
  threat: ThreatDetail;
  onUpdated: (t: ThreatDetail) => void;
}

/** Status control + the evidence behind the verdict (rule hits, cited facts, threat intel). */
export default function ThreatTriagePanel({ threat, onUpdated }: Props) {
  const role = useUserStore((s) => s.profile?.role);
  const canEdit = role === "owner" || role === "admin" || role === "analyst";
  const [saving, setSaving] = useState(false);

  const evidence = (threat.ai_analysis?.evidence as Evidence[] | undefined) ?? [];
  const reconciliation = threat.ai_analysis?.reconciliation as Reconciliation | undefined;
  const prov = reconciliation?.provenance;
  const grounding = reconciliation?.grounding;
  const intel = (threat.enrichment?.threat_intel ?? null) as
    | { reputation?: string; composite_score?: number | null; feeds_used?: string[]; summary?: string }
    | null;
  const hits = threat.rule_hits ?? [];

  async function setStatus(status: CaseStatus) {
    setSaving(true);
    try {
      const updated = (await api.cases.patchThreat(threat.short_id, { status })) as ThreatDetail;
      onUpdated({ ...threat, ...updated });
      toast.success(status === "false_positive" ? "Marked as false positive" : "Threat updated");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Update failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="bg-card border border-border rounded-xl p-4 sm:p-5 space-y-5">
      <div className="flex items-center justify-between gap-3">
        <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
          Triage & evidence
        </div>
        <div className="flex items-center gap-2">
          {saving && <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground" />}
          <Select
            value={threat.status}
            disabled={!canEdit || saving}
            onValueChange={(v) => setStatus(v as CaseStatus)}
          >
            <SelectTrigger size="sm" aria-label="Threat status">
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
        </div>
      </div>

      {(threat.event_count ?? 1) > 1 && (
        <p className="text-[12.5px] text-foreground/80">
          <strong className="font-semibold">{threat.event_count} raw events</strong> were folded into this
          threat by alert de-duplication
          {threat.last_seen_at ? ` (last seen ${new Date(threat.last_seen_at).toLocaleString()})` : ""}.
        </p>
      )}

      {reconciliation?.adjusted && (
        <div className="p-3 rounded-lg bg-severity-medium/8 border border-severity-medium/30 text-[12.5px]">
          <div className="font-semibold mb-1">Verdict adjusted by detection rules</div>
          <ul className="list-disc pl-4 text-foreground/80">
            {(reconciliation.notes ?? []).map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </div>
      )}

      {prov?.severity && (
        <p className="text-[12.5px] text-foreground/80" data-testid="provenance">
          Severity <strong className="font-semibold">{reconciliation?.final_severity}</strong> was decided by {SEVERITY_SOURCE[prov.severity]}
          {prov.severity === "rules_floor_over_model" && prov.model_severity ? <> (the model said {prov.model_severity})</> : null}.
        </p>
      )}

      {grounding && (grounding.confidence_capped || (grounding.dropped_attack_techniques?.length ?? 0) > 0 || (grounding.secrets_or_prompt_text_redacted ?? 0) > 0) && (
        <div className="p-3 rounded-lg bg-severity-medium/8 border border-severity-medium/30 text-[12.5px]" data-testid="grounding-warning">
          <div className="font-semibold mb-1">The AI write-up contains claims the platform could not verify</div>
          <ul className="list-disc pl-4 text-foreground/80">
            {grounding.confidence_capped && <li>Confidence was capped: some facts it cites are not in the event data.</li>}
            {(grounding.unsupported_in_text ?? []).length > 0 && <li>Not found in the evidence: {(grounding.unsupported_in_text ?? []).join(", ")}</li>}
            {(grounding.dropped_attack_techniques ?? []).length > 0 && <li>Non-existent ATT&CK ids were dropped: {(grounding.dropped_attack_techniques ?? []).join(", ")}</li>}
            {(grounding.secrets_or_prompt_text_redacted ?? 0) > 0 && <li>Secret-like or prompt-like text was redacted from the output.</li>}
          </ul>
        </div>
      )}

      {hits.length > 0 && (
        <div>
          <div className="text-[11px] text-muted-foreground mb-2">Detections</div>
          <ul className="space-y-2">
            {hits.map((h) => {
              const kind = KIND_LABEL[h.kind ?? "rule"] ?? KIND_LABEL.rule;
              return (
                <li key={h.rule_id} className="text-[12.5px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11px] bg-muted px-1.5 py-0.5 rounded">{h.rule_id}</span>
                    <span className={`text-[10.5px] px-1.5 py-0.5 rounded ${kind.cls}`}>{kind.text}</span>
                    {h.signal && <span className="text-[10.5px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">Signal (context only)</span>}
                    <SeverityBadge severity={h.severity} />
                    <span className="text-foreground">{h.name}</span>
                    <span className="font-mono text-[10.5px] text-muted-foreground">
                      {h.techniques.join(", ")} · {h.confidence}% {h.kind === "behavior" ? "estimated" : "rule"} confidence
                    </span>
                  </div>
                  {h.kind === "behavior" && h.explanation?.signals && (
                    <ul className="mt-1 ml-4 list-disc text-foreground/75">
                      {h.explanation.signals.slice(0, 4).map((sg, i) => (
                        <li key={i}>{sg.explanation?.summary ?? sg.feature}</li>
                      ))}
                      {h.explanation.note && <li className="italic">{h.explanation.note}</li>}
                    </ul>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {evidence.length > 0 && (
        <div>
          <div className="text-[11px] text-muted-foreground mb-2">Evidence (deterministic items come from rules; the rest is AI-generated)</div>
          <ul className="space-y-1.5">
            {evidence.map((e, i) => (
              <li key={i} className="text-[12.5px] flex gap-2">
                <span className="font-mono text-[10.5px] text-muted-foreground shrink-0 mt-0.5">[{e.source}]</span>
                <span className="text-foreground/85">
                  {e.detail}
                  {e.source.startsWith("rule:") ? (
                    <span className="ml-2 text-[10.5px] text-muted-foreground">deterministic</span>
                  ) : e.verified === false ? (
                    <span className="ml-2 text-[10.5px] text-severity-high" title="A concrete token in this claim is not in the event data">AI-generated · unverified</span>
                  ) : (
                    <span className="ml-2 text-[10.5px] text-muted-foreground">AI-generated</span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {intel && (
        <div className="flex items-start gap-2 text-[12.5px]">
          <ShieldCheck className="w-4 h-4 mt-0.5 text-severity-info shrink-0" />
          <div>
            <span className="font-semibold capitalize">{intel.reputation ?? "unknown"}</span> source
            {intel.composite_score != null && <> · composite score {intel.composite_score}/100</>}
            {intel.feeds_used && intel.feeds_used.length > 0 && <> · feeds: {intel.feeds_used.join(", ")}</>}
            {intel.summary && <p className="text-foreground/70 mt-0.5">{intel.summary}</p>}
          </div>
        </div>
      )}

      {hits.length === 0 && evidence.length === 0 && !intel && !reconciliation?.adjusted && (
        <p className="text-[12.5px] text-muted-foreground italic">No structured evidence was recorded for this threat.</p>
      )}
    </div>
  );
}
