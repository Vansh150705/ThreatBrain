import { useCallback, useEffect, useMemo, useState } from "react";
import { motion } from "motion/react";
import { AlertCircle, CheckCircle2, FlaskConical, Loader2, Search, Sparkles, XCircle } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { BuiltinRule, Coverage, CustomRule, RuleDefinitionInput, RulesResponse, Severity, TuningResult, ValidationResult } from "@/lib/api/detection";
import { useUserStore } from "@/store/useUserStore";
import { Button } from "@/components/ui/button";
import SeverityBadge from "@/components/SeverityBadge";
import { cn } from "@/lib/utils";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
type Tab = "rules" | "coverage" | "custom" | "sigma";

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function Section({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <section className="bg-card border border-border rounded-xl p-4 sm:p-5 space-y-3">
      <div>
        <h2 className="text-[15px] font-semibold tracking-[-0.015em]">{title}</h2>
        {subtitle && <p className="text-[12.5px] text-muted-foreground mt-0.5">{subtitle}</p>}
      </div>
      {children}
    </section>
  );
}

/* ------------------------------------------------------------------ built-in rules */
function BuiltinRules({ rules, canEdit, reload }: { rules: BuiltinRule[]; canEdit: boolean; reload: () => void }) {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<"all" | Severity>("all");
  const [onlyOff, setOnlyOff] = useState(false);
  const [tuning, setTuning] = useState<{ rule: string; busy: boolean; result?: TuningResult; error?: string } | null>(null);

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rules.filter(
      (r) =>
        (sev === "all" || (r.severity_override ?? r.severity) === sev) &&
        (!onlyOff || !r.enabled) &&
        (!needle ||
          r.id.toLowerCase().includes(needle) ||
          r.name.toLowerCase().includes(needle) ||
          r.techniques.some((t) => t.toLowerCase().includes(needle)) ||
          r.tags.some((t) => t.toLowerCase().includes(needle)))
    );
  }, [rules, q, sev, onlyOff]);

  async function toggle(r: BuiltinRule) {
    let reason: string | undefined;
    if (r.enabled) {
      reason = window.prompt(`Why disable ${r.id}? (required, recorded in the audit trail)`)?.trim();
      if (!reason) return;
    }
    try {
      await api.detection.setBuiltinOverride(r.id, { enabled: !r.enabled, severity_override: r.severity_override, reason });
      toast.success(r.enabled ? `${r.id} disabled for your organization` : `${r.id} re-enabled`);
      reload();
    } catch (e) {
      toast.error(errMsg(e));
    }
  }

  async function setSeverity(r: BuiltinRule, value: string) {
    try {
      await api.detection.setBuiltinOverride(r.id, { enabled: r.enabled, severity_override: value === "default" ? null : (value as Severity), reason: r.override_reason ?? undefined });
      reload();
    } catch (e) {
      toast.error(errMsg(e));
    }
  }

  async function propose(r: BuiltinRule) {
    setTuning({ rule: r.id, busy: true });
    try {
      const result = await api.detection.proposeTuning(r.id);
      setTuning({ rule: r.id, busy: false, result });
      reload();
    } catch (e) {
      setTuning({ rule: r.id, busy: false, error: errMsg(e) });
    }
  }

  return (
    <Section title="Built-in rules" subtitle={`${rules.length} rules. Disabling or re-grading a rule applies to your organization only and is recorded in the audit trail.`}>
      <div className="flex flex-wrap items-center gap-2">
        <label className="relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-muted-foreground" aria-hidden />
          <input
            aria-label="Search rules"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search id, name, technique, tag"
            className="rounded-lg border border-input bg-transparent pl-8 pr-3 h-9 w-72 max-w-full text-[13px] outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
          />
        </label>
        <select aria-label="Severity filter" value={sev} onChange={(e) => setSev(e.target.value as typeof sev)} className="rounded-lg border border-input bg-transparent px-2 h-9 text-[13px]">
          <option value="all">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <label className="inline-flex items-center gap-1.5 text-[12.5px]">
          <input type="checkbox" checked={onlyOff} onChange={(e) => setOnlyOff(e.target.checked)} /> Disabled only
        </label>
        <span className="text-[12px] text-muted-foreground ml-auto" aria-live="polite">{shown.length} shown</span>
      </div>

      {tuning && (
        <div role="status" className="rounded-lg border border-border p-3 text-[12.5px] space-y-1 bg-muted/30">
          <div className="font-semibold">Tuning proposal for {tuning.rule}</div>
          {tuning.busy && <div className="flex items-center gap-2"><Loader2 className="w-3.5 h-3.5 animate-spin" /> Reviewing analyst feedback…</div>}
          {tuning.error && <div className="text-severity-critical">{tuning.error}</div>}
          {tuning.result && (
            <>
              <div><b>{tuning.result.recommendation}</b>: {tuning.result.assessment}</div>
              <div className="text-muted-foreground">{tuning.result.rationale}</div>
              {tuning.result.verification.accepted === true && (
                <div className="text-severity-low">
                  Verified against real events: false positives {tuning.result.verification.measurements.fp_matched_before}→{tuning.result.verification.measurements.fp_matched_after},
                  genuine detections {tuning.result.verification.measurements.tp_matched_before}→{tuning.result.verification.measurements.tp_matched_after}. Saved as a <b>draft</b> under Custom rules; review, test and enable it yourself.
                </div>
              )}
              {tuning.result.verification.accepted === false && (
                <div className="text-severity-high">Proposal rejected by verification: {tuning.result.verification.reasons.join("; ")}</div>
              )}
            </>
          )}
          <Button size="sm" variant="ghost" onClick={() => setTuning(null)}>Dismiss</Button>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-[12.5px]">
          <thead className="text-left text-muted-foreground">
            <tr>
              <th className="py-1.5 pr-3 font-medium">Rule</th>
              <th className="py-1.5 pr-3 font-medium">Severity</th>
              <th className="py-1.5 pr-3 font-medium">Confidence</th>
              <th className="py-1.5 pr-3 font-medium">ATT&amp;CK</th>
              <th className="py-1.5 pr-3 font-medium">State</th>
              {canEdit && <th />}
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {shown.map((r) => (
              <tr key={r.id} className={cn(!r.enabled && "opacity-60")}>
                <td className="py-2 pr-3 max-w-[28rem]">
                  <div className="font-mono text-[11px] text-muted-foreground">{r.id}</div>
                  <div>{r.name}</div>
                  {r.tuning && <div className="text-[11px] text-muted-foreground mt-0.5">Tuning: {r.tuning}</div>}
                  {r.override_reason && <div className="text-[11px] text-severity-medium mt-0.5">Disabled because: {r.override_reason}</div>}
                </td>
                <td className="py-2 pr-3">
                  {canEdit ? (
                    <select
                      aria-label={`Severity for ${r.id}`}
                      value={r.severity_override ?? "default"}
                      onChange={(e) => void setSeverity(r, e.target.value)}
                      className="rounded-md border border-input bg-transparent px-1.5 h-8 text-[12px]"
                    >
                      <option value="default">{r.severity} (default)</option>
                      {SEVERITIES.filter((s) => s !== r.severity).map((s) => (
                        <option key={s} value={s}>{s}</option>
                      ))}
                    </select>
                  ) : (
                    <SeverityBadge severity={r.severity_override ?? r.severity} />
                  )}
                </td>
                <td className="py-2 pr-3 tabular">{r.confidence}%</td>
                <td className="py-2 pr-3 font-mono text-[10.5px]">{r.techniques.join(" ")}</td>
                <td className="py-2 pr-3">
                  <span className={cn("font-mono text-[10px] uppercase", r.enabled ? "text-severity-low" : "text-muted-foreground")}>{r.enabled ? "enabled" : "disabled"}</span>
                </td>
                {canEdit && (
                  <td className="py-2 text-right whitespace-nowrap">
                    <Button size="sm" variant="ghost" onClick={() => void propose(r)} title="Ask the Detection Engineering agent to propose a tuning from false-positive feedback" aria-label={`Propose tuning for ${r.id}`}>
                      <Sparkles className="w-3.5 h-3.5" />
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => void toggle(r)}>{r.enabled ? "Disable" : "Enable"}</Button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
        {shown.length === 0 && <p className="text-[12.5px] text-muted-foreground italic py-3">No rules match the filters.</p>}
      </div>
    </Section>
  );
}

/* ----------------------------------------------------------------------- coverage */
function CoverageView({ coverage }: { coverage: Coverage | null }) {
  if (!coverage) return <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />;
  return (
    <Section
      title="MITRE ATT&CK coverage"
      subtitle={`Technique coverage of the rules that are enabled for your organization (rule set ${coverage.rule_version}). This counts techniques that have a rule, not how well each rule detects them; see docs/VALIDATION.md for measured detection rates. The catalog is a curated subset of ATT&CK, not the whole framework.`}
    >
      <ul className="space-y-2">
        {coverage.tactics.map((t) => {
          const pct = t.techniques_in_catalog ? Math.round((t.covered / t.techniques_in_catalog) * 100) : 0;
          return (
            <li key={t.id}>
              <div className="flex items-baseline justify-between text-[12.5px]">
                <span><span className="font-mono text-[10.5px] text-muted-foreground mr-2">{t.id}</span>{t.name}</span>
                <span className="tabular text-muted-foreground">{t.covered}/{t.techniques_in_catalog}</span>
              </div>
              <div className="h-2 rounded bg-muted overflow-hidden" role="img" aria-label={`${t.name}: ${t.covered} of ${t.techniques_in_catalog} techniques covered`}>
                <div className={cn("h-full", pct >= 80 ? "bg-severity-low" : pct >= 50 ? "bg-severity-medium" : "bg-severity-high")} style={{ width: `${pct}%` }} />
              </div>
              {t.uncovered.length > 0 && <div className="text-[11px] text-muted-foreground mt-0.5">No rule: <span className="font-mono">{t.uncovered.join(" ")}</span></div>}
            </li>
          );
        })}
      </ul>
    </Section>
  );
}

/* ----------------------------------------------------------------- custom rules */
const TEMPLATE = `{
  "rule_key": "corp-forbidden-tool",
  "name": "Forbidden remote tool",
  "severity": "high",
  "techniques": ["T1219"],
  "match": { "field": "process_name", "regex": "^(anydesk|rustdesk)(\\\\.exe)?$" },
  "tests": [
    { "name": "tool runs", "event": { "process_name": "AnyDesk.exe" }, "expect_match": true },
    { "name": "browser", "event": { "process_name": "chrome.exe" }, "expect_match": false }
  ]
}`;

function CustomRules({ rules, canEdit, reload }: { rules: CustomRule[]; canEdit: boolean; reload: () => void }) {
  const [text, setText] = useState(TEMPLATE);
  const [result, setResult] = useState<ValidationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function parse(): RuleDefinitionInput | null {
    try {
      return JSON.parse(text) as RuleDefinitionInput;
    } catch (e) {
      setError(`Not valid JSON: ${errMsg(e)}`);
      setResult(null);
      return null;
    }
  }

  async function validate() {
    const def = parse();
    if (!def) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await api.detection.validateRule(def));
    } catch (e) {
      setResult(null);
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    const def = parse();
    if (!def) return;
    setBusy(true);
    try {
      await api.detection.createRule(def);
      toast.success("Saved as a draft. Enable it once its tests pass.");
      setResult(null);
      reload();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  async function setStatus(r: CustomRule, status: CustomRule["status"]) {
    try {
      await api.detection.setRuleStatus(r.id, status);
      reload();
    } catch (e) {
      toast.error(errMsg(e));
    }
  }

  return (
    <div className="space-y-4">
      <Section title="Custom rules" subtitle="Drafts never fire. A rule can be enabled only after it has at least one passing positive and one passing negative test.">
        {rules.length === 0 && <p className="text-[12.5px] text-muted-foreground italic">No custom rules yet.</p>}
        <ul className="divide-y divide-border">
          {rules.map((r) => (
            <li key={r.id} className="py-2 flex flex-wrap items-center gap-3 text-[13px]">
              <div className="flex-1 min-w-48">
                <div className="font-mono text-[11px] text-muted-foreground">{r.rule_key} · v{r.version} · {r.origin}</div>
                <div>{r.name}</div>
              </div>
              <SeverityBadge severity={r.severity} />
              <span className={cn("font-mono text-[10px] uppercase", r.status === "enabled" ? "text-severity-low" : "text-muted-foreground")}>{r.status}</span>
              {canEdit && (
                <span className="flex gap-2">
                  {r.status !== "enabled" ? (
                    <Button size="sm" onClick={() => void setStatus(r, "enabled")}>Enable</Button>
                  ) : (
                    <Button size="sm" variant="outline" onClick={() => void setStatus(r, "disabled")}>Disable</Button>
                  )}
                  <Button size="sm" variant="ghost" onClick={() => { if (window.confirm(`Delete ${r.rule_key}?`)) void api.detection.deleteRule(r.id).then(reload); }}>Delete</Button>
                </span>
              )}
            </li>
          ))}
        </ul>
      </Section>

      {canEdit && (
        <Section title="Write a rule" subtitle="JSON definition (same DSL as the built-in rules). Validate runs its inline tests without saving anything.">
          <textarea
            aria-label="Rule definition"
            value={text}
            onChange={(e) => setText(e.target.value)}
            spellCheck={false}
            rows={14}
            className="w-full font-mono text-[12px] rounded-lg border border-input bg-transparent p-3 outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
          />
          <div className="flex gap-2">
            <Button onClick={() => void validate()} disabled={busy} variant="outline"><FlaskConical className="w-4 h-4 mr-2" />Validate &amp; run tests</Button>
            <Button onClick={() => void save()} disabled={busy}>Save as draft</Button>
          </div>
          {error && (
            <div role="alert" className="flex items-start gap-2 text-[12.5px] text-severity-critical"><AlertCircle className="w-4 h-4 mt-0.5 shrink-0" /> {error}</div>
          )}
          {result && (
            <div role="status" className="text-[12.5px] space-y-1">
              <div className={cn("flex items-center gap-1.5 font-semibold", result.tests_passed && result.has_positive_and_negative ? "text-severity-low" : "text-severity-high")}>
                {result.tests_passed && result.has_positive_and_negative ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                {result.tests_passed && result.has_positive_and_negative ? "Valid. All tests pass; it can be enabled once saved." : "Valid, but not ready to enable (needs passing positive and negative tests)."}
              </div>
              <div className="text-muted-foreground">Tactics derived: {result.tactics.join(", ") || "none"}</div>
              {result.attack_warnings.length > 0 && <div className="text-severity-medium">{result.attack_warnings.join("; ")}</div>}
              <ul>
                {result.tests.map((t, i) => (
                  <li key={i} className={t.passed ? "text-severity-low" : "text-severity-critical"}>
                    {t.passed ? "✓" : "✗"} {t.name}: expected {t.expected ? "match" : "no match"}, got {t.matched ? "match" : "no match"}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Section>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------------ sigma */
function SigmaImport({ canEdit, reload }: { canEdit: boolean; reload: () => void }) {
  const [text, setText] = useState("");
  const [preview, setPreview] = useState<{ rule: RuleDefinitionInput; warnings: string[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function convert() {
    setBusy(true);
    setError(null);
    try {
      setPreview(await api.detection.convertSigma(text));
    } catch (e) {
      setPreview(null);
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }
  async function importIt() {
    setBusy(true);
    try {
      await api.detection.importSigma(text);
      toast.success("Imported as a draft. Add tests, then enable it.");
      setText("");
      setPreview(null);
      reload();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section title="Import a Sigma rule" subtitle="Supports selections, field modifiers, and/or/not and 1-of/all-of conditions. Aggregations (count, near, timeframe) and transforming modifiers are rejected, not guessed.">
      <textarea
        aria-label="Sigma rule YAML"
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
        rows={12}
        placeholder={"title: Suspicious tool\nlevel: high\ndetection:\n  selection:\n    CommandLine|contains: evil\n  condition: selection"}
        className="w-full font-mono text-[12px] rounded-lg border border-input bg-transparent p-3 outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
      />
      <div className="flex gap-2">
        <Button variant="outline" onClick={() => void convert()} disabled={busy || text.trim().length < 10}>Preview conversion</Button>
        {canEdit && <Button onClick={() => void importIt()} disabled={busy || !preview}>Import as draft</Button>}
      </div>
      {error && <div role="alert" className="flex items-start gap-2 text-[12.5px] text-severity-critical"><AlertCircle className="w-4 h-4 mt-0.5 shrink-0" /> {error}</div>}
      {preview && (
        <div className="space-y-1.5">
          {preview.warnings.map((w) => (
            <div key={w} className="text-[12px] text-severity-medium">⚠ {w}</div>
          ))}
          <pre className="font-mono text-[11.5px] bg-muted/50 rounded-lg p-3 overflow-x-auto">{JSON.stringify({ ...preview.rule, sigma_source: undefined }, null, 2)}</pre>
        </div>
      )}
    </Section>
  );
}

/* ------------------------------------------------------------------------- page */
export default function DetectionPage() {
  const role = useUserStore((s) => s.profile?.role);
  const canEdit = role === "owner" || role === "admin";
  const [tab, setTab] = useState<Tab>("rules");
  const [data, setData] = useState<RulesResponse | null>(null);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    let live = true;
    Promise.all([api.detection.listRules(), api.detection.getCoverage()])
      .then(([r, c]) => {
        if (!live) return;
        setData(r);
        setCoverage(c);
        setError(null);
      })
      .catch((e) => live && setError(errMsg(e)));
    return () => {
      live = false;
    };
  }, [tick]);

  const tabs: Array<[Tab, string]> = [["rules", "Built-in rules"], ["coverage", "Coverage"], ["custom", "Custom rules"], ["sigma", "Sigma import"]];

  return (
    <div className="space-y-6 pb-12 max-w-5xl">
      <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <h1 className="title-serif text-[24px] sm:text-[30px] tracking-[-0.03em]">Detection</h1>
        <p className="text-[13.5px] text-muted-foreground mt-1">
          What ThreatBrain looks for, how well it is covered, and how you tune it to your environment.
          {data && <span className="font-mono text-[11px] ml-2">rule set {data.version}</span>}
        </p>
      </motion.div>

      <div role="tablist" aria-label="Detection sections" className="flex flex-wrap gap-1 border-b border-border">
        {tabs.map(([id, label]) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
            className={cn("px-3 py-2 text-[13px] -mb-px border-b-2", tab === id ? "border-foreground font-semibold" : "border-transparent text-muted-foreground hover:text-foreground")}
          >
            {label}
            {data && id === "custom" && <span className="ml-1.5 font-mono text-[10.5px] text-muted-foreground">{data.custom.length}</span>}
          </button>
        ))}
      </div>

      {error && <div role="alert" className="flex items-start gap-2 text-[13px] text-severity-critical"><AlertCircle className="w-4 h-4 mt-0.5" /> {error}</div>}
      {!data && !error && <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />}
      {data && tab === "rules" && <BuiltinRules rules={data.builtin} canEdit={canEdit} reload={reload} />}
      {tab === "coverage" && <CoverageView coverage={coverage} />}
      {data && tab === "custom" && <CustomRules rules={data.custom} canEdit={canEdit} reload={reload} />}
      {tab === "sigma" && <SigmaImport canEdit={canEdit} reload={reload} />}
    </div>
  );
}
