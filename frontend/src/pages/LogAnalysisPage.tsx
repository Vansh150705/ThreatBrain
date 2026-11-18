import { useState } from "react";
import { motion } from "motion/react";
import { AlertCircle, CheckCircle2, Loader2, ScanSearch, TriangleAlert } from "lucide-react";

import { api } from "@/lib/api";
import type { LogAnalysisResponse } from "@/lib/api/logAnalysis";
import { Button } from "@/components/ui/button";
import SeverityBadge from "@/components/SeverityBadge";

const MAX_LINES = 300;

export default function LogAnalysisPage() {
  const [text, setText] = useState("");
  const [hint, setHint] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<LogAnalysisResponse | null>(null);

  const lines = text.split("\n").filter((l) => l.trim());
  const tooMany = lines.length > MAX_LINES;

  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.logAnalysis.analyzeLogs(text, hint));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const v = result?.verdict;

  return (
    <div className="space-y-6 pb-12">
      <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <h1 className="title-serif text-[24px] sm:text-[30px] tracking-[-0.03em]">Log analysis</h1>
        <p className="text-[13.5px] text-muted-foreground mt-1 max-w-2xl">
          Paste raw log lines (auth, web, firewall, CloudTrail…). The Log Analysis agent extracts entities and findings; every
          cited line number and entity is verified against your text, and deterministic detection rules run line by line.
        </p>
      </motion.div>

      <div className="bg-card border border-border rounded-xl p-4 sm:p-5 space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            value={hint}
            onChange={(e) => setHint(e.target.value)}
            maxLength={100}
            placeholder="Source (optional): sshd auth.log, nginx access, CloudTrail…"
            aria-label="Log source"
            className="flex-1 rounded-lg border border-input bg-transparent px-3 h-9 text-[13px] outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
          />
        </div>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={10}
          spellCheck={false}
          aria-label="Log lines"
          placeholder={"Oct 27 10:00:01 web sshd[411]: Failed password for root from 203.0.113.9 port 4444 ssh2\n…"}
          className="w-full font-mono text-[12px] rounded-lg border border-input bg-transparent px-3 py-2 outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
        />
        <div className="flex items-center justify-between gap-3">
          <span className={`text-[12px] ${tooMany ? "text-severity-critical" : "text-muted-foreground"}`}>
            {lines.length} / {MAX_LINES} lines
          </span>
          <Button onClick={run} disabled={busy || lines.length === 0 || tooMany}>
            {busy ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <ScanSearch className="w-4 h-4 mr-2" />}
            Analyse
          </Button>
        </div>
      </div>

      {error && (
        <div role="alert" className="flex items-start gap-2.5 p-3.5 border border-severity-critical/30 bg-severity-critical/5 rounded-lg">
          <AlertCircle className="w-4 h-4 text-severity-critical shrink-0 mt-0.5" />
          <span className="text-[13px]">{error}</span>
        </div>
      )}

      {v && (
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
          <div className="bg-card border border-border rounded-xl p-4 sm:p-5">
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <SeverityBadge severity={v.severity} />
              <span className="font-mono text-[11px] text-muted-foreground">{v.confidence}% confidence · {v.lines_analyzed} lines · {result.model}</span>
            </div>
            <p className="text-[14px] leading-relaxed">{v.summary}</p>
            {v.reasoning && <p className="text-[12.5px] text-muted-foreground mt-2">{v.reasoning}</p>}
          </div>

          <div className="bg-card border border-border rounded-xl p-4 sm:p-5">
            <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-3">
              Findings ({v.findings.length})
            </div>
            {v.findings.length === 0 ? (
              <p className="text-[12.5px] text-muted-foreground italic">No suspicious activity identified.</p>
            ) : (
              <ul className="space-y-3">
                {v.findings.map((f, i) => (
                  <li key={i} className="p-3 bg-muted/40 rounded-lg">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="text-[13.5px] font-medium">{f.title}</span>
                      {f.verified ? (
                        <span className="inline-flex items-center gap-1 text-[11px] text-severity-low" title="All cited line numbers exist in your log">
                          <CheckCircle2 className="w-3.5 h-3.5" /> evidence verified
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] text-severity-medium" title="The model cited no valid line numbers">
                          <TriangleAlert className="w-3.5 h-3.5" /> unverified
                        </span>
                      )}
                    </div>
                    {f.detail && <p className="text-[12.5px] text-foreground/80 mt-1">{f.detail}</p>}
                    <div className="font-mono text-[10.5px] text-muted-foreground mt-1.5">
                      {f.evidence_lines.length > 0 && <>lines {f.evidence_lines.join(", ")}</>}
                      {f.mitre_techniques.length > 0 && <> · {f.mitre_techniques.join(", ")}</>}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {v.rule_hits.length > 0 && (
            <div className="bg-card border border-border rounded-xl p-4 sm:p-5">
              <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-3">
                Deterministic rule hits ({v.rule_hits.length})
              </div>
              <ul className="space-y-1.5 text-[12.5px]">
                {v.rule_hits.map((h, i) => (
                  <li key={i} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11px] bg-muted px-1.5 py-0.5 rounded">line {h.line}</span>
                    <span className="font-mono text-[11px]">{h.rule_id}</span>
                    <SeverityBadge severity={h.severity} />
                    <span>{h.name}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="bg-card border border-border rounded-xl p-4 sm:p-5">
            <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-3">
              Entities (verified against the log text)
            </div>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {(Object.keys(v.entities) as Array<keyof typeof v.entities>).map((k) =>
                v.entities[k].length ? (
                  <div key={k}>
                    <div className="text-[11px] text-muted-foreground capitalize mb-1">{k}</div>
                    <div className="flex flex-wrap gap-1.5">
                      {v.entities[k].map((e) => (
                        <span key={e} className="font-mono text-[11px] px-2 py-0.5 bg-muted rounded break-all">{e}</span>
                      ))}
                    </div>
                  </div>
                ) : null
              )}
            </div>
          </div>

          {v.suggested_detections.length > 0 && (
            <div className="bg-card border border-border rounded-xl p-4 sm:p-5">
              <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-2">
                Suggested detections
              </div>
              <ul className="list-disc pl-5 text-[12.5px] space-y-1">
                {v.suggested_detections.map((d, i) => (
                  <li key={i}>{d}</li>
                ))}
              </ul>
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
}
