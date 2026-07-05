import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { CheckCircle2, XCircle, MinusCircle } from "lucide-react";

import type { OrchestratorStage } from "@/lib/api/types";
import { cn } from "@/lib/utils";

/**
 * The orchestrator returns every stage in a single response (no streaming), so
 * during the run there is no real per-stage signal to show. To keep the wait
 * engaging we simulate a live walkthrough: advance through the stages on a
 * timeline calibrated to their real durations, then snap to the actual results
 * the moment the response arrives.
 */
type Stage = { key: string; label: string; est: number; hints: string[] };

const STAGES: Stage[] = [
  { key: "triage", label: "Triage", est: 4, hints: ["Classifying severity", "Mapping to MITRE ATT&CK", "Scoring confidence"] },
  { key: "threat_intel", label: "Threat Intel", est: 5, hints: ["Querying AbuseIPDB", "Scoring IP reputation", "Checking known feeds"] },
  { key: "investigation", label: "Investigation", est: 16, hints: ["Correlating recent threats", "Grouping into incidents", "Tracing the kill chain"] },
  { key: "response", label: "Response", est: 8, hints: ["Selecting playbooks", "Prioritizing actions", "Drafting remediation"] },
  { key: "forensics", label: "Forensics", est: 20, hints: ["Reconstructing the timeline", "Collecting artifacts", "Building chain of custody"] },
  { key: "compliance", label: "Compliance", est: 12, hints: ["Assessing GDPR & SOC 2", "Checking notification duties", "Weighing data exposure"] },
];

const EST_TOTAL = STAGES.reduce((sum, s) => sum + s.est, 0);

// Wall-clock second at which each stage becomes the "active" one.
const STAGE_STARTS = STAGES.reduce<number[]>((arr, _s, i) => {
  arr.push(i === 0 ? 0 : arr[i - 1] + STAGES[i - 1].est);
  return arr;
}, []);

function simIdxFor(elapsed: number): number {
  let idx = 0;
  for (let i = 0; i < STAGES.length; i++) {
    if (elapsed >= STAGE_STARTS[i]) idx = i;
  }
  return idx;
}

type View = "pending" | "active" | "done" | "ok" | "failed" | "skipped";

interface PipelineProgressProps {
  stages: Record<string, OrchestratorStage> | null;
  isRunning: boolean;
}

export default function PipelineProgress({ stages, isRunning }: PipelineProgressProps) {
  const hasResult = !!stages;
  const reduce = useReducedMotion();

  // A single elapsed clock drives the simulation; stage index and caption are
  // derived from it, so there is no synchronous state reset inside the effect.
  const [elapsed, setElapsed] = useState(0);
  const startRef = useRef(0);

  useEffect(() => {
    if (!isRunning || hasResult) return;
    startRef.current = Date.now();
    const tick = () => setElapsed((Date.now() - startRef.current) / 1000);
    const first = window.setTimeout(tick, 0);
    const timer = window.setInterval(tick, 100);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(timer);
    };
  }, [isRunning, hasResult]);

  const simIdx = simIdxFor(elapsed);
  const hintTick = Math.floor(elapsed / 2.2);

  // Cap simulated progress below 100% so the bar never "finishes" before the
  // real response lands; snap to full (or the fail state) once it does.
  const anyFailed = hasResult && Object.values(stages!).some((s) => s.status === "failed");
  const progress = hasResult ? 1 : Math.min(elapsed / EST_TOTAL, 0.92);

  const viewFor = (i: number, key: string): View => {
    if (hasResult) {
      const s = stages?.[key]?.status;
      return s === "ok" ? "ok" : s === "failed" ? "failed" : s === "skipped" ? "skipped" : "pending";
    }
    if (i < simIdx) return "done";
    if (i === simIdx) return "active";
    return "pending";
  };

  return (
    <div>
      {/* Overall progress bar + elapsed */}
      <div className="flex items-center gap-3 mb-4">
        <div className="relative h-1 flex-1 rounded-full bg-muted overflow-hidden">
          <motion.div
            className={cn(
              "absolute inset-y-0 left-0 rounded-full",
              anyFailed ? "bg-severity-critical/70" : "bg-foreground"
            )}
            animate={{ width: `${progress * 100}%` }}
            transition={{ ease: "easeOut", duration: hasResult ? 0.5 : 0.4 }}
          />
          {!hasResult && !reduce && (
            <motion.div
              className="absolute inset-y-0 w-1/3 bg-gradient-to-r from-transparent via-white/50 to-transparent"
              animate={{ x: ["-120%", "420%"] }}
              transition={{ duration: 1.6, repeat: Infinity, ease: "easeInOut" }}
            />
          )}
        </div>
        <span className="font-mono text-[10.5px] tabular-nums text-muted-foreground w-11 text-right">
          {(hasResult ? Math.max(elapsed, 0.1) : elapsed).toFixed(1)}s
        </span>
      </div>

      {/* Stepper with a filling spine */}
      <div className="relative">
        <div className="absolute left-[11px] top-3 bottom-3 w-px bg-border" />
        <motion.div
          className={cn(
            "absolute left-[11px] top-3 w-px origin-top",
            anyFailed ? "bg-severity-critical/50" : "bg-severity-low"
          )}
          style={{ bottom: 12 }}
          animate={{ scaleY: progress }}
          transition={{ ease: "easeOut", duration: 0.4 }}
        />

        <div className="space-y-1">
          {STAGES.map((s, i) => {
            const view = viewFor(i, s.key);
            const stage = stages?.[s.key];
            const active = view === "active";

            return (
              <motion.div
                key={s.key}
                initial={{ opacity: 0, x: -6 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: hasResult ? i * 0.03 : 0 }}
                className="relative flex items-center gap-3"
              >
                {/* Node */}
                <div className="relative z-10 flex-shrink-0">
                  <StageNode view={view} reduce={!!reduce} />
                </div>

                {/* Row body */}
                <div
                  className={cn(
                    "relative flex-1 min-w-0 flex items-center justify-between gap-3 rounded-md px-3 py-2 overflow-hidden transition-colors",
                    active && "bg-accent/50",
                    view === "ok" && "bg-severity-low/[0.07]",
                    view === "failed" && "bg-severity-critical/[0.07]",
                    (view === "pending" || view === "skipped") && "bg-transparent"
                  )}
                >
                  {active && !reduce && (
                    <motion.div
                      className="absolute inset-0 bg-gradient-to-r from-transparent via-foreground/[0.05] to-transparent"
                      animate={{ x: ["-100%", "100%"] }}
                      transition={{ duration: 1.8, repeat: Infinity, ease: "easeInOut" }}
                    />
                  )}

                  <div className="relative min-w-0">
                    <div
                      className={cn(
                        "text-[13px] leading-tight transition-colors",
                        active && "text-foreground font-medium",
                        view === "done" && "text-foreground/80",
                        view === "ok" && "text-foreground font-medium",
                        view === "failed" && "text-severity-critical font-medium",
                        (view === "pending" || view === "skipped") && "text-muted-foreground/60"
                      )}
                    >
                      {s.label}
                    </div>

                    {/* Rotating micro-caption on the active stage */}
                    <AnimatePresence mode="wait">
                      {active && (
                        <motion.div
                          key={hintTick % s.hints.length}
                          initial={{ opacity: 0, y: 3 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -3 }}
                          transition={{ duration: 0.28 }}
                          className="font-mono text-[10.5px] text-muted-foreground mt-0.5"
                        >
                          {s.hints[hintTick % s.hints.length]}
                          <span className="inline-block w-1 ml-0.5 animate-pulse">▍</span>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>

                  {/* Right-side meta */}
                  <div className="relative flex items-center gap-2.5 font-mono text-[10.5px] text-muted-foreground tabular-nums flex-shrink-0">
                    {view === "skipped" && <span className="italic text-muted-foreground/50">skipped</span>}
                    {(view === "ok" || view === "failed") && stage?.latency_ms != null && (
                      <span>{formatMs(stage.latency_ms)}</span>
                    )}
                    {(view === "ok" || view === "failed") && stage?.tokens != null && stage.tokens > 0 && (
                      <span className="text-muted-foreground/70">{stage.tokens} tok</span>
                    )}
                    {active && !reduce && <WorkingDots />}
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function StageNode({ view, reduce }: { view: View; reduce: boolean }) {
  if (view === "ok" || view === "done") {
    return <CheckCircle2 className="w-[22px] h-[22px] text-severity-low bg-background rounded-full" />;
  }
  if (view === "failed") {
    return <XCircle className="w-[22px] h-[22px] text-severity-critical bg-background rounded-full" />;
  }
  if (view === "skipped") {
    return <MinusCircle className="w-[22px] h-[22px] text-muted-foreground/40 bg-background rounded-full" />;
  }
  if (view === "active") {
    return (
      <span className="relative flex items-center justify-center w-[22px] h-[22px] rounded-full bg-background">
        {!reduce && (
          <motion.span
            className="absolute inset-0 rounded-full border border-foreground/30"
            animate={{ scale: [1, 1.55], opacity: [0.6, 0] }}
            transition={{ duration: 1.4, repeat: Infinity, ease: "easeOut" }}
          />
        )}
        <motion.span
          className="w-2.5 h-2.5 rounded-full bg-foreground"
          animate={reduce ? {} : { scale: [1, 0.75, 1] }}
          transition={{ duration: 1.4, repeat: Infinity, ease: "easeInOut" }}
        />
      </span>
    );
  }
  // pending
  return (
    <span className="flex items-center justify-center w-[22px] h-[22px] rounded-full bg-background">
      <span className="w-2.5 h-2.5 rounded-full border-2 border-border" />
    </span>
  );
}

function WorkingDots() {
  return (
    <span className="flex items-center gap-0.5">
      {[0, 1, 2].map((i) => (
        <motion.span
          key={i}
          className="w-1 h-1 rounded-full bg-foreground/60"
          animate={{ opacity: [0.25, 1, 0.25] }}
          transition={{ duration: 1.1, repeat: Infinity, delay: i * 0.18, ease: "easeInOut" }}
        />
      ))}
    </span>
  );
}

function formatMs(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}
