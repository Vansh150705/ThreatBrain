import { motion } from "motion/react";
import { CheckCircle2, XCircle, MinusCircle, Loader2 } from "lucide-react";

import type { OrchestratorStage } from "@/lib/api/types";
import { cn } from "@/lib/utils";

const STAGE_ORDER: Array<{ key: string; label: string }> = [
  { key: "triage",        label: "Triage" },
  { key: "threat_intel",  label: "Threat Intel" },
  { key: "investigation", label: "Investigation" },
  { key: "response",      label: "Response" },
  { key: "forensics",     label: "Forensics" },
  { key: "compliance",    label: "Compliance" },
];

interface PipelineProgressProps {
  stages: Record<string, OrchestratorStage> | null;
  isRunning: boolean;
}

export default function PipelineProgress({ stages, isRunning }: PipelineProgressProps) {
  return (
    <div className="space-y-1.5">
      {STAGE_ORDER.map(({ key, label }, idx) => {
        const stage = stages?.[key];
        const status = stage?.status;

        let icon: React.ReactNode;
        let rowClass = "bg-muted/50";
        let textClass = "text-muted-foreground";

        if (!stages && isRunning) {
          icon = <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground/60" />;
        } else if (status === "ok") {
          icon = <CheckCircle2 className="w-3.5 h-3.5 text-severity-low" />;
          textClass = "text-foreground font-medium";
          rowClass = "bg-severity-low/8";
        } else if (status === "failed") {
          icon = <XCircle className="w-3.5 h-3.5 text-severity-critical" />;
          textClass = "text-severity-critical font-medium";
          rowClass = "bg-severity-critical/8";
        } else if (status === "skipped") {
          icon = <MinusCircle className="w-3.5 h-3.5 text-muted-foreground/40" />;
          textClass = "text-muted-foreground/50";
          rowClass = "bg-muted/30";
        } else {
          icon = <div className="w-3.5 h-3.5 rounded-full border-2 border-border" />;
        }

        return (
          <motion.div
            key={key}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: idx * 0.04 }}
            className={cn(
              "flex items-center justify-between gap-3 px-3 py-2 rounded-md transition-colors",
              rowClass
            )}
          >
            <div className="flex items-center gap-2 min-w-0">
              {icon}
              <span className={cn("text-[13px]", textClass)}>{label}</span>
            </div>
            <div className="flex items-center gap-3 font-mono text-[10.5px] text-muted-foreground tabular">
              {stage?.latency_ms != null && <span>{stage.latency_ms}ms</span>}
              {stage?.tokens != null && stage.tokens > 0 && (
                <span>{stage.tokens} tok</span>
              )}
              {status === "skipped" && stage?.reason && (
                <span className="italic">skipped</span>
              )}
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}
