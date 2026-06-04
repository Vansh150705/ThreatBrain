import { motion } from "motion/react";
import { CheckCircle2, XCircle, MinusCircle, Loader2 } from "lucide-react";

import type { OrchestratorStage } from "@/lib/api/types";
import { cn } from "@/lib/utils";

// Pipeline stages in the order the orchestrator runs them
const STAGE_ORDER: Array<{ key: string; label: string }> = [
  { key: "triage", label: "Triage" },
  { key: "threat_intel", label: "Threat Intel" },
  { key: "investigation", label: "Investigation" },
  { key: "response", label: "Response" },
  { key: "forensics", label: "Forensics" },
  { key: "compliance", label: "Compliance" },
];

interface PipelineProgressProps {
  stages: Record<string, OrchestratorStage> | null;
  isRunning: boolean;
}

export default function PipelineProgress({ stages, isRunning }: PipelineProgressProps) {
  return (
    <div className="space-y-2">
      {STAGE_ORDER.map(({ key, label }, idx) => {
        const stage = stages?.[key];
        const status = stage?.status;

        // Determine icon + color
        let icon: React.ReactNode;
        let textClass = "text-slate-500";
        let bgClass = "bg-slate-100";

        if (!stages && isRunning) {
          icon = <Loader2 className="w-4 h-4 animate-spin text-slate-400" />;
        } else if (status === "ok") {
          icon = <CheckCircle2 className="w-4 h-4 text-green-600" />;
          textClass = "text-slate-900 font-medium";
          bgClass = "bg-green-50";
        } else if (status === "failed") {
          icon = <XCircle className="w-4 h-4 text-red-600" />;
          textClass = "text-red-700 font-medium";
          bgClass = "bg-red-50";
        } else if (status === "skipped") {
          icon = <MinusCircle className="w-4 h-4 text-slate-400" />;
          textClass = "text-slate-400";
          bgClass = "bg-slate-50";
        } else {
          icon = <div className="w-4 h-4 rounded-full border-2 border-slate-300" />;
          textClass = "text-slate-400";
        }

        return (
          <motion.div
            key={key}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: idx * 0.04 }}
            className={cn(
              "flex items-center justify-between gap-3 px-3 py-2 rounded-md transition-colors",
              bgClass
            )}
          >
            <div className="flex items-center gap-2.5 min-w-0">
              {icon}
              <span className={cn("text-sm", textClass)}>{label}</span>
            </div>
            <div className="flex items-center gap-3 text-xs text-slate-500 font-mono">
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