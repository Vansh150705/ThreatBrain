import { useState } from "react";
import { Link } from "react-router-dom";
import { Sparkles, Play, RotateCcw, ExternalLink, CheckCircle2, AlertCircle } from "lucide-react";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { OrchestratorResponse, TriageEventPayload } from "@/lib/api/types";
import { SCENARIOS, type Scenario } from "@/lib/scenarios";
import PipelineProgress from "./PipelineProgress";

type RunState = "idle" | "running" | "success" | "failed";

export default function TriggerPipelineDialog() {
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<Scenario>(SCENARIOS[0]);
  const [runState, setRunState] = useState<RunState>("idle");
  const [result, setResult] = useState<OrchestratorResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"scenario" | "custom">("scenario");

  const [customTitle, setCustomTitle] = useState("");
  const [customDescription, setCustomDescription] = useState("");
  const [customSourceIp, setCustomSourceIp] = useState("");

  function reset() {
    setRunState("idle");
    setResult(null);
    setError(null);
  }

  async function runPipeline(event: TriageEventPayload) {
    setRunState("running");
    setResult(null);
    setError(null);

    try {
      const response = await api.orchestrator.handleEvent({
        event,
        promote_threats: true,
        run_threat_intel: true,
        run_investigation: true,
        run_response: true,
        run_forensics: true,
        run_compliance: true,
      });
      setResult(response);
      setRunState("success");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      setRunState("failed");
    }
  }

  function runPreset() {
    return runPipeline(selected.event);
  }

  function runCustom() {
    if (!customTitle.trim()) {
      setError("Title is required");
      setRunState("failed");
      return;
    }
    return runPipeline({
      title: customTitle.trim(),
      description: customDescription.trim() || undefined,
      source: "custom",
      event_type: "custom_alert",
      source_ip: customSourceIp.trim() || undefined,
      asset_name: "demo-asset",
      asset_environment: "production",
      asset_criticality: "high",
    });
  }

  const isRunning = runState === "running";
  const isComplete = runState === "success" || runState === "failed";

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) reset();
      }}
    >
      <DialogTrigger asChild>
        <Button
          size="sm"
          className="bg-foreground text-background hover:bg-foreground/90 h-9 px-4 text-[13px] font-medium"
        >
          <Sparkles className="w-4 h-4 mr-2" />
          Trigger pipeline
        </Button>
      </DialogTrigger>

      <DialogContent className="sm:max-w-2xl w-[calc(100vw-2rem)] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-[16px] tracking-[-0.015em]">
            <Sparkles className="w-4 h-4 text-foreground" />
            Run a security event through the AI pipeline
          </DialogTitle>
          <DialogDescription className="text-[13px]">
            Send an alert to the orchestrator. Watch the 6 agents work through it end-to-end.
          </DialogDescription>
        </DialogHeader>

        {runState === "idle" && (
          <div className="mt-2">
            {/* Tab bar */}
            <div className="flex items-center border-b border-border gap-5 mb-5">
              {(["scenario", "custom"] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setActiveTab(t)}
                  className={`pb-2.5 text-[13px] font-medium border-b-2 transition-colors capitalize ${
                    activeTab === t
                      ? "border-foreground text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {t === "scenario" ? "Pick a scenario" : "Custom alert"}
                </button>
              ))}
            </div>

            {activeTab === "scenario" && (
              <div className="space-y-2">
                <div className="space-y-1.5">
                  {SCENARIOS.map((s) => (
                    <button
                      key={s.id}
                      type="button"
                      onClick={() => setSelected(s)}
                      className={`w-full text-left p-3.5 rounded-lg border transition-all ${
                        selected.id === s.id
                          ? "border-foreground bg-muted"
                          : "border-border hover:border-foreground/25 hover:bg-accent/40"
                      }`}
                    >
                      <div className="text-[13px] font-medium text-foreground tracking-[-0.01em]">
                        {s.title}
                      </div>
                      <div className="text-[12px] text-muted-foreground mt-0.5">
                        {s.blurb}
                      </div>
                    </button>
                  ))}
                </div>
                <Button
                  className="w-full mt-3 bg-foreground text-background hover:bg-foreground/90 h-10 text-[13px] font-medium"
                  onClick={runPreset}
                >
                  <Play className="w-4 h-4 mr-2" />
                  Run pipeline
                </Button>
              </div>
            )}

            {activeTab === "custom" && (
              <div className="space-y-3">
                <div className="space-y-1.5">
                  <Label htmlFor="custom-title" className="text-[12.5px] font-medium">
                    Alert title *
                  </Label>
                  <Input
                    id="custom-title"
                    value={customTitle}
                    onChange={(e) => setCustomTitle(e.target.value)}
                    placeholder="e.g. Suspicious lateral movement detected"
                    className="h-10 text-[13px]"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="custom-desc" className="text-[12.5px] font-medium">
                    Description
                  </Label>
                  <textarea
                    id="custom-desc"
                    value={customDescription}
                    onChange={(e) => setCustomDescription(e.target.value)}
                    rows={3}
                    className="w-full px-3 py-2 text-[13px] border border-border rounded-md resize-none focus:outline-none focus:ring-2 focus:ring-foreground/15 focus:border-foreground bg-background"
                    placeholder="What did you observe?"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="custom-ip" className="text-[12.5px] font-medium">
                    Source IP (optional)
                  </Label>
                  <Input
                    id="custom-ip"
                    value={customSourceIp}
                    onChange={(e) => setCustomSourceIp(e.target.value)}
                    placeholder="e.g. 198.51.100.42"
                    className="h-10 text-[13px]"
                  />
                  <p className="text-[11.5px] text-muted-foreground">
                    If provided, Threat Intel agent will check it against AbuseIPDB.
                  </p>
                </div>
                <Button
                  className="w-full bg-foreground text-background hover:bg-foreground/90 h-10 text-[13px] font-medium"
                  onClick={runCustom}
                >
                  <Play className="w-4 h-4 mr-2" />
                  Run pipeline
                </Button>
              </div>
            )}
          </div>
        )}

        {(isRunning || isComplete) && (
          <div className="space-y-4 mt-4">
            <div className="font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground">
              {isRunning && "Running 6-stage AI pipeline..."}
              {runState === "success" && "Pipeline completed."}
              {runState === "failed" && "Pipeline failed."}
            </div>

            <PipelineProgress stages={result?.stages ?? null} isRunning={isRunning} />

            {runState === "success" && result && (
              <div className="border border-severity-low/30 bg-severity-low/5 rounded-lg p-4">
                <div className="flex items-start gap-3">
                  <CheckCircle2 className="w-4 h-4 text-severity-low flex-shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <div className="text-[13px] font-semibold text-foreground">
                      Pipeline complete
                    </div>
                    <div className="mt-1.5 space-y-0.5 font-mono text-[11px] text-muted-foreground">
                      <div>
                        Stages succeeded:{" "}
                        <span className="text-foreground font-semibold">
                          {result.summary.stages_succeeded} / {result.summary.stages_run}
                        </span>
                      </div>
                      {result.summary.incident_short_id && (
                        <div>
                          Incident:{" "}
                          <span className="text-foreground font-semibold">
                            {result.summary.incident_short_id}
                          </span>
                        </div>
                      )}
                      {result.summary.promoted_threat_id && (
                        <div>
                          New threat:{" "}
                          <span className="text-foreground font-semibold">
                            {result.summary.promoted_threat_id.slice(0, 8)}...
                          </span>
                        </div>
                      )}
                    </div>

                    <div className="flex flex-wrap gap-2 mt-3">
                      <Link
                        to="/threats"
                        onClick={() => setOpen(false)}
                        className="inline-flex items-center gap-1 text-[12px] font-medium text-foreground hover:text-muted-foreground bg-background px-2.5 py-1 rounded border border-border transition-colors"
                      >
                        <ExternalLink className="w-3 h-3" />
                        View threats
                      </Link>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={reset}
                        className="text-[12px] h-auto py-1 px-2.5"
                      >
                        <RotateCcw className="w-3 h-3 mr-1" />
                        Run again
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {runState === "failed" && (
              <div className="border border-severity-critical/30 bg-severity-critical/5 rounded-lg p-4">
                <div className="flex items-start gap-3">
                  <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <div className="text-[13px] font-semibold text-foreground">
                      Pipeline failed
                    </div>
                    <div className="text-[12px] text-muted-foreground mt-1 break-words font-mono">
                      {error || "Unknown error"}
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={reset}
                      className="text-[12px] h-auto py-1 px-2.5 mt-3"
                    >
                      <RotateCcw className="w-3 h-3 mr-1" />
                      Try again
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
