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
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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

  // Custom alert fields
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
          className="bg-gradient-to-br from-primary-600 to-primary-700 hover:from-primary-700 hover:to-primary-800 text-white shadow-md shadow-primary-500/20"
        >
          <Sparkles className="w-4 h-4 mr-2" />
          Trigger pipeline
        </Button>
      </DialogTrigger>

      <DialogContent className="sm:max-w-2xl w-[calc(100vw-2rem)] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-primary-600" />
            Run a security event through the AI pipeline
          </DialogTitle>
          <DialogDescription>
            Send an alert to the orchestrator. Watch the 6 agents work through it end-to-end.
          </DialogDescription>
        </DialogHeader>

        {runState === "idle" && (
          <Tabs defaultValue="scenario" className="w-full mt-2">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="scenario">Pick a scenario</TabsTrigger>
              <TabsTrigger value="custom">Custom alert</TabsTrigger>
            </TabsList>

            <TabsContent value="scenario" className="space-y-2 mt-4">
              <div className="space-y-2">
                {SCENARIOS.map((s) => (
                  <button
                    key={s.id}
                    type="button"
                    onClick={() => setSelected(s)}
                    className={`w-full text-left p-3 rounded-md border transition-all ${
                      selected.id === s.id
                        ? "border-primary-500 bg-primary-50 ring-1 ring-primary-500"
                        : "border-slate-200 hover:border-slate-300 hover:bg-slate-50"
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <span className="text-xl shrink-0">{s.emoji}</span>
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium text-slate-900">
                          {s.title}
                        </div>
                        <div className="text-xs text-slate-500 mt-0.5">
                          {s.blurb}
                        </div>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
              <Button className="w-full mt-3 bg-primary-600 hover:bg-primary-700 text-white" onClick={runPreset}>
                <Play className="w-4 h-4 mr-2" />
                Run pipeline
              </Button>
            </TabsContent>

            <TabsContent value="custom" className="space-y-3 mt-4">
              <div className="space-y-1.5">
                <Label htmlFor="custom-title">Alert title *</Label>
                <Input
                  id="custom-title"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  placeholder="e.g. Suspicious lateral movement detected"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="custom-desc">Description</Label>
                <textarea
                  id="custom-desc"
                  value={customDescription}
                  onChange={(e) => setCustomDescription(e.target.value)}
                  rows={3}
                  className="w-full px-3 py-2 text-sm border border-slate-200 rounded-md resize-none focus:outline-none focus:ring-2 focus:ring-primary-500/30 focus:border-primary-500"
                  placeholder="What did you observe?"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="custom-ip">Source IP (optional)</Label>
                <Input
                  id="custom-ip"
                  value={customSourceIp}
                  onChange={(e) => setCustomSourceIp(e.target.value)}
                  placeholder="e.g. 198.51.100.42"
                />
                <p className="text-xs text-slate-500">
                  If provided, Threat Intel agent will check it against AbuseIPDB.
                </p>
              </div>
              <Button className="w-full bg-primary-600 hover:bg-primary-700 text-white" onClick={runCustom}>
                <Play className="w-4 h-4 mr-2" />
                Run pipeline
              </Button>
            </TabsContent>
          </Tabs>
        )}

        {(isRunning || isComplete) && (
          <div className="space-y-4 mt-4">
            <div className="text-xs text-slate-500">
              {isRunning && "Running 6-stage AI pipeline…"}
              {runState === "success" && "Pipeline completed."}
              {runState === "failed" && "Pipeline failed."}
            </div>

            <PipelineProgress stages={result?.stages ?? null} isRunning={isRunning} />

            {runState === "success" && result && (
              <Card className="border-green-200 bg-green-50/30">
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-green-600 flex-shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-green-900">
                        Pipeline complete
                      </div>
                      <div className="text-xs text-green-700 mt-1 space-y-0.5">
                        <div>
                          <span className="text-green-600">Stages succeeded:</span>{" "}
                          <span className="font-mono">
                            {result.summary.stages_succeeded} / {result.summary.stages_run}
                          </span>
                        </div>
                        {result.summary.incident_short_id && (
                          <div>
                            <span className="text-green-600">Incident:</span>{" "}
                            <span className="font-mono">
                              {result.summary.incident_short_id}
                            </span>
                          </div>
                        )}
                        {result.summary.promoted_threat_id && (
                          <div>
                            <span className="text-green-600">New threat:</span>{" "}
                            <span className="font-mono">
                              {result.summary.promoted_threat_id.slice(0, 8)}…
                            </span>
                          </div>
                        )}
                      </div>

                      <div className="flex flex-wrap gap-2 mt-3">
                        <Link
                          to="/threats"
                          onClick={() => setOpen(false)}
                          className="inline-flex items-center gap-1 text-xs font-medium text-primary-700 hover:text-primary-900 bg-white px-2.5 py-1 rounded border border-primary-200"
                        >
                          <ExternalLink className="w-3 h-3" />
                          View threats
                        </Link>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={reset}
                          className="text-xs h-auto py-1 px-2.5"
                        >
                          <RotateCcw className="w-3 h-3 mr-1" />
                          Run again
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {runState === "failed" && (
              <Card className="border-red-200 bg-red-50/30">
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-red-900">
                        Pipeline failed
                      </div>
                      <div className="text-xs text-red-700 mt-1 break-words">
                        {error || "Unknown error"}
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={reset}
                        className="text-xs h-auto py-1 px-2.5 mt-3"
                      >
                        <RotateCcw className="w-3 h-3 mr-1" />
                        Try again
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}