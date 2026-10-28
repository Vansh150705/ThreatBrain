import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, Circle, Loader2, X } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { Onboarding } from "@/lib/api/ops";
import { useUserStore } from "@/store/useUserStore";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const DISMISS_KEY = "threatbrain.onboarding.dismissed";

function dismissed(): boolean {
  try {
    return localStorage.getItem(DISMISS_KEY) === "1";
  } catch {
    return false;
  }
}

/** First-run checklist computed from the organization's real state, with a one-click demo campaign. */
export default function OnboardingCard() {
  const role = useUserStore((s) => s.profile?.role);
  const isAdmin = role === "owner" || role === "admin";
  const [data, setData] = useState<Onboarding | null>(null);
  const [hidden, setHidden] = useState(dismissed);
  const [busy, setBusy] = useState(false);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    if (hidden) return;
    let live = true;
    api.ops.getOnboarding().then((d) => live && setData(d)).catch(() => live && setData(null));
    return () => {
      live = false;
    };
  }, [hidden, tick]);

  if (hidden || !data) return null;
  const required = data.steps.filter((s) => s.id !== "executor");
  if (required.every((s) => s.done)) return null;

  async function demo() {
    setBusy(true);
    try {
      const r = await api.ops.loadDemo();
      toast.success(`Loaded ${r.accepted} synthetic events. Detections appear in a few seconds.`);
      setTimeout(reload, 4000);
      reload();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not load the demo campaign");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-label="Getting started" className="bg-card border border-border rounded-xl p-4 sm:p-5 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-[15px] font-semibold tracking-[-0.015em]">Getting started</h2>
          <p className="text-[12.5px] text-muted-foreground mt-0.5">
            {data.completed} of {data.total} steps done. This list is computed from your organization&apos;s real data.
          </p>
        </div>
        <button
          aria-label="Dismiss getting started"
          className="text-muted-foreground hover:text-foreground"
          onClick={() => {
            try {
              localStorage.setItem(DISMISS_KEY, "1");
            } catch {
              /* storage unavailable: dismiss for this session only */
            }
            setHidden(true);
          }}
        >
          <X className="w-4 h-4" />
        </button>
      </div>
      <ol className="space-y-1.5">
        {data.steps.map((s) => (
          <li key={s.id} className={cn("flex items-start gap-2 text-[13px]", data.next === s.id && "font-semibold")}>
            {s.done ? <CheckCircle2 className="w-4 h-4 mt-0.5 text-severity-low shrink-0" aria-label="done" /> : <Circle className="w-4 h-4 mt-0.5 text-muted-foreground shrink-0" aria-label="to do" />}
            <span>
              {s.title}
              {!s.done && <span className="block text-[11.5px] font-normal text-muted-foreground">{s.where}</span>}
            </span>
          </li>
        ))}
      </ol>
      {isAdmin && !data.demo_loaded && (
        <div className="pt-1">
          <Button size="sm" onClick={() => void demo()} disabled={busy}>
            {busy && <Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" />}
            Load a synthetic attack campaign
          </Button>
          <span className="text-[11.5px] text-muted-foreground ml-3">Documentation-range IPs only; runs through the real pipeline.</span>
        </div>
      )}
    </section>
  );
}
