import { Activity } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export default function RunsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
          Run history
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Every AI agent call, with full input, output, and timing.
        </p>
      </div>

      <Card className="border-dashed">
        <CardContent className="p-10 flex flex-col items-center text-center text-slate-500">
          <Activity className="w-10 h-10 mb-3 text-slate-400" />
          <p className="text-sm">Run history table coming next.</p>
        </CardContent>
      </Card>
    </div>
  );
}