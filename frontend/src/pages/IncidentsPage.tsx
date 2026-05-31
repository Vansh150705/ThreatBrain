import { ShieldAlert } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export default function IncidentsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
          Incidents
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Correlated attack stories grouped from raw threats.
        </p>
      </div>

      <Card className="border-dashed">
        <CardContent className="p-10 flex flex-col items-center text-center text-slate-500">
          <ShieldAlert className="w-10 h-10 mb-3 text-slate-400" />
          <p className="text-sm">Incidents page coming in Phase 6.</p>
        </CardContent>
      </Card>
    </div>
  );
}