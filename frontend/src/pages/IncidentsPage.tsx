import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ShieldAlert, Search, AlertCircle } from "lucide-react";

import { api, type IncidentListResponse } from "@/lib/api";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import SeverityBadge from "@/components/SeverityBadge";
import StatusBadge from "@/components/StatusBadge";
import PriorityBadge from "@/components/PriorityBadge";

const SEVERITY_OPTIONS = [
  { value: "all", label: "All severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const STATUS_OPTIONS = [
  { value: "all", label: "All statuses" },
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "contained", label: "Contained" },
  { value: "resolved", label: "Resolved" },
];

const PRIORITY_OPTIONS = [
  { value: "all", label: "All priorities" },
  { value: "p1", label: "P1 — Critical" },
  { value: "p2", label: "P2 — High" },
  { value: "p3", label: "P3 — Medium" },
  { value: "p4", label: "P4 — Low" },
];

function formatRelativeTime(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  const diffMs = Date.now() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 30) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

export default function IncidentsPage() {
  const [data, setData] = useState<IncidentListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState("all");
  const [incidentStatus, setIncidentStatus] = useState("all");
  const [priority, setPriority] = useState("all");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    api.incidents
      .listIncidents({
        page: 1,
        page_size: 25,
        severity: severity === "all" ? undefined : severity,
        status: incidentStatus === "all" ? undefined : incidentStatus,
        priority: priority === "all" ? undefined : priority,
      })
      .then((res) => {
        if (!cancelled) setData(res);
      })
      .catch((err) => {
        if (!cancelled) {
          const msg = err instanceof Error ? err.message : String(err);
          setError(msg);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [severity, incidentStatus, priority]);

  const filtersActive =
    severity !== "all" || incidentStatus !== "all" || priority !== "all";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            Incidents
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Grouped attack campaigns under investigation across your organization.
          </p>
        </div>
        <div className="text-sm text-slate-500">
          {data ? (
            <span>
              <span className="font-medium text-slate-900">{data.total}</span>{" "}
              total
            </span>
          ) : null}
        </div>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            {SEVERITY_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={incidentStatus} onValueChange={setIncidentStatus}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            {STATUS_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={priority} onValueChange={setPriority}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Priority" />
          </SelectTrigger>
          <SelectContent>
            {PRIORITY_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {filtersActive && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSeverity("all");
              setIncidentStatus("all");
              setPriority("all");
            }}
          >
            Clear filters
          </Button>
        )}
      </div>

      {loading && (
        <Card>
          <CardContent className="p-8 flex flex-col items-center text-slate-500">
            <Search className="w-8 h-8 mb-2 text-slate-400 animate-pulse" />
            <p className="text-sm">Loading incidents…</p>
          </CardContent>
        </Card>
      )}

      {error && !loading && (
        <Card className="border-severity-critical/30 bg-severity-critical/5">
          <CardContent className="p-6 flex items-center gap-3 text-severity-critical">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <p className="text-sm font-medium">{error}</p>
          </CardContent>
        </Card>
      )}

      {!loading && !error && data && data.items.length === 0 && (
        <Card className="border-dashed">
          <CardContent className="p-10 flex flex-col items-center text-center text-slate-500">
            <ShieldAlert className="w-10 h-10 mb-3 text-slate-400" />
            <p className="text-sm">No incidents match your filters.</p>
          </CardContent>
        </Card>
      )}

      {!loading && !error && data && data.items.length > 0 && (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Title</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Priority</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Threats</th>
                  <th className="px-4 py-3 text-right">Assets</th>
                  <th className="px-4 py-3">Kill chain</th>
                  <th className="px-4 py-3">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {data.items.map((incident) => (
                  <tr
                    key={incident.id}
                    className="hover:bg-slate-50 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <Link
                        to={`/incidents/${incident.short_id}`}
                        className="font-mono text-xs text-primary-700 hover:underline"
                      >
                        {incident.short_id}
                      </Link>
                    </td>
                    <td className="px-4 py-3 max-w-md">
                      <Link
                        to={`/incidents/${incident.short_id}`}
                        className="font-medium text-slate-900 hover:text-primary-700 line-clamp-2"
                      >
                        {incident.title}
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <PriorityBadge priority={incident.priority} />
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={incident.status} />
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-xs text-slate-700">
                      {incident.threat_count}
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-xs text-slate-700">
                      {incident.asset_count}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {incident.kill_chain.slice(0, 2).map((stage) => (
                          <span
                            key={stage}
                            className="text-[10px] px-1.5 py-0.5 bg-slate-100 text-slate-600 rounded font-mono"
                          >
                            {stage}
                          </span>
                        ))}
                        {incident.kill_chain.length > 2 && (
                          <span className="text-[10px] text-slate-400">
                            +{incident.kill_chain.length - 2}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500 whitespace-nowrap">
                      {formatRelativeTime(incident.last_seen_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}