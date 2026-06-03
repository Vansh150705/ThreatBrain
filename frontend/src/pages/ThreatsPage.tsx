import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ShieldAlert, Search, AlertCircle } from "lucide-react";

import { api, type ThreatListResponse } from "@/lib/api";
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

const SEVERITY_OPTIONS = [
  { value: "all", label: "All severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "info", label: "Info" },
];

const STATUS_OPTIONS = [
  { value: "all", label: "All statuses" },
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "contained", label: "Contained" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False positive" },
];

function formatRelativeTime(iso: string): string {
  const date = new Date(iso);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 30) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

export default function ThreatsPage() {
  const [data, setData] = useState<ThreatListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState("all");
  const [threatStatus, setThreatStatus] = useState("all");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    api.threats
      .listThreats({
        page: 1,
        page_size: 25,
        severity: severity === "all" ? undefined : severity,
        status: threatStatus === "all" ? undefined : threatStatus,
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
  }, [severity, threatStatus]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            Threats
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            All detected security threats across your organization.
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

      {/* Filters */}
      <div className="flex items-center gap-3">
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

        <Select value={threatStatus} onValueChange={setThreatStatus}>
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

        {(severity !== "all" || threatStatus !== "all") && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSeverity("all");
              setThreatStatus("all");
            }}
          >
            Clear filters
          </Button>
        )}
      </div>

      {/* Loading */}
      {loading && (
        <Card>
          <CardContent className="p-8 flex flex-col items-center text-slate-500">
            <Search className="w-8 h-8 mb-2 text-slate-400 animate-pulse" />
            <p className="text-sm">Loading threats…</p>
          </CardContent>
        </Card>
      )}

      {/* Error */}
      {error && !loading && (
        <Card className="border-severity-critical/30 bg-severity-critical/5">
          <CardContent className="p-6 flex items-center gap-3 text-severity-critical">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <p className="text-sm font-medium">{error}</p>
          </CardContent>
        </Card>
      )}

      {/* Empty */}
      {!loading && !error && data && data.items.length === 0 && (
        <Card className="border-dashed">
          <CardContent className="p-10 flex flex-col items-center text-center text-slate-500">
            <ShieldAlert className="w-10 h-10 mb-3 text-slate-400" />
            <p className="text-sm">No threats match your filters.</p>
          </CardContent>
        </Card>
      )}

      {/* Table */}
      {!loading && !error && data && data.items.length > 0 && (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Title</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Confidence</th>
                  <th className="px-4 py-3 text-right">Risk</th>
                  <th className="px-4 py-3">MITRE</th>
                  <th className="px-4 py-3">Detected</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {data.items.map((threat) => (
                  <tr
                    key={threat.id}
                    className="hover:bg-slate-50 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <Link
                        to={`/threats/${threat.short_id}`}
                        className="font-mono text-xs text-primary-700 hover:underline"
                      >
                        {threat.short_id}
                      </Link>
                    </td>
                    <td className="px-4 py-3 max-w-md">
                      <Link
                        to={`/threats/${threat.short_id}`}
                        className="font-medium text-slate-900 hover:text-primary-700 line-clamp-2"
                      >
                        {threat.title}
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={threat.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={threat.status} />
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-xs text-slate-700">
                      {threat.confidence}%
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-xs text-slate-700">
                      {threat.risk_score ?? "—"}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {threat.mitre_techniques.slice(0, 2).map((t) => (
                          <span
                            key={t}
                            className="font-mono text-[10px] px-1.5 py-0.5 bg-slate-100 text-slate-600 rounded"
                          >
                            {t}
                          </span>
                        ))}
                        {threat.mitre_techniques.length > 2 && (
                          <span className="text-[10px] text-slate-400">
                            +{threat.mitre_techniques.length - 2}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500 whitespace-nowrap">
                      {formatRelativeTime(threat.detected_at)}
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