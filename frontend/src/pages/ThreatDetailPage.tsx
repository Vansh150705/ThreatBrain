import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  AlertCircle,
  ShieldAlert,
  User,
  Clock,
  Target,
  Globe,
  Activity,
  ChevronRight,
  ExternalLink,
} from "lucide-react";

import { api, type ThreatDetail } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import SeverityBadge from "@/components/SeverityBadge";
import StatusBadge from "@/components/StatusBadge";

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatRelativeTime(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${Math.floor(diffHours / 24)}d ago`;
}

interface MetaItemProps {
  icon: React.ElementType;
  label: string;
  value: string | React.ReactNode;
}

function MetaItem({ icon: Icon, label, value }: MetaItemProps) {
  return (
    <div className="flex items-start gap-2">
      <Icon className="w-4 h-4 text-slate-400 mt-0.5 flex-shrink-0" />
      <div className="min-w-0">
        <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
          {label}
        </div>
        <div className="text-sm text-slate-900 mt-0.5">{value}</div>
      </div>
    </div>
  );
}

export default function ThreatDetailPage() {
  const { identifier } = useParams<{ identifier: string }>();
  const [threat, setThreat] = useState<ThreatDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!identifier) return;
    let cancelled = false;
    setLoading(true);
    setError(null);

    api.threats
      .getThreat(identifier)
      .then((res) => {
        if (!cancelled) setThreat(res);
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
  }, [identifier]);

  if (loading) {
    return (
      <div className="space-y-4">
        <Link
          to="/threats"
          className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to threats
        </Link>
        <Card>
          <CardContent className="p-8 text-center text-slate-500">
            Loading threat…
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error || !threat) {
    return (
      <div className="space-y-4">
        <Link
          to="/threats"
          className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to threats
        </Link>
        <Card className="border-severity-critical/30 bg-severity-critical/5">
          <CardContent className="p-6 flex items-center gap-3 text-severity-critical">
            <AlertCircle className="w-5 h-5" />
            <p className="text-sm font-medium">{error || "Threat not found"}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Back link */}
      <Link
        to="/threats"
        className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to threats
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between gap-6">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-2">
            <span className="font-mono text-xs text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
              {threat.short_id}
            </span>
            <SeverityBadge severity={threat.severity} />
            <StatusBadge status={threat.status} />
          </div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            {threat.title}
          </h1>
        </div>
      </div>

      {/* Metadata grid */}
      <Card>
        <CardContent className="p-5 grid grid-cols-2 md:grid-cols-4 gap-5">
          <MetaItem
            icon={Activity}
            label="Confidence"
            value={
              <span className="font-mono">{threat.confidence}%</span>
            }
          />
          <MetaItem
            icon={Target}
            label="Risk score"
            value={
              <span className="font-mono">{threat.risk_score ?? "—"}</span>
            }
          />
          <MetaItem
            icon={Clock}
            label="Detected"
            value={
              <span title={formatDate(threat.detected_at)}>
                {formatRelativeTime(threat.detected_at)}
              </span>
            }
          />
          <MetaItem
            icon={User}
            label="Assigned"
            value={
              threat.assigned_to ? (
                <span className="font-mono text-xs">
                  {threat.assigned_to.slice(0, 8)}…
                </span>
              ) : (
                <span className="text-slate-400">Unassigned</span>
              )
            }
          />
        </CardContent>
      </Card>

      {/* Main grid: content + sidebar */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* LEFT — main content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Description */}
          {threat.description && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Description</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-slate-700 leading-relaxed">
                  {threat.description}
                </p>
              </CardContent>
            </Card>
          )}

          {/* AI Analysis */}
          {threat.ai_analysis && Object.keys(threat.ai_analysis).length > 0 && (
            <Card className="border-primary-200 bg-gradient-to-br from-primary-50/30 to-transparent">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-primary-600" />
                  AI analysis
                </CardTitle>
              </CardHeader>
              <CardContent>
                <pre className="text-xs text-slate-700 bg-white rounded-md p-3 border border-slate-200 overflow-auto max-h-72 whitespace-pre-wrap">
                  {JSON.stringify(threat.ai_analysis, null, 2)}
                </pre>
              </CardContent>
            </Card>
          )}

          {/* MITRE ATT&CK */}
          {(threat.mitre_tactics.length > 0 ||
            threat.mitre_techniques.length > 0) && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">MITRE ATT&CK</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {threat.mitre_tactics.length > 0 && (
                  <div>
                    <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                      Tactics
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {threat.mitre_tactics.map((tactic) => (
                        <span
                          key={tactic}
                          className="font-mono text-xs px-2 py-1 bg-amber-50 text-amber-800 rounded border border-amber-200"
                        >
                          {tactic}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {threat.mitre_techniques.length > 0 && (
                  <div>
                    <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                      Techniques
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {threat.mitre_techniques.map((tech) => (
                        <span
                          key={tech}
                          className="font-mono text-xs px-2 py-1 bg-slate-100 text-slate-700 rounded border border-slate-200"
                        >
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Attack Chain */}
          {threat.attack_chain.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Attack chain</CardTitle>
              </CardHeader>
              <CardContent>
                <ol className="space-y-2">
                  {threat.attack_chain.map((step, idx) => (
                    <li
                      key={idx}
                      className="flex items-start gap-3 text-sm text-slate-700"
                    >
                      <span className="flex-shrink-0 w-5 h-5 rounded-full bg-primary-100 text-primary-700 text-xs font-semibold flex items-center justify-center mt-0.5">
                        {idx + 1}
                      </span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ol>
              </CardContent>
            </Card>
          )}

          {/* IOCs */}
          {(threat.source_ips.length > 0 ||
            threat.target_ips.length > 0 ||
            threat.affected_users.length > 0) && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Indicators of compromise</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="ips" className="w-full">
                  <TabsList>
                    <TabsTrigger value="ips">
                      Source IPs ({threat.source_ips.length})
                    </TabsTrigger>
                    <TabsTrigger value="targets">
                      Targets ({threat.target_ips.length})
                    </TabsTrigger>
                    <TabsTrigger value="users">
                      Users ({threat.affected_users.length})
                    </TabsTrigger>
                  </TabsList>

                  <TabsContent value="ips" className="mt-4">
                    {threat.source_ips.length === 0 ? (
                      <p className="text-sm text-slate-400">No source IPs.</p>
                    ) : (
                      <div className="space-y-1">
                        {threat.source_ips.map((ip) => (
                          <div
                            key={ip}
                            className="flex items-center gap-2 font-mono text-sm text-slate-700 bg-slate-50 rounded px-3 py-1.5"
                          >
                            <Globe className="w-3.5 h-3.5 text-slate-400" />
                            {ip}
                          </div>
                        ))}
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="targets" className="mt-4">
                    {threat.target_ips.length === 0 ? (
                      <p className="text-sm text-slate-400">No target IPs.</p>
                    ) : (
                      <div className="space-y-1">
                        {threat.target_ips.map((ip) => (
                          <div
                            key={ip}
                            className="flex items-center gap-2 font-mono text-sm text-slate-700 bg-slate-50 rounded px-3 py-1.5"
                          >
                            <Target className="w-3.5 h-3.5 text-slate-400" />
                            {ip}
                          </div>
                        ))}
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="users" className="mt-4">
                    {threat.affected_users.length === 0 ? (
                      <p className="text-sm text-slate-400">No affected users.</p>
                    ) : (
                      <div className="space-y-1">
                        {threat.affected_users.map((user) => (
                          <div
                            key={user}
                            className="flex items-center gap-2 text-sm text-slate-700 bg-slate-50 rounded px-3 py-1.5"
                          >
                            <User className="w-3.5 h-3.5 text-slate-400" />
                            {user}
                          </div>
                        ))}
                      </div>
                    )}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          )}
        </div>

        {/* RIGHT — sidebar */}
        <div className="space-y-6">
          {/* Tags */}
          {threat.tags.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Tags</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1.5">
                  {threat.tags.map((tag) => (
                    <span
                      key={tag}
                      className="text-xs px-2 py-1 bg-slate-100 text-slate-700 rounded"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Related */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Related</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {threat.incident_id ? (
                <Link
                  to={`/incidents/${threat.incident_id}`}
                  className="flex items-center justify-between p-2 -mx-2 rounded hover:bg-slate-50 transition-colors group"
                >
                  <div className="min-w-0">
                    <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                      Incident
                    </div>
                    <div className="text-sm font-mono text-primary-700 truncate">
                      {threat.incident_id.slice(0, 8)}…
                    </div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-slate-700" />
                </Link>
              ) : (
                <div className="text-sm text-slate-400">
                  No related incident
                </div>
              )}

              {threat.primary_asset_id && (
                <>
                  <Separator />
                  <div className="p-2 -mx-2">
                    <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                      Primary asset
                    </div>
                    <div className="text-sm font-mono text-slate-700 truncate">
                      {threat.primary_asset_id.slice(0, 8)}…
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {/* Timestamps */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Timeline</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-xs">
              <div>
                <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                  Detected
                </div>
                <div className="text-slate-700 mt-0.5">
                  {formatDate(threat.detected_at)}
                </div>
              </div>
              <div>
                <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                  Created
                </div>
                <div className="text-slate-700 mt-0.5">
                  {formatDate(threat.created_at)}
                </div>
              </div>
              <div>
                <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                  Updated
                </div>
                <div className="text-slate-700 mt-0.5">
                  {formatDate(threat.updated_at)}
                </div>
              </div>
              {threat.resolved_at && (
                <div>
                  <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                    Resolved
                  </div>
                  <div className="text-slate-700 mt-0.5">
                    {formatDate(threat.resolved_at)}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}