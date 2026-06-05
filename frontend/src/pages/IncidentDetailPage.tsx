import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  AlertCircle,
  Brain,
  Users,
  Target,
  Clock,
  ChevronRight,
  Activity,
  PlayCircle,
  ShieldAlert,
} from "lucide-react";

import { api, type IncidentDetail, type IncidentThreatItem } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import SeverityBadge from "@/components/SeverityBadge";
import StatusBadge from "@/components/StatusBadge";
import PriorityBadge from "@/components/PriorityBadge";

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatRelativeTime(iso: string | null): string {
  if (!iso) return "—";
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

// Convert any jsonb timeline shape to a normalized array
function normalizeTimeline(
  timeline: IncidentDetail["timeline"]
): Array<{ ts?: string; phase?: string; event?: string; [k: string]: unknown }> {
  if (Array.isArray(timeline)) return timeline as Array<Record<string, unknown>>;
  if (timeline && typeof timeline === "object") {
    const arr = (timeline as Record<string, unknown>).events;
    if (Array.isArray(arr)) return arr as Array<Record<string, unknown>>;
  }
  return [];
}

// Convert playbook_runs to a normalized array
function normalizePlaybookRuns(
  pr: IncidentDetail["playbook_runs"]
): Array<Record<string, unknown>> {
  if (Array.isArray(pr)) return pr as Array<Record<string, unknown>>;
  if (pr && typeof pr === "object") {
    const arr = (pr as Record<string, unknown>).runs;
    if (Array.isArray(arr)) return arr as Array<Record<string, unknown>>;
  }
  return [];
}

export default function IncidentDetailPage() {
  const { identifier } = useParams<{ identifier: string }>();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [threats, setThreats] = useState<IncidentThreatItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!identifier) return;
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.incidents.getIncident(identifier),
      api.incidents.getIncidentThreats(identifier),
    ])
      .then(([inc, thr]) => {
        if (cancelled) return;
        setIncident(inc);
        setThreats(thr.items);
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
          to="/incidents"
          className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to incidents
        </Link>
        <Card>
          <CardContent className="p-8 text-center text-slate-500">
            Loading incident…
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="space-y-4">
        <Link
          to="/incidents"
          className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to incidents
        </Link>
        <Card className="border-severity-critical/30 bg-severity-critical/5">
          <CardContent className="p-6 flex items-center gap-3 text-severity-critical">
            <AlertCircle className="w-5 h-5" />
            <p className="text-sm font-medium">{error || "Incident not found"}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const timelineEvents = normalizeTimeline(incident.timeline);
  const playbookRuns = normalizePlaybookRuns(incident.playbook_runs);
  const hasAiSummary =
    incident.ai_summary && Object.keys(incident.ai_summary).length > 0;
  const hasAttribution =
    incident.attribution && Object.keys(incident.attribution).length > 0;

  return (
    <div className="space-y-6">
      {/* Back link */}
      <Link
        to="/incidents"
        className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to incidents
      </Link>

      {/* Header */}
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <span className="font-mono text-xs text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
            {incident.short_id}
          </span>
          <SeverityBadge severity={incident.severity} />
          <PriorityBadge priority={incident.priority} />
          <StatusBadge status={incident.status} />
        </div>
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
          {incident.title}
        </h1>
      </div>

      {/* Metadata grid */}
      <Card>
        <CardContent className="p-5 grid grid-cols-2 md:grid-cols-4 gap-5">
          <MetaItem
            icon={Activity}
            label="Confidence"
            value={<span className="font-mono">{incident.confidence}%</span>}
          />
          <MetaItem
            icon={Target}
            label="Risk score"
            value={<span className="font-mono">{incident.risk_score ?? "—"}</span>}
          />
          <MetaItem
            icon={ShieldAlert}
            label="Threats"
            value={<span className="font-mono">{incident.threat_count}</span>}
          />
          <MetaItem
            icon={Users}
            label="Affected assets"
            value={<span className="font-mono">{incident.asset_count}</span>}
          />
        </CardContent>
      </Card>

      {/* Main grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* LEFT — main content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Description */}
          {incident.description && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Description</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-slate-700 leading-relaxed">
                  {incident.description}
                </p>
              </CardContent>
            </Card>
          )}

          {/* AI Summary */}
          {hasAiSummary && (
            <Card className="border-primary-200 bg-gradient-to-br from-primary-50/30 to-transparent">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Brain className="w-4 h-4 text-primary-600" />
                  AI summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <pre className="text-xs text-slate-700 bg-white rounded-md p-3 border border-slate-200 overflow-auto max-h-72 whitespace-pre-wrap">
                  {JSON.stringify(incident.ai_summary, null, 2)}
                </pre>
              </CardContent>
            </Card>
          )}

          {/* Kill Chain visualizer */}
          {incident.kill_chain.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Kill chain</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap items-center gap-1.5">
                  {incident.kill_chain.map((stage, idx) => (
                    <div key={`${stage}-${idx}`} className="flex items-center gap-1.5">
                      <span className="font-mono text-xs px-2.5 py-1 bg-amber-50 text-amber-800 rounded border border-amber-200">
                        {stage}
                      </span>
                      {idx < incident.kill_chain.length - 1 && (
                        <ChevronRight className="w-3.5 h-3.5 text-slate-300" />
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* MITRE ATT&CK */}
          {(incident.mitre_tactics.length > 0 ||
            incident.mitre_techniques.length > 0) && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">MITRE ATT&CK</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {incident.mitre_tactics.length > 0 && (
                  <div>
                    <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                      Tactics
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {incident.mitre_tactics.map((t) => (
                        <span
                          key={t}
                          className="font-mono text-xs px-2 py-1 bg-amber-50 text-amber-800 rounded border border-amber-200"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {incident.mitre_techniques.length > 0 && (
                  <div>
                    <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                      Techniques
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {incident.mitre_techniques.map((t) => (
                        <span
                          key={t}
                          className="font-mono text-xs px-2 py-1 bg-slate-100 text-slate-700 rounded border border-slate-200"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Threats under this incident */}
          {threats.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-slate-600" />
                  Threats in this incident
                  <span className="ml-1 text-xs text-slate-500 font-normal">
                    {threats.length}
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <div className="divide-y divide-slate-100">
                  {threats.map((threat) => (
                    <Link
                      key={threat.id}
                      to={`/threats/${threat.short_id}`}
                      className="flex items-center justify-between gap-3 px-4 py-3 hover:bg-slate-50 transition-colors group"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-mono text-xs text-primary-700">
                            {threat.short_id}
                          </span>
                          <SeverityBadge severity={threat.severity} />
                          <StatusBadge status={threat.status} />
                        </div>
                        <div className="text-sm font-medium text-slate-900 group-hover:text-primary-700 line-clamp-1">
                          {threat.title}
                        </div>
                      </div>
                      <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-slate-700 flex-shrink-0" />
                    </Link>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Timeline + Playbook tabs */}
          {(timelineEvents.length > 0 || playbookRuns.length > 0) && (
            <Card>
              <CardContent className="p-5">
                <Tabs defaultValue={timelineEvents.length > 0 ? "timeline" : "playbook"}>
                  <TabsList>
                    <TabsTrigger value="timeline">
                      Timeline ({timelineEvents.length})
                    </TabsTrigger>
                    <TabsTrigger value="playbook">
                      Playbook runs ({playbookRuns.length})
                    </TabsTrigger>
                  </TabsList>

                  <TabsContent value="timeline" className="mt-4">
                    {timelineEvents.length === 0 ? (
                      <p className="text-sm text-slate-400">No timeline events.</p>
                    ) : (
                      <ol className="relative border-l border-slate-200 ml-3 space-y-4">
                        {timelineEvents.map((evt, idx) => {
                          const ts =
                            (evt.ts as string) ||
                            (evt.timestamp as string) ||
                            "";
                          const event =
                            (evt.event as string) ||
                            (evt.action as string) ||
                            (evt.description as string) ||
                            JSON.stringify(evt);
                          const phase = evt.phase as string | undefined;
                          return (
                            <li key={idx} className="ml-4">
                              <div className="absolute -left-1.5 w-3 h-3 bg-primary-500 rounded-full border-2 border-white" />
                              {ts && (
                                <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                                  {formatDate(ts)}
                                </div>
                              )}
                              <div className="text-sm text-slate-700 mt-0.5">
                                {event}
                              </div>
                              {phase && (
                                <div className="text-xs text-slate-500 mt-0.5 font-mono">
                                  {phase}
                                </div>
                              )}
                            </li>
                          );
                        })}
                      </ol>
                    )}
                  </TabsContent>

                  <TabsContent value="playbook" className="mt-4">
                    {playbookRuns.length === 0 ? (
                      <p className="text-sm text-slate-400">
                        No playbook actions recorded yet.
                      </p>
                    ) : (
                      <div className="space-y-2">
                        {playbookRuns.map((run, idx) => (
                          <div
                            key={idx}
                            className="flex items-start gap-3 p-3 bg-slate-50 rounded-md"
                          >
                            <PlayCircle className="w-4 h-4 text-slate-500 mt-0.5 flex-shrink-0" />
                            <div className="min-w-0 flex-1 text-sm">
                              <pre className="text-xs text-slate-700 whitespace-pre-wrap break-words">
                                {JSON.stringify(run, null, 2)}
                              </pre>
                            </div>
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
          {incident.tags && incident.tags.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Tags</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1.5">
                  {incident.tags.map((tag) => (
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

          {/* Attribution */}
          {hasAttribution && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Attribution</CardTitle>
              </CardHeader>
              <CardContent>
                <pre className="text-xs text-slate-700 bg-slate-50 rounded p-2 overflow-auto max-h-48 whitespace-pre-wrap">
                  {JSON.stringify(incident.attribution, null, 2)}
                </pre>
              </CardContent>
            </Card>
          )}

          {/* Source IPs */}
          {incident.source_ips.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Source IPs</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1">
                  {incident.source_ips.map((ip) => (
                    <div
                      key={ip}
                      className="font-mono text-xs text-slate-700 bg-slate-50 rounded px-2 py-1"
                    >
                      {ip}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Lifecycle */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Clock className="w-4 h-4 text-slate-500" />
                Lifecycle
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-xs">
              <div>
                <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                  First seen
                </div>
                <div className="text-slate-700 mt-0.5">
                  {formatDate(incident.first_seen_at)}
                </div>
              </div>
              <Separator />
              <div>
                <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                  Last seen
                </div>
                <div className="text-slate-700 mt-0.5">
                  {formatDate(incident.last_seen_at)}
                  <span className="text-slate-400 ml-1">
                    ({formatRelativeTime(incident.last_seen_at)})
                  </span>
                </div>
              </div>
              {incident.contained_at && (
                <>
                  <Separator />
                  <div>
                    <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                      Contained
                    </div>
                    <div className="text-slate-700 mt-0.5">
                      {formatDate(incident.contained_at)}
                    </div>
                  </div>
                </>
              )}
              {incident.resolved_at && (
                <>
                  <Separator />
                  <div>
                    <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                      Resolved
                    </div>
                    <div className="text-slate-700 mt-0.5">
                      {formatDate(incident.resolved_at)}
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}