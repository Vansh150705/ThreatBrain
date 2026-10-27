import { useCallback, useEffect, useState } from "react";
import { motion } from "motion/react";
import { AlertCircle, Check, Copy, KeyRound, Loader2, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { ApiKeyCreated, ApiKeyItem, IntegrationStatus } from "@/lib/api/admin";
import type { Member } from "@/lib/api/cases";
import { useUserStore } from "@/store/useUserStore";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

function Card({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <section className="bg-card border border-border rounded-xl p-4 sm:p-5 space-y-3">
      <div>
        <h2 className="text-[15px] font-semibold tracking-[-0.015em]">{title}</h2>
        {subtitle && <p className="text-[12.5px] text-muted-foreground mt-0.5">{subtitle}</p>}
      </div>
      {children}
    </section>
  );
}

const INTEGRATION_LABELS: Array<[keyof IntegrationStatus, string, string]> = [
  ["llm", "LLM (Groq)", "GROQ_API_KEY — without it the agents cannot run; rule-based degraded mode still classifies known attacks."],
  ["abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY — IP reputation."],
  ["virustotal", "VirusTotal", "VIRUSTOTAL_API_KEY — IP reputation."],
  ["otx", "AlienVault OTX", "OTX_API_KEY — pulse-based IP reputation."],
  ["discord_notifications", "Discord alerts", "DISCORD_WEBHOOK_URL — notifies on new high/critical incidents."],
  ["hunt_scheduler", "Scheduled hunting", "HUNT_INTERVAL_MINUTES > 0 — proactive Hunt agent sweep."],
  ["rate_limiting", "Rate limiting", "RATE_LIMIT_ENABLED"],
  ["public_signup", "Public signup", "ALLOW_PUBLIC_SIGNUP"],
];

function Integrations() {
  const [s, setS] = useState<IntegrationStatus | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    api.admin.getIntegrations().then(setS).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);
  return (
    <Card title="Integrations" subtitle="Configured on the backend via environment variables. Secrets are never shown.">
      {err && <p className="text-[12.5px] text-severity-critical">{err}</p>}
      {!s && !err && <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />}
      {s && (
        <ul className="divide-y divide-border">
          {INTEGRATION_LABELS.map(([key, label, help]) => (
            <li key={key} className="py-2 flex items-start gap-3">
              <span
                className={cn("mt-1.5 w-2 h-2 rounded-full shrink-0", s[key] ? "bg-severity-low" : "bg-muted-foreground/40")}
                aria-hidden
              />
              <div className="min-w-0">
                <div className="text-[13px] font-medium">
                  {label} <span className="sr-only">{s[key] ? "enabled" : "not configured"}</span>
                  <span className="ml-2 font-mono text-[10px] uppercase text-muted-foreground">{s[key] ? "on" : "off"}</span>
                </div>
                <div className="text-[11.5px] text-muted-foreground">{help}</div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function ApiKeys() {
  const [keys, setKeys] = useState<ApiKeyItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<Array<"ingest" | "executor">>(["ingest"]);
  const [days, setDays] = useState("");
  const [busy, setBusy] = useState(false);
  const [fresh, setFresh] = useState<ApiKeyCreated | null>(null);
  const [copied, setCopied] = useState(false);

  const [reload, setReload] = useState(0);
  const load = useCallback(() => setReload((n) => n + 1), []);
  useEffect(() => {
    let cancelled = false;
    api.admin
      .listApiKeys()
      .then((k) => {
        if (cancelled) return;
        setKeys(k);
        setError(null);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [reload]);

  async function create() {
    setBusy(true);
    try {
      const created = await api.admin.createApiKey({
        name: name.trim(),
        scopes,
        expires_in_days: days ? Number(days) : undefined,
      });
      setFresh(created);
      setName("");
      setDays("");
      setCopied(false);
      load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not create key");
    } finally {
      setBusy(false);
    }
  }

  async function revoke(k: ApiKeyItem) {
    if (!window.confirm(`Revoke “${k.name}”? Anything using it stops working immediately.`)) return;
    try {
      await api.admin.revokeApiKey(k.id);
      toast.success("Key revoked");
      load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not revoke key");
    }
  }

  function toggle(scope: "ingest" | "executor") {
    setScopes((cur) => (cur.includes(scope) ? cur.filter((s) => s !== scope) : [...cur, scope]));
  }

  return (
    <Card
      title="API keys"
      subtitle="Credentials for collectors (ingest), the response executor (executor) and SIEM webhooks. Keys cannot read your data or approve actions."
    >
      {fresh && (
        <div role="status" className="p-3 rounded-lg border border-severity-medium/40 bg-severity-medium/8 space-y-2">
          <div className="text-[12.5px] font-semibold">Copy your new key now — it will not be shown again.</div>
          <div className="flex items-center gap-2">
            <code className="flex-1 font-mono text-[12px] bg-background border border-border rounded px-2 py-1.5 break-all">{fresh.api_key}</code>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                void navigator.clipboard.writeText(fresh.api_key).then(() => setCopied(true));
              }}
            >
              {copied ? <Check className="w-3.5 h-3.5 mr-1" /> : <Copy className="w-3.5 h-3.5 mr-1" />}
              {copied ? "Copied" : "Copy"}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setFresh(null)}>
              Done
            </Button>
          </div>
        </div>
      )}

      <form
        className="flex flex-col sm:flex-row sm:items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          void create();
        }}
      >
        <label className="flex-1 space-y-1">
          <span className="text-[11px] text-muted-foreground">Name</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={100}
            required
            placeholder="e.g. kali-lab collector"
            className="w-full rounded-lg border border-input bg-transparent px-3 h-9 text-[13px] outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
          />
        </label>
        <fieldset className="space-y-1">
          <legend className="text-[11px] text-muted-foreground">Scopes</legend>
          <div className="flex gap-3 h-9 items-center">
            {(["ingest", "executor"] as const).map((s) => (
              <label key={s} className="inline-flex items-center gap-1.5 text-[12.5px]">
                <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggle(s)} /> {s}
              </label>
            ))}
          </div>
        </fieldset>
        <label className="space-y-1 sm:w-28">
          <span className="text-[11px] text-muted-foreground">Expires (days)</span>
          <input
            type="number"
            min={1}
            max={730}
            value={days}
            onChange={(e) => setDays(e.target.value)}
            placeholder="never"
            className="w-full rounded-lg border border-input bg-transparent px-3 h-9 text-[13px] outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
          />
        </label>
        <Button type="submit" disabled={busy || !name.trim() || scopes.length === 0}>
          {busy ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <KeyRound className="w-4 h-4 mr-2" />}
          Create key
        </Button>
      </form>

      {error && (
        <div className="flex items-start gap-2 text-[12.5px] text-severity-critical">
          <AlertCircle className="w-4 h-4 mt-0.5" /> {error}
        </div>
      )}
      {keys && keys.length === 0 && <p className="text-[12.5px] text-muted-foreground italic">No API keys yet.</p>}
      {keys && keys.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-[12.5px]">
            <thead className="text-left text-muted-foreground">
              <tr>
                <th className="py-1.5 pr-3 font-medium">Name</th>
                <th className="py-1.5 pr-3 font-medium">Key</th>
                <th className="py-1.5 pr-3 font-medium">Scopes</th>
                <th className="py-1.5 pr-3 font-medium">Last used</th>
                <th className="py-1.5 pr-3 font-medium">Status</th>
                <th />
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {keys.map((k) => {
                const expired = k.expires_at && new Date(k.expires_at) < new Date();
                const state = k.revoked_at ? "revoked" : expired ? "expired" : "active";
                return (
                  <tr key={k.id}>
                    <td className="py-2 pr-3">{k.name}</td>
                    <td className="py-2 pr-3 font-mono text-[11px]">{k.key_prefix}…</td>
                    <td className="py-2 pr-3 font-mono text-[11px]">{k.scopes.join(", ")}</td>
                    <td className="py-2 pr-3 text-muted-foreground">{k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "never"}</td>
                    <td className="py-2 pr-3">
                      <span className={cn("font-mono text-[10px] uppercase", state === "active" ? "text-severity-low" : "text-muted-foreground")}>{state}</span>
                    </td>
                    <td className="py-2 text-right">
                      {state === "active" && (
                        <Button size="sm" variant="ghost" onClick={() => void revoke(k)} aria-label={`Revoke ${k.name}`}>
                          <Trash2 className="w-3.5 h-3.5" />
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function Webhooks() {
  const base = API_BASE.replace(/\/$/, "");
  return (
    <Card title="Connect telemetry" subtitle="Send events from a SIEM or any tool. Authenticate with an ingest API key in the X-API-Key header.">
      <pre className="font-mono text-[11.5px] bg-muted/50 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">{`# Wazuh / Elastic (ECS) / Splunk / CloudTrail / CEF / generic
curl -X POST ${base}/ingest/webhook/wazuh \\
  -H "X-API-Key: tbk_..." -H "Content-Type: application/json" \\
  -d @alert.json                      # 202 Accepted; track under Pipelines

# a single normalized event, waiting for the verdict
curl -X POST ${base}/ingest/event -H "X-API-Key: tbk_..." \\
  -H "Content-Type: application/json" -d '{"event": {"title": "...", "source_ip": "198.51.100.7"}}'`}</pre>
      <p className="text-[12px] text-muted-foreground">
        Formats: <span className="font-mono">wazuh, ecs, cef, cloudtrail, splunk, generic</span> · up to 50 events per request.
      </p>
    </Card>
  );
}

function Members() {
  const [members, setMembers] = useState<Member[] | null>(null);
  useEffect(() => {
    api.cases.listMembers().then(setMembers).catch(() => setMembers([]));
  }, []);
  return (
    <Card title="Team" subtitle="Members of your organization and their roles.">
      {!members ? (
        <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
      ) : (
        <ul className="divide-y divide-border">
          {members.map((m) => (
            <li key={m.id} className="py-2 flex items-center justify-between text-[13px]">
              <span>{m.full_name || m.email}</span>
              <span className="font-mono text-[10.5px] uppercase text-muted-foreground">{m.role}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export default function SettingsPage() {
  const role = useUserStore((s) => s.profile?.role);
  const isAdmin = role === "owner" || role === "admin";
  const isAnalyst = isAdmin || role === "analyst";
  return (
    <div className="space-y-6 pb-12 max-w-4xl">
      <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <h1 className="title-serif text-[24px] sm:text-[30px] tracking-[-0.03em]">Settings</h1>
        <p className="text-[13.5px] text-muted-foreground mt-1">Integrations, machine credentials and your team.</p>
      </motion.div>
      <Integrations />
      {isAdmin ? (
        <ApiKeys />
      ) : (
        <Card title="API keys">
          <p className="text-[12.5px] text-muted-foreground">Only admins and owners can manage API keys.</p>
        </Card>
      )}
      {isAnalyst && <Webhooks />}
      {isAnalyst && <Members />}
    </div>
  );
}
