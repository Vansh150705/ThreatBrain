import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { motion } from "motion/react";
import { Loader2, AlertCircle } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, type Agent } from "@/lib/api";
import { ApiError } from "@/lib/api";

export default function AgentsPage() {
  const { agentKey } = useParams<{ agentKey?: string }>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);

  useEffect(() => {
    setLoading(true);
    setError(null);

    const promise = agentKey
      ? api.agents.getAgent(agentKey).then((a) => [a])
      : api.agents.listAgents().then((res) => res.items);

    promise
      .then(setAgents)
      .catch((err) => {
        if (err instanceof ApiError) setError(`${err.status} — ${err.message}`);
        else setError(String(err));
      })
      .finally(() => setLoading(false));
  }, [agentKey]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
          {agentKey ? `Agent · ${agentKey}` : "Agents"}
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          {agentKey
            ? "Single agent details and run history."
            : "All 7 specialized AI agents that make up the SOC pipeline."}
        </p>
      </div>

      {loading && (
        <div className="flex items-center gap-2 text-slate-500 text-sm">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading...
        </div>
      )}

      {error && (
        <Card className="border-severity-critical/40 bg-severity-critical/5">
          <CardContent className="p-4 flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-severity-critical flex-shrink-0 mt-0.5" />
            <div className="text-sm text-slate-700">{error}</div>
          </CardContent>
        </Card>
      )}

      {!loading && !error && (
        <div className="space-y-2">
          {agents.map((agent, i) => (
            <motion.div
              key={agent.id}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.04 }}
            >
              <Card>
                <CardContent className="p-5">
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <div className="font-semibold text-slate-900">
                        {agent.name}
                      </div>
                      <div className="text-xs text-slate-500 font-mono mt-0.5">
                        {agent.agent_key} · {agent.model}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="font-mono text-xs">
                        {agent.total_runs} runs
                      </Badge>
                      <Badge
                        className={
                          agent.enabled
                            ? "bg-severity-low text-white"
                            : "bg-slate-300 text-slate-700"
                        }
                      >
                        {agent.enabled ? "active" : "disabled"}
                      </Badge>
                    </div>
                  </div>
                  {agent.description && (
                    <p className="text-sm text-slate-600 leading-relaxed mt-2">
                      {agent.description}
                    </p>
                  )}
                  <div className="grid grid-cols-3 gap-4 mt-4 pt-4 border-t border-slate-200 text-xs">
                    <div>
                      <div className="text-slate-500 uppercase font-semibold tracking-wide">
                        Successful
                      </div>
                      <div className="text-slate-900 font-semibold text-sm mt-1">
                        {agent.successful_runs}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500 uppercase font-semibold tracking-wide">
                        Failed
                      </div>
                      <div className="text-slate-900 font-semibold text-sm mt-1">
                        {agent.failed_runs}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500 uppercase font-semibold tracking-wide">
                        Avg latency
                      </div>
                      <div className="text-slate-900 font-semibold text-sm mt-1">
                        {agent.avg_latency_ms
                          ? `${agent.avg_latency_ms}ms`
                          : "—"}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}