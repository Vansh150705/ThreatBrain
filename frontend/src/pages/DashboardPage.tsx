import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "motion/react";
import {
  Loader2,
  AlertCircle,
  CheckCircle2,
  ArrowRight,
  Activity,
  AlertTriangle,
} from "lucide-react";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api, type Agent } from "@/lib/api";
import { ApiError } from "@/lib/api";

export default function DashboardPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);

  useEffect(() => {
    setLoading(true);
    api.agents
      .listAgents()
      .then((res) => setAgents(res.items))
      .catch((err) => {
        if (err instanceof ApiError) {
          setError(`${err.status} — ${err.message}`);
        } else {
          setError(String(err));
        }
      })
      .finally(() => setLoading(false));
  }, []);

  const totalRuns = agents.reduce((sum, a) => sum + a.total_runs, 0);
  const activeAgents = agents.filter((a) => a.enabled).length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
          Dashboard
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Operational overview of your autonomous SOC.
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-primary-100 flex items-center justify-center">
                <Activity className="w-5 h-5 text-primary-700" />
              </div>
              <div>
                <div className="text-xs text-slate-500 uppercase tracking-wide font-semibold">
                  Active agents
                </div>
                <div className="text-2xl font-bold text-slate-900">
                  {loading ? "—" : `${activeAgents} / ${agents.length}`}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-severity-info/15 flex items-center justify-center">
                <CheckCircle2 className="w-5 h-5 text-severity-info" />
              </div>
              <div>
                <div className="text-xs text-slate-500 uppercase tracking-wide font-semibold">
                  Total runs
                </div>
                <div className="text-2xl font-bold text-slate-900">
                  {loading ? "—" : totalRuns}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-severity-high/15 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-severity-high" />
              </div>
              <div>
                <div className="text-xs text-slate-500 uppercase tracking-wide font-semibold">
                  Open incidents
                </div>
                <div className="text-2xl font-bold text-slate-900">—</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick agents list */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-base">Agents</CardTitle>
          <Link to="/agents">
            <Button variant="ghost" size="sm">
              View all
              <ArrowRight className="w-4 h-4 ml-1" />
            </Button>
          </Link>
        </CardHeader>
        <CardContent>
          {loading && (
            <div className="flex items-center gap-2 text-slate-500 text-sm">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading agents...
            </div>
          )}

          {error && (
            <div className="flex items-start gap-2 p-3 rounded-md bg-severity-critical/5 border border-severity-critical/30 text-sm text-slate-700">
              <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {!loading && !error && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="space-y-2"
            >
              {agents.slice(0, 4).map((agent, i) => (
                <motion.div
                  key={agent.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.04 }}
                >
                  <Link
                    to={`/agents/${agent.agent_key}`}
                    className="flex items-center justify-between p-3 rounded-lg hover:bg-slate-50 transition-colors"
                  >
                    <div>
                      <div className="font-medium text-slate-900 text-sm">
                        {agent.name}
                      </div>
                      <div className="text-xs text-slate-500 font-mono">
                        {agent.agent_key}
                      </div>
                    </div>
                    <Badge variant="outline" className="font-mono text-xs">
                      {agent.total_runs} runs
                    </Badge>
                  </Link>
                </motion.div>
              ))}
            </motion.div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}