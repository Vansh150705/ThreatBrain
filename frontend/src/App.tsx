import { useState } from "react";
import { motion } from "motion/react";
import { Shield, Loader2, AlertCircle, CheckCircle2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, setToken, type Agent } from "@/lib/api";
import { ApiError } from "@/lib/api";

function App() {
  const [token, setTokenInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);

  const handleFetch = async () => {
    setError(null);
    setLoading(true);
    try {
      if (token) setToken(token);
      const response = await api.agents.listAgents();
      setAgents(response.items);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`${err.status} — ${err.message}`);
      } else {
        setError(String(err));
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <div className="max-w-5xl mx-auto px-8 pt-16 pb-8">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="flex items-center gap-4 mb-2"
        >
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center shadow-lg shadow-primary-500/30">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-slate-900 tracking-tight">
              ThreatBrain
            </h1>
            <p className="text-sm text-slate-500">
              Step 5.5 · API client + JWT injection
            </p>
          </div>
        </motion.div>

        <div className="mt-10 grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Auth panel */}
          <Card className="lg:col-span-1 h-fit">
            <CardHeader>
              <CardTitle className="text-base">Auth token</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="token">Paste a JWT (Jane's token)</Label>
                <Input
                  id="token"
                  type="text"
                  placeholder="eyJhbGciOi..."
                  value={token}
                  onChange={(e) => setTokenInput(e.target.value)}
                  className="font-mono text-xs"
                />
              </div>
              <Button
                onClick={handleFetch}
                disabled={loading}
                className="w-full"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Fetching...
                  </>
                ) : (
                  "Fetch agents"
                )}
              </Button>
              <p className="text-xs text-slate-500 leading-relaxed">
                Run{" "}
                <code className="font-mono bg-slate-100 px-1 rounded">
                  python scripts/make_jane_token.py
                </code>{" "}
                in the backend to get a token, then paste it here.
              </p>
            </CardContent>
          </Card>

          {/* Results panel */}
          <div className="lg:col-span-2 space-y-4">
            {error && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <Card className="border-severity-critical/40 bg-severity-critical/5">
                  <CardContent className="p-4 flex items-start gap-3">
                    <AlertCircle className="w-5 h-5 text-severity-critical flex-shrink-0 mt-0.5" />
                    <div className="text-sm text-slate-700">
                      <strong>API error:</strong> {error}
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            )}

            {agents.length > 0 && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-2"
              >
                <div className="flex items-center gap-2 text-sm text-slate-600 mb-3">
                  <CheckCircle2 className="w-4 h-4 text-severity-low" />
                  Fetched {agents.length} agents from{" "}
                  <code className="font-mono bg-slate-100 px-1 rounded text-xs">
                    GET /agents
                  </code>
                </div>
                {agents.map((agent, i) => (
                  <motion.div
                    key={agent.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.04 }}
                  >
                    <Card>
                      <CardContent className="p-4 flex items-center justify-between">
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
                      </CardContent>
                    </Card>
                  </motion.div>
                ))}
              </motion.div>
            )}

            {!error && agents.length === 0 && (
              <Card className="border-dashed">
                <CardContent className="p-8 text-center text-slate-500 text-sm">
                  Paste your JWT and click "Fetch agents" to test the API
                  client.
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;