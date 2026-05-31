import { useEffect, useState } from "react";
import { motion } from "motion/react";
import {
  Shield,
  Loader2,
  AlertCircle,
  LogOut,
  CheckCircle2,
} from "lucide-react";
import type { Session } from "@supabase/supabase-js";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, type Agent } from "@/lib/api";
import { ApiError } from "@/lib/api";
import { supabase, signIn, signOut, getSession } from "@/lib/supabase";

function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [bootstrapping, setBootstrapping] = useState(true);

  // On mount: check for an existing session
  useEffect(() => {
    getSession()
      .then((s) => setSession(s))
      .catch(() => setSession(null))
      .finally(() => setBootstrapping(false));

    const { data: sub } = supabase.auth.onAuthStateChange((_evt, s) => {
      setSession(s);
    });
    return () => sub.subscription.unsubscribe();
  }, []);

  if (bootstrapping) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
      </div>
    );
  }

  return session ? <Dashboard /> : <LoginPage />;
}

// Login page
function LoginPage() {
  const [email, setEmail] = useState("jane.morrison@acme.example");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await signIn(email, password);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="w-full max-w-md"
      >
        <div className="flex items-center gap-3 mb-8 justify-center">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center shadow-lg shadow-primary-500/30">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
              ThreatBrain
            </h1>
            <p className="text-xs text-slate-500">The Neural SOC</p>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Sign in</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleLogin} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoFocus
                />
              </div>

              {error && (
                <div className="flex items-start gap-2 p-3 rounded-md bg-severity-critical/5 border border-severity-critical/30 text-sm text-slate-700">
                  <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Signing in...
                  </>
                ) : (
                  "Sign in"
                )}
              </Button>
            </form>
          </CardContent>
        </Card>

        <p className="text-center text-xs text-slate-400 mt-6 font-mono">
          step 5.6 ✓ supabase auth
        </p>
      </motion.div>
    </div>
  );
}

// Dashboard — shown when authenticated
function Dashboard() {
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

  return (
    <div className="min-h-screen bg-slate-50">
      <div className="max-w-5xl mx-auto px-8 pt-12 pb-8">
        {/* Top bar */}
        <div className="flex items-center justify-between mb-10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center shadow-lg shadow-primary-500/30">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-900 tracking-tight">
                ThreatBrain
              </h1>
              <p className="text-xs text-slate-500">
                Signed in as jane.morrison@acme.example
              </p>
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={() => signOut()}>
            <LogOut className="w-4 h-4 mr-2" />
            Sign out
          </Button>
        </div>

        {/* Body */}
        {loading && (
          <div className="flex items-center gap-2 text-slate-500">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading agents...
          </div>
        )}

        {error && (
          <Card className="border-severity-critical/40 bg-severity-critical/5">
            <CardContent className="p-4 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-severity-critical flex-shrink-0 mt-0.5" />
              <div className="text-sm text-slate-700">
                <strong>API error:</strong> {error}
              </div>
            </CardContent>
          </Card>
        )}

        {!loading && !error && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
            <div className="flex items-center gap-2 text-sm text-slate-600 mb-4">
              <CheckCircle2 className="w-4 h-4 text-severity-low" />
              {agents.length} agents · live data from your FastAPI backend
            </div>
            <div className="space-y-2">
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
                        <Badge
                          variant="outline"
                          className="font-mono text-xs"
                        >
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
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}

export default App;