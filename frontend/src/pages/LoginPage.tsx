import { useState } from "react";
import { useNavigate, useLocation, useSearchParams, Navigate, Link } from "react-router-dom";
import { motion } from "motion/react";
import { Loader2, AlertCircle } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { LogoMark } from "@/components/Logo";
import { signIn } from "@/lib/supabase";
import { useAuth } from "@/contexts/AuthContext";

export default function LoginPage() {
  const { session, loading: authLoading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const redirectTo =
    (location.state as { from?: string } | null)?.from ?? "/dashboard";

  // ?demo=1 (from the signup page's bypass button) pre-fills the demo creds.
  const [searchParams] = useSearchParams();
  const isDemo = searchParams.get("demo") === "1";

  const [email, setEmail] = useState("test@acme.example");
  const [password, setPassword] = useState(isDemo ? "ThreatBrain123!" : "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!authLoading && session) {
    return <Navigate to={redirectTo} replace />;
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await signIn(email, password);
      navigate(redirectTo, { replace: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-white flex flex-col relative overflow-hidden">
      <div className="lp-grid absolute inset-0 pointer-events-none" aria-hidden />

      {/* Top nav */}
      <header className="relative h-16 border-b border-border flex items-center justify-between px-6 sm:px-8">
        <Link to="/" className="flex items-center gap-2.5">
          <div className="w-7 h-7 text-foreground">
            <LogoMark className="w-full h-full" />
          </div>
          <span className="font-semibold text-[15px] tracking-[-0.02em]">ThreatBrain</span>
        </Link>
        <Link
          to="/"
          className="lp-underline text-[13px] text-muted-foreground hover:text-foreground transition-colors"
        >
          Back to home
        </Link>
      </header>

      {/* Form */}
      <div className="relative flex-1 flex items-center justify-center px-6 py-12">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: "easeOut" }}
          className="w-full max-w-[400px]"
        >
          <div className="mb-9">
            <div className="inline-flex items-center gap-2 font-mono text-[10.5px] uppercase tracking-[0.16em] text-muted-foreground mb-5">
              <span className="w-1.5 h-1.5 rounded-full bg-signal animate-pulse" />
              SOC operational
            </div>
            <h1 className="title-serif text-[34px] tracking-[-0.03em] text-foreground leading-[1.05]">
              Welcome{" "}
              <em className="font-serif italic font-medium text-signal">back.</em>
            </h1>
            <p className="text-[14px] text-muted-foreground mt-3 leading-[1.6]">
              Sign in to your ThreatBrain operations console.
            </p>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="email" className="text-[12.5px] font-medium text-foreground">
                Email
              </Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="h-10 text-[14px] bg-white"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password" className="text-[12.5px] font-medium text-foreground">
                Password
              </Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoFocus
                className="h-10 text-[14px] bg-white"
              />
            </div>

            {error && (
              <div className="flex items-start gap-2 p-3 rounded-md bg-severity-critical/5 border border-severity-critical/30 text-[13px] text-foreground">
                <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <Button
              type="submit"
              className="w-full h-10 bg-foreground text-background hover:bg-foreground/90 text-[14px] font-medium"
              disabled={loading}
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Signing in…
                </>
              ) : (
                "Sign in"
              )}
            </Button>
          </form>

          <div className="mt-5 text-[13px] text-muted-foreground">
            Don't have an account?{" "}
            <Link to="/signup" className="lp-underline text-foreground font-medium">
              Sign up →
            </Link>
          </div>

          {/* Demo creds */}
          <div className="mt-6 rounded-lg border border-border bg-muted/40 px-4 py-3.5">
            <div className="font-mono text-[12px] text-muted-foreground">
              <span className="text-signal">demo →</span>{" "}
              <span className="text-foreground">test@acme.example · ThreatBrain123!</span>
            </div>
          </div>

          <div className="mt-8 flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
            <span className="w-1.5 h-1.5 rounded-full bg-signal" />
            <span>all systems operational</span>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
