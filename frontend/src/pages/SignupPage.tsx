import { useState } from "react";
import { useNavigate, Navigate, Link } from "react-router-dom";
import { motion } from "motion/react";
import { Loader2, AlertCircle, Check } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { LogoMark } from "@/components/Logo";
import { http } from "@/lib/api";
import { setToken } from "@/lib/api";
import { supabase } from "@/lib/supabase";
import { useAuth } from "@/contexts/AuthContext";

interface SignupResponse {
  access_token: string;
  refresh_token: string;
  user: {
    id: string;
    email: string | null;
    full_name: string | null;
    organization_id: string | null;
  };
}

export default function SignupPage() {
  const { session, loading: authLoading } = useAuth();
  const navigate = useNavigate();

  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!authLoading && session) {
    return <Navigate to="/dashboard" replace />;
  }

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Local validation before hitting the API
    if (!fullName.trim()) {
      setError("Please enter your name.");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError("Please enter a valid email address.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }

    setLoading(true);
    try {
      const res = await http.post<SignupResponse>("/auth/signup", {
        email,
        password,
        full_name: fullName.trim(),
      });
      const { access_token, refresh_token } = res.data;

      // set the session so the rest of the app picks up the login
      setToken(access_token);
      await supabase.auth.setSession({ access_token, refresh_token });
      await supabase.realtime.setAuth(access_token);

      navigate("/dashboard", { replace: true });
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
              Create your{" "}
              <em className="font-serif italic font-medium text-signal">workspace.</em>
            </h1>
            <p className="text-[14px] text-muted-foreground mt-3 leading-[1.6]">
              Get your own isolated SOC instance in 8 seconds. No email
              confirmation required.
            </p>

            <ul className="mt-5 space-y-2">
              {[
                "A private workspace where your data is yours alone",
                "Seeded threats, an incident, and a live attack map",
                "Six AI agents pre-configured and ready to run",
                "Instant access with no confirmation email to wait for",
              ].map((item) => (
                <li key={item} className="flex items-start gap-2.5 text-[13px] text-muted-foreground leading-[1.5]">
                  <span className="mt-0.5 w-4 h-4 rounded-full bg-signal/10 flex items-center justify-center flex-shrink-0">
                    <Check className="w-2.5 h-2.5 text-signal" strokeWidth={3} />
                  </span>
                  {item}
                </li>
              ))}
            </ul>
          </div>

          <form onSubmit={handleSignup} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="fullName" className="text-[12.5px] font-medium text-foreground">
                Full name
              </Label>
              <Input
                id="fullName"
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Vansh Mahajan"
                required
                autoFocus
                className="h-10 text-[14px] bg-white"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="email" className="text-[12.5px] font-medium text-foreground">
                Email
              </Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="vansh@example.com"
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
                placeholder="at least 8 characters"
                required
                minLength={8}
                className="h-10 text-[14px] bg-white"
              />
              <p className="text-[11.5px] text-muted-foreground">
                Use at least 8 characters. This is a demo platform, so don't reuse a real password.
              </p>
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
                  Creating workspace…
                </>
              ) : (
                "Create workspace →"
              )}
            </Button>
          </form>

          <div className="mt-5 text-[13px] text-muted-foreground">
            Already have an account?{" "}
            <Link to="/login" className="lp-underline text-foreground font-medium">
              Sign in →
            </Link>
          </div>

          {/* Demo bypass */}
          <div className="mt-8 flex items-center gap-3" aria-hidden>
            <span className="flex-1 h-px bg-border" />
            <span className="font-mono text-[10.5px] uppercase tracking-[0.14em] text-muted-foreground">or</span>
            <span className="flex-1 h-px bg-border" />
          </div>
          <Link to="/login?demo=1" className="block mt-4">
            <Button
              type="button"
              variant="outline"
              className="w-full h-10 text-[13.5px] font-medium border-border hover:border-foreground/25 bg-white"
            >
              Try the demo account instead →
            </Button>
          </Link>

          <p className="mt-6 font-mono text-[10.5px] text-muted-foreground/80 leading-[1.7]">
            Portfolio demo · workspaces are isolated per account via Postgres
            Row-Level Security and may be reset periodically.
          </p>
        </motion.div>
      </div>
    </div>
  );
}
