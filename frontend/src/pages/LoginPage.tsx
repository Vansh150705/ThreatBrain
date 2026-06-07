import { useState } from "react";
import { useNavigate, useLocation, Navigate, Link } from "react-router-dom";
import { motion } from "motion/react";
import { Loader2, AlertCircle } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { signIn } from "@/lib/supabase";
import { useAuth } from "@/contexts/AuthContext";

function LogoMark({ className = "" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M12 2 L20 5 L20 12 C20 17 16 21 12 22 C8 21 4 17 4 12 L4 5 Z"
        fill="currentColor"
      />
      <circle cx="9" cy="9" r="1.4" fill="#ffffff" />
      <circle cx="15" cy="9" r="1.4" fill="#ffffff" />
      <circle cx="12" cy="14" r="1.4" fill="#ffffff" />
      <line x1="9" y1="9" x2="15" y2="9" stroke="#ffffff" strokeWidth="0.6" />
      <line x1="9" y1="9" x2="12" y2="14" stroke="#ffffff" strokeWidth="0.6" />
      <line x1="15" y1="9" x2="12" y2="14" stroke="#ffffff" strokeWidth="0.6" />
    </svg>
  );
}

export default function LoginPage() {
  const { session, loading: authLoading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const redirectTo =
    (location.state as { from?: string } | null)?.from ?? "/dashboard";

  const [email, setEmail] = useState("test@acme.example");
  const [password, setPassword] = useState("");
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
    <div className="min-h-screen bg-background flex flex-col">
      {/* Top nav */}
      <header className="h-16 border-b border-border flex items-center justify-between px-8">
        <Link to="/" className="flex items-center gap-2.5">
          <div className="w-6 h-6 text-foreground">
            <LogoMark className="w-full h-full" />
          </div>
          <span className="font-semibold text-[15px] tracking-[-0.02em]">ThreatBrain</span>
        </Link>
        <Link
          to="/"
          className="text-[13px] text-muted-foreground hover:text-foreground transition-colors"
        >
          Back to home
        </Link>
      </header>

      {/* Form */}
      <div className="flex-1 flex items-center justify-center px-6 py-12">
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="w-full max-w-[400px]"
        >
          <div className="mb-8">
            <h1 className="text-[28px] tracking-[-0.025em] font-semibold text-foreground">
              Sign in
            </h1>
            <p className="text-[14px] text-muted-foreground mt-1.5">
              Access your ThreatBrain operations console.
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
                className="h-10 text-[14px]"
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
                className="h-10 text-[14px]"
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

          {/* Demo creds */}
          <div className="mt-6 p-4 rounded-lg bg-muted border border-border">
            <div className="text-[11px] font-mono uppercase tracking-[0.1em] text-muted-foreground mb-2 font-semibold">
              Demo credentials
            </div>
            <div className="font-mono text-[12px] text-foreground space-y-0.5">
              <div>test@acme.example</div>
              <div>ThreatBrain123!</div>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}