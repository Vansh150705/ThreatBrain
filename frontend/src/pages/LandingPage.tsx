import { useEffect, useState, useRef } from "react";
import { Link, Navigate } from "react-router-dom";
import { motion, useInView } from "motion/react";
import {
  ArrowRight,
  Check,
  Menu,
  X,
  Shield,
  Lock,
  Database,
  Eye,
} from "lucide-react";

import { useAuth } from "@/contexts/AuthContext";
import { Button } from "@/components/ui/button";
import { Olivia, Henry, Nathan, Rachel, Frank, Claire } from "@/components/CrewPortraits";

/* ─────────── Logo mark ─────────── */
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

/* ─────────── GitHub icon (lucide-react removed brand icons in v1) ─────────── */
function GithubIcon({ className = "" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
    </svg>
  );
}

/* ─────────── Crew data ─────────── */
const CREW = [
  { name: "Olivia", role: "the Sorter", agent: "Triage", desc: "Classifies severity with MITRE ATT&CK.", portrait: Olivia, latency: "1.4s" },
  { name: "Henry", role: "the Investigator", agent: "Threat Intel", desc: "Enriches IPs against AbuseIPDB feeds.", portrait: Henry, latency: "0.8s" },
  { name: "Nathan", role: "the Connector", agent: "Investigation", desc: "Correlates threats into incidents.", portrait: Nathan, latency: "2.6s" },
  { name: "Rachel", role: "the Responder", agent: "Response", desc: "Recommends remediation playbooks.", portrait: Rachel, latency: "1.8s" },
  { name: "Frank", role: "the Forensicist", agent: "Forensics", desc: "Reconstructs chain-of-custody timelines.", portrait: Frank, latency: "3.1s" },
  { name: "Claire", role: "the Compliance Officer", agent: "Compliance", desc: "Assesses GDPR, PCI-DSS, SOC 2.", portrait: Claire, latency: "2.5s" },
];

/* ─────────── Live pipeline console ─────────── */
function PipelineConsole() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-100px" });
  const [step, setStep] = useState(-1);

  useEffect(() => {
    if (!inView) return;
    let i = -1;
    const tick = () => {
      i++;
      if (i >= CREW.length) {
        setTimeout(() => {
          i = -1;
          setStep(-1);
          setTimeout(tick, 800);
        }, 3000);
        return;
      }
      setStep(i);
      setTimeout(tick, 1400);
    };
    const t = setTimeout(tick, 600);
    return () => clearTimeout(t);
  }, [inView]);

  return (
    <div ref={ref} className="w-full max-w-3xl mx-auto rounded-2xl border border-border bg-card overflow-hidden shadow-sm">
      {/* Console header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-border bg-muted/40">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-foreground/15" />
            <div className="w-2.5 h-2.5 rounded-full bg-foreground/15" />
            <div className="w-2.5 h-2.5 rounded-full bg-foreground/15" />
          </div>
          <span className="ml-3 font-mono text-[11px] text-muted-foreground">pipeline.run · INC-FCBD7B</span>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-[10.5px] text-muted-foreground">
          <span className="w-1.5 h-1.5 rounded-full bg-severity-low animate-pulse" />
          <span>RUNNING</span>
        </div>
      </div>

      {/* Alert banner */}
      <div className="px-5 py-3 border-b border-border bg-muted/30">
        <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground mb-1">Input alert</div>
        <div className="text-[13px] text-foreground">
          Someone connected a new app to a corporate account.
        </div>
      </div>

      {/* Steps */}
      <div className="p-5 space-y-2.5">
        {CREW.map((c, i) => {
          const Portrait = c.portrait;
          const isActive = step === i;
          const isDone = step > i;
          return (
            <div key={c.name} className="flex items-center gap-3.5">
              <motion.div
                animate={{
                  scale: isActive ? 1.08 : 1,
                  opacity: step < i ? 0.35 : 1,
                }}
                transition={{ duration: 0.3 }}
                className="w-9 h-9 rounded-full bg-muted overflow-hidden flex-shrink-0 ring-1 ring-border"
              >
                <Portrait className="w-full h-full" />
              </motion.div>
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline gap-2">
                  <span className={`text-[13px] font-medium tracking-[-0.01em] ${step < i ? "text-muted-foreground" : "text-foreground"}`}>
                    {c.name}
                  </span>
                  <span className="font-mono text-[10.5px] text-muted-foreground">{c.agent}</span>
                </div>
                {isActive && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="flex items-center gap-1.5 mt-0.5"
                  >
                    <span className="w-1 h-1 rounded-full bg-muted-foreground animate-bounce" style={{ animationDelay: "0ms" }} />
                    <span className="w-1 h-1 rounded-full bg-muted-foreground animate-bounce" style={{ animationDelay: "150ms" }} />
                    <span className="w-1 h-1 rounded-full bg-muted-foreground animate-bounce" style={{ animationDelay: "300ms" }} />
                  </motion.div>
                )}
              </div>
              <div className="font-mono text-[11px] text-muted-foreground tabular w-12 text-right">{c.latency}</div>
              <div className="w-4 flex justify-center">
                {isDone && (
                  <motion.div
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ type: "spring", stiffness: 500, damping: 20 }}
                    className="w-4 h-4 rounded-full bg-severity-low flex items-center justify-center"
                  >
                    <Check className="w-2.5 h-2.5 text-white" strokeWidth={3} />
                  </motion.div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Footer */}
      <div className="px-5 py-3 border-t border-border bg-muted/30 flex items-center justify-between">
        <div className="flex items-center gap-2 font-mono text-[10.5px] text-muted-foreground">
          <span className="text-foreground font-semibold">{step + 1 < 0 ? 0 : Math.min(step + 1, CREW.length)}</span>
          <span>/</span>
          <span>{CREW.length}</span>
          <span>complete</span>
        </div>
        <div className="font-mono text-[10.5px] text-muted-foreground">
          Total · <span className="text-foreground font-semibold tabular">11.5s</span>
        </div>
      </div>
    </div>
  );
}

/* ─────────── Main page ─────────── */
export default function LandingPage() {
  const { session, loading } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    document.documentElement.style.scrollBehavior = "smooth";
    return () => {
      document.documentElement.style.scrollBehavior = "auto";
    };
  }, []);

  if (loading) return null;
  if (session) return <Navigate to="/dashboard" replace />;

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* ─────────── NAV ─────────── */}
      <nav className="sticky top-0 z-50 bg-background/85 backdrop-blur-xl border-b border-border">
        <div className="max-w-[1200px] mx-auto px-6 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="w-6 h-6 text-foreground">
              <LogoMark className="w-full h-full" />
            </div>
            <span className="font-semibold text-[15px] tracking-[-0.02em]">ThreatBrain</span>
          </Link>

          <div className="hidden md:flex items-center gap-7 text-[13px] text-muted-foreground">
            <a href="#crew" className="hover:text-foreground transition-colors">Crew</a>
            <a href="#how" className="hover:text-foreground transition-colors">How it works</a>
            <a href="#architecture" className="hover:text-foreground transition-colors">Architecture</a>
            <a href="#pricing" className="hover:text-foreground transition-colors">Pricing</a>
          </div>

          <div className="flex items-center gap-2">
            <a
              href="https://github.com/Vansh150705/ThreatBrain"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden sm:inline-flex items-center justify-center w-9 h-9 rounded-md hover:bg-accent text-muted-foreground"
              aria-label="GitHub"
            >
              <GithubIcon className="w-4 h-4" />
            </a>
            <Link to="/login" className="hidden md:block">
              <Button size="sm" className="bg-foreground text-background hover:bg-foreground/90 h-9 px-4 text-[13px] font-medium">
                Try the demo
                <ArrowRight className="w-3.5 h-3.5 ml-1.5" />
              </Button>
            </Link>
            <button
              className="md:hidden p-2 text-foreground"
              onClick={() => setMenuOpen((v) => !v)}
            >
              {menuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {menuOpen && (
          <div className="md:hidden border-t border-border bg-background">
            <div className="px-6 py-4 flex flex-col gap-3 text-[14px]">
              <a href="#crew" onClick={() => setMenuOpen(false)}>Crew</a>
              <a href="#how" onClick={() => setMenuOpen(false)}>How it works</a>
              <a href="#architecture" onClick={() => setMenuOpen(false)}>Architecture</a>
              <a href="#pricing" onClick={() => setMenuOpen(false)}>Pricing</a>
              <Link to="/login">
                <Button size="sm" className="w-full bg-foreground text-background">Try the demo</Button>
              </Link>
            </div>
          </div>
        )}
      </nav>

      {/* ─────────── HERO ─────────── */}
      <section className="relative">
        <div className="max-w-[1200px] mx-auto px-6 pt-24 pb-20">
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="max-w-3xl"
          >
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-border text-[11px] font-mono uppercase tracking-[0.1em] text-muted-foreground mb-8">
              <span className="w-1.5 h-1.5 rounded-full bg-severity-low animate-pulse" />
              Live demo available
            </div>

            <h1 className="title-serif text-[64px] md:text-[88px] leading-[0.96] tracking-[-0.04em] text-foreground">
              Your security team,<br />
              <em className="not-italic font-serif italic font-medium text-foreground">always on duty.</em>
            </h1>

            <p className="text-[19px] md:text-[20px] text-muted-foreground mt-8 leading-[1.5] max-w-2xl">
              Six AI agents triage, enrich, investigate, and respond to security alerts end-to-end.
              Hours of analyst work becomes a fifteen-second auditable pipeline.
            </p>

            <div className="mt-10 flex flex-wrap items-center gap-3">
              <Link to="/login">
                <Button size="lg" className="bg-foreground text-background hover:bg-foreground/90 h-11 px-5 text-[14px] font-medium">
                  Try the live demo
                  <ArrowRight className="w-4 h-4 ml-2" />
                </Button>
              </Link>
              <a href="https://github.com/Vansh150705/ThreatBrain" target="_blank" rel="noopener noreferrer">
                <Button size="lg" variant="outline" className="h-11 px-5 text-[14px] font-medium border-border">
                  <GithubIcon className="w-4 h-4 mr-2" />
                  View on GitHub
                </Button>
              </a>
            </div>

            <div className="mt-6 font-mono text-[12px] text-muted-foreground">
              test@acme.example · ThreatBrain123!
            </div>
          </motion.div>
        </div>
      </section>

      {/* ─────────── LIVE CONSOLE ─────────── */}
      <section className="border-y border-border bg-muted/20">
        <div className="max-w-[1200px] mx-auto px-6 py-20">
          <div className="text-center mb-12">
            <div className="font-mono text-[11px] uppercase tracking-[0.14em] text-muted-foreground font-semibold mb-3">
              Watch the pipeline
            </div>
            <h2 className="title-serif text-[36px] md:text-[44px] tracking-[-0.03em] text-foreground">
              One alert in.<br />
              <em className="not-italic font-serif italic font-medium">A full investigation out.</em>
            </h2>
          </div>
          <PipelineConsole />
        </div>
      </section>

      {/* ─────────── CREW ─────────── */}
      <section id="crew" className="border-b border-border">
        <div className="max-w-[1200px] mx-auto px-6 py-24">
          <div className="grid md:grid-cols-3 gap-8 mb-16">
            <div className="md:col-span-1">
              <div className="font-mono text-[11px] uppercase tracking-[0.14em] text-muted-foreground font-semibold mb-3">
                Meet the team
              </div>
              <h2 className="title-serif text-[36px] md:text-[44px] tracking-[-0.03em] text-foreground leading-[1.05]">
                Six specialists.<br />
                <em className="not-italic font-serif italic font-medium">One orchestrator.</em>
              </h2>
            </div>
            <div className="md:col-span-2 flex items-end">
              <p className="text-[16px] text-muted-foreground leading-[1.6]">
                Each agent has a focused job and a strict input-output schema. Together they form
                a virtual SOC team that runs around the clock.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-border rounded-2xl overflow-hidden border border-border">
            {CREW.map((c, i) => {
              const Portrait = c.portrait;
              return (
                <motion.div
                  key={c.name}
                  initial={{ opacity: 0, y: 12 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.05 }}
                  className="bg-card p-6 hover:bg-muted/40 transition-colors"
                >
                  <div className="flex items-start gap-4">
                    <motion.div
                      whileHover={{ y: -2 }}
                      className="w-14 h-14 rounded-full bg-muted overflow-hidden flex-shrink-0 ring-1 ring-border"
                    >
                      <Portrait className="w-full h-full" />
                    </motion.div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-baseline gap-2 flex-wrap">
                        <span className="title-serif text-[19px] text-foreground">{c.name}</span>
                        <span className="font-serif italic text-[14px] text-muted-foreground">{c.role}</span>
                      </div>
                      <div className="font-mono text-[10.5px] uppercase tracking-[0.1em] text-muted-foreground font-semibold mt-1">
                        {c.agent} Agent
                      </div>
                      <p className="text-[13.5px] text-foreground/80 mt-3 leading-[1.5]">{c.desc}</p>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ─────────── STATS BAR ─────────── */}
      <section className="bg-foreground text-background">
        <div className="max-w-[1200px] mx-auto px-6 py-16 grid grid-cols-2 md:grid-cols-4 gap-8">
          {[
            { value: "6", label: "AI agents" },
            { value: "11.5s", label: "End-to-end pipeline" },
            { value: "100%", label: "Audit coverage" },
            { value: "∞", label: "Alerts handled" },
          ].map((s, i) => (
            <motion.div
              key={s.label}
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.06 }}
            >
              <div className="title-serif text-[56px] md:text-[64px] leading-[0.95] tracking-[-0.04em] text-background tabular">
                {s.value}
              </div>
              <div className="font-mono text-[11px] uppercase tracking-[0.12em] text-background/60 mt-3 font-semibold">
                {s.label}
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* ─────────── HOW IT WORKS ─────────── */}
      <section id="how" className="border-b border-border">
        <div className="max-w-[1200px] mx-auto px-6 py-24">
          <div className="text-center mb-16">
            <div className="font-mono text-[11px] uppercase tracking-[0.14em] text-muted-foreground font-semibold mb-3">
              How it works
            </div>
            <h2 className="title-serif text-[36px] md:text-[44px] tracking-[-0.03em] text-foreground leading-[1.05]">
              Three steps,<br />
              <em className="not-italic font-serif italic font-medium">no analyst required.</em>
            </h2>
          </div>

          <div className="grid md:grid-cols-3 gap-12">
            {[
              { num: "I", title: "Alert arrives", desc: "A SIEM, firewall, or cloud audit log fires an event. ThreatBrain ingests it through a single FastAPI endpoint." },
              { num: "II", title: "Agents collaborate", desc: "Six specialized agents run in sequence: Triage, Threat Intel, Investigation, Response, Forensics, and Compliance." },
              { num: "III", title: "Incident is logged", desc: "A complete incident appears in the dashboard with attribution, kill chain, playbook, and chain-of-custody timeline." },
            ].map((s, i) => (
              <motion.div
                key={s.num}
                initial={{ opacity: 0, y: 12 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.08 }}
              >
                <div className="title-serif text-[28px] text-muted-foreground/60 mb-4">{s.num}.</div>
                <h3 className="text-[19px] font-semibold tracking-[-0.02em] mb-3">{s.title}</h3>
                <p className="text-[14px] text-muted-foreground leading-[1.6]">{s.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ─────────── ARCHITECTURE ─────────── */}
      <section id="architecture">
        <div className="max-w-[1200px] mx-auto px-6 py-24">
          <div className="grid md:grid-cols-3 gap-8 mb-16">
            <div className="md:col-span-1">
              <div className="font-mono text-[11px] uppercase tracking-[0.14em] text-muted-foreground font-semibold mb-3">
                Security architecture
              </div>
              <h2 className="title-serif text-[36px] md:text-[44px] tracking-[-0.03em] text-foreground leading-[1.05]">
                Built for{" "}
                <em className="not-italic font-serif italic font-medium">scrutiny.</em>
              </h2>
            </div>
            <div className="md:col-span-2 flex items-end">
              <p className="text-[16px] text-muted-foreground leading-[1.6]">
                Security is not a feature added later. It is baked into every layer of the platform.
              </p>
            </div>
          </div>

          <div className="space-y-px bg-border rounded-2xl overflow-hidden border border-border">
            {[
              { icon: Lock, title: "Multi-tenant isolation", desc: "Postgres Row-Level Security binds every query to the JWT's organization claim. Even buggy code cannot leak cross-tenant data." },
              { icon: Eye, title: "Append-only audit logs", desc: "Postgres triggers physically reject UPDATE and DELETE on audit_logs. Every agent decision is verifiable for regulators." },
              { icon: Shield, title: "Human-in-the-loop", desc: "The Response Agent recommends, never executes. Real actions require admin role plus per-playbook authorization." },
              { icon: Database, title: "Pydantic + JSON mode", desc: "Every LLM call has a strict input and output schema. The model has no free-form channel to misbehave through." },
            ].map((feat, i) => (
              <motion.div
                key={feat.title}
                initial={{ opacity: 0, x: -8 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.05 }}
                className="bg-card p-7 flex gap-5 items-start hover:bg-muted/40 transition-colors"
              >
                <div className="w-10 h-10 rounded-lg bg-muted border border-border flex items-center justify-center flex-shrink-0">
                  <feat.icon className="w-4 h-4 text-foreground" strokeWidth={1.8} />
                </div>
                <div className="flex-1">
                  <div className="text-[16px] font-semibold tracking-[-0.015em] text-foreground">{feat.title}</div>
                  <p className="text-[14px] text-muted-foreground mt-1.5 leading-[1.6] max-w-2xl">{feat.desc}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ─────────── CTA (inverted block) ─────────── */}
      <section className="bg-foreground text-background">
        <div className="max-w-[1200px] mx-auto px-6 py-24 text-center">
          <motion.h2
            initial={{ opacity: 0, y: 12 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="title-serif text-[48px] md:text-[64px] tracking-[-0.035em] leading-[1.05] text-background max-w-3xl mx-auto"
          >
            Your first investigation is{" "}
            <em className="not-italic font-serif italic font-medium">two seconds away.</em>
          </motion.h2>
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1 }}
            className="mt-10 flex flex-wrap justify-center gap-3"
          >
            <Link to="/login">
              <Button size="lg" className="bg-background text-foreground hover:bg-background/90 h-12 px-6 text-[14px] font-medium">
                Try the live demo
                <ArrowRight className="w-4 h-4 ml-2" />
              </Button>
            </Link>
            <a href="https://github.com/Vansh150705/ThreatBrain" target="_blank" rel="noopener noreferrer">
              <Button size="lg" variant="outline" className="h-12 px-6 text-[14px] font-medium border-background/30 text-background hover:bg-background/10 bg-transparent">
                <GithubIcon className="w-4 h-4 mr-2" />
                View on GitHub
              </Button>
            </a>
          </motion.div>
        </div>
      </section>

      {/* ─────────── FOOTER ─────────── */}
      <footer className="border-t border-border bg-background">
        <div className="max-w-[1200px] mx-auto px-6 py-12">
          <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-8">
            <div>
              <div className="flex items-center gap-2.5">
                <div className="w-6 h-6 text-foreground">
                  <LogoMark className="w-full h-full" />
                </div>
                <span className="font-semibold text-[15px] tracking-[-0.02em]">ThreatBrain</span>
              </div>
              <p className="text-[13px] text-muted-foreground mt-4 leading-[1.6] max-w-[200px]">
                The neural SOC where AI agents converge to defend.
              </p>
            </div>
            <div>
              <div className="font-mono text-[10.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-4">Product</div>
              <ul className="space-y-2.5 text-[13px] text-foreground/80">
                <li><a href="#crew" className="hover:text-foreground">Crew</a></li>
                <li><a href="#how" className="hover:text-foreground">How it works</a></li>
                <li><a href="#architecture" className="hover:text-foreground">Architecture</a></li>
              </ul>
            </div>
            <div>
              <div className="font-mono text-[10.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-4">Resources</div>
              <ul className="space-y-2.5 text-[13px] text-foreground/80">
                <li><a href="https://github.com/Vansh150705/ThreatBrain" target="_blank" rel="noopener noreferrer" className="hover:text-foreground">GitHub</a></li>
                <li><Link to="/login" className="hover:text-foreground">Live demo</Link></li>
              </ul>
            </div>
            <div>
              <div className="font-mono text-[10.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-4">Built by</div>
              <ul className="space-y-2.5 text-[13px] text-foreground/80">
                <li><a href="https://github.com/Vansh150705" target="_blank" rel="noopener noreferrer" className="hover:text-foreground">@Vansh150705</a></li>
              </ul>
            </div>
          </div>

          <div className="border-t border-border mt-12 pt-6 flex flex-col sm:flex-row justify-between items-center gap-3 text-[12px] text-muted-foreground">
            <div>© 2026 ThreatBrain · Portfolio project · MIT License</div>
            <div className="flex items-center gap-2 font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-severity-low" />
              <span>All systems operational</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}