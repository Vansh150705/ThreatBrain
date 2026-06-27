import { useEffect, useState, useRef, type ReactNode } from "react";
import { Link, Navigate } from "react-router-dom";
import { motion, useInView } from "motion/react";
import { ArrowRight, Check, Menu, X } from "lucide-react";

import { useAuth } from "@/contexts/AuthContext";
import { Button } from "@/components/ui/button";
import { LogoMark } from "@/components/Logo";
import { Olivia, Henry, Nathan, Rachel, Frank, Claire } from "@/components/CrewPortraits";

/* github icon (lucide-react removed brand icons in v1) */
function GithubIcon({ className = "" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
    </svg>
  );
}

/* scroll reveal */
function Reveal({
  children,
  delay = 0,
  className = "",
}: {
  children: ReactNode;
  delay?: number;
  className?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.55, delay, ease: "easeOut" }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

/* crew data */
const CREW = [
  { name: "Olivia", role: "the Sorter", agent: "Triage", desc: "Classifies severity with MITRE ATT&CK.", portrait: Olivia, latency: "1.4s" },
  { name: "Henry", role: "the Investigator", agent: "Threat Intel", desc: "Enriches IPs against AbuseIPDB feeds.", portrait: Henry, latency: "0.8s" },
  { name: "Nathan", role: "the Connector", agent: "Investigation", desc: "Correlates threats into incidents.", portrait: Nathan, latency: "2.6s" },
  { name: "Rachel", role: "the Responder", agent: "Response", desc: "Recommends remediation playbooks.", portrait: Rachel, latency: "1.8s" },
  { name: "Frank", role: "the Forensicist", agent: "Forensics", desc: "Reconstructs chain-of-custody timelines.", portrait: Frank, latency: "3.1s" },
  { name: "Claire", role: "the Compliance Officer", agent: "Compliance", desc: "Assesses GDPR, PCI-DSS, SOC 2.", portrait: Claire, latency: "2.5s" },
];

/* attack arc visual (hero signature) */
const HQ = { x: 268, y: 426 };

type Arc = {
  d: string;
  x: number;
  y: number;
  label: string;
  color: string;
  dur: number;
  begin: number;
  labelLeft?: boolean;
};

const ARCS: Arc[] = [
  { d: "M 805 95 C 660 40, 380 200, 268 420", x: 805, y: 95, label: "Moscow", color: "var(--color-severity-critical)", dur: 5.5, begin: 0 },
  { d: "M 1080 185 C 880 110, 470 240, 270 422", x: 1080, y: 185, label: "Pyongyang", color: "var(--color-severity-high)", dur: 7, begin: 1.6, labelLeft: true },
  { d: "M 990 295 C 800 250, 480 310, 270 424", x: 990, y: 295, label: "Beijing", color: "var(--color-severity-high)", dur: 6, begin: 3.1 },
  { d: "M 1105 400 C 890 370, 500 380, 272 428", x: 1105, y: 400, label: "Shenzhen", color: "var(--color-severity-medium)", dur: 6.5, begin: 0.8, labelLeft: true },
  { d: "M 952 490 C 780 482, 460 462, 270 432", x: 952, y: 490, label: "Lagos", color: "var(--color-severity-medium)", dur: 7.5, begin: 2.3 },
];

function CityChip({
  x,
  y,
  label,
  color,
  anchorLeft,
}: {
  x: number;
  y: number;
  label: string;
  color: string;
  anchorLeft?: boolean;
}) {
  const width = label.length * 7.2 + 34;
  const rectX = anchorLeft ? x - 16 - width : x + 16;
  return (
    <g>
      <rect
        x={rectX}
        y={y - 12}
        width={width}
        height={24}
        rx={12}
        fill="rgba(255,255,255,0.92)"
        stroke={color}
        strokeOpacity="0.4"
        strokeWidth="1"
      />
      <circle cx={rectX + 14} cy={y} r="3" fill={color} />
      <text
        x={rectX + 25}
        y={y + 4}
        fontFamily="var(--font-mono)"
        fontSize="11.5"
        fontWeight="500"
        fill="oklch(0.155 0.012 252 / 0.75)"
      >
        {label}
      </text>
    </g>
  );
}

function AttackArcs({ className = "" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 1200 520" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden>
      {ARCS.map((a) => (
        <g key={a.label}>
          {/* severity-tinted arc */}
          <path
            d={a.d}
            stroke={a.color}
            strokeOpacity="0.35"
            strokeWidth="1.4"
            strokeDasharray="5 7"
            className="lp-dash"
            style={{ animationDuration: `${a.dur * 1.6}s` }}
          />
          {/* origin dot + pulse */}
          <circle cx={a.x} cy={a.y} r="4.5" fill={a.color} />
          <circle cx={a.x} cy={a.y} r="9" stroke={a.color} strokeWidth="1.2" fill="none" className="attack-pulse-ring" />
          <CityChip x={a.x} y={a.y} label={a.label} color={a.color} anchorLeft={a.labelLeft} />
          {/* glowing packet travelling toward hq */}
          <g>
            <circle r="7" fill={a.color} opacity="0.18" />
            <circle r="3.2" fill={a.color} />
            <animateMotion dur={`${a.dur}s`} begin={`${a.begin}s`} repeatCount="indefinite" path={a.d} />
          </g>
        </g>
      ))}

      {/* hq node */}
      <circle cx={HQ.x} cy={HQ.y} r="30" fill="var(--color-signal)" opacity="0.07" />
      <circle
        cx={HQ.x}
        cy={HQ.y}
        r="18"
        stroke="var(--color-signal)"
        strokeWidth="1"
        strokeDasharray="4 9"
        fill="none"
        opacity="0.55"
      >
        <animateTransform
          attributeName="transform"
          type="rotate"
          from={`0 ${HQ.x} ${HQ.y}`}
          to={`360 ${HQ.x} ${HQ.y}`}
          dur="14s"
          repeatCount="indefinite"
        />
      </circle>
      <circle cx={HQ.x} cy={HQ.y} r="6" fill="var(--color-signal)" />
      <circle cx={HQ.x} cy={HQ.y} r="2.2" fill="#ffffff" />
      <circle cx={HQ.x} cy={HQ.y} r="11" stroke="var(--color-signal)" strokeWidth="1.2" fill="none" className="attack-pulse-ring" />
      <circle
        cx={HQ.x}
        cy={HQ.y}
        r="11"
        stroke="var(--color-signal)"
        strokeWidth="1.2"
        fill="none"
        className="attack-pulse-ring"
        style={{ animationDelay: "1.2s" }}
      />
      <CityChip x={HQ.x} y={HQ.y + 40} label="acme-corp · shielded" color="var(--color-signal)" anchorLeft />
    </svg>
  );
}

/* integration marquee */
const SOURCES = [
  "SPLUNK", "CROWDSTRIKE", "OKTA", "AWS GUARDDUTY", "MICROSOFT SENTINEL",
  "DATADOG", "CLOUDFLARE", "PALO ALTO", "ELASTIC", "WIZ",
];

function SourceMarquee() {
  const items = [...SOURCES, ...SOURCES];
  return (
    <section className="border-b border-border">
      <div className="max-w-[1200px] mx-auto px-6 py-10 flex flex-col sm:flex-row items-center gap-6">
        <div className="font-mono text-[10.5px] uppercase tracking-[0.16em] text-muted-foreground whitespace-nowrap flex-shrink-0">
          Ingests alerts from
        </div>
        <div className="overflow-hidden flex-1 w-full [mask-image:linear-gradient(to_right,transparent,black_12%,black_88%,transparent)]">
          <div className="lp-marquee flex w-max items-center">
            {items.map((s, i) => (
              <span key={i} className="px-8 font-mono text-[12.5px] tracking-[0.1em] text-foreground/45 whitespace-nowrap font-medium">
                {s}
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/* live showcase: console in, dossier out */
const DOSSIER = [
  { label: "Triage", title: "High severity · OAuth consent abuse", body: "Mapped to MITRE ATT&CK T1550.001, application access token abuse." },
  { label: "Threat intel", title: "185.220.101.42 flagged", body: "AbuseIPDB confidence 97% · known TOR exit node · 312 prior reports." },
  { label: "Investigation", title: "Correlated with 3 prior threats", body: "Same actor fingerprint seen across staging and prod tenants in 48h." },
  { label: "Response", title: "Playbook: revoke and contain", body: "Revoke the OAuth grant, rotate refresh tokens, notify the account owner." },
  { label: "Forensics", title: "Chain of custody preserved", body: "14 events reconstructed into a tamper-evident timeline." },
  { label: "Compliance", title: "GDPR Art. 33 assessed", body: "No personal-data breach. SOC 2 evidence attached to the incident." },
];

function PipelineShowcase() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-120px" });
  const [step, setStep] = useState(-1);

  useEffect(() => {
    if (!inView) return;
    let i = -1;
    let cancelled = false;
    const timers: ReturnType<typeof setTimeout>[] = [];
    const tick = () => {
      if (cancelled) return;
      i++;
      if (i >= CREW.length) {
        timers.push(
          setTimeout(() => {
            i = -1;
            setStep(-1);
            timers.push(setTimeout(tick, 900));
          }, 4200)
        );
        return;
      }
      setStep(i);
      timers.push(setTimeout(tick, 1500));
    };
    timers.push(setTimeout(tick, 700));
    return () => {
      cancelled = true;
      timers.forEach(clearTimeout);
    };
  }, [inView]);

  return (
    <div
      ref={ref}
      className="grid lg:grid-cols-5 rounded-2xl border border-border bg-card overflow-hidden shadow-[0_1px_2px_rgba(16,24,40,0.04),0_16px_40px_-16px_rgba(16,24,40,0.1)]"
    >
      {/* agent console */}
      <div className="lg:col-span-2 lg:border-r border-b lg:border-b-0 border-border flex flex-col">
        <div className="flex items-center justify-between px-5 py-3 border-b border-border bg-muted/40">
          <span className="font-mono text-[11px] text-muted-foreground">pipeline.run · INC-2041</span>
          <div className="flex items-center gap-1.5 font-mono text-[10.5px] text-signal">
            <span className="w-1.5 h-1.5 rounded-full bg-signal animate-pulse" />
            <span>RUNNING</span>
          </div>
        </div>

        <div className="px-5 py-3 border-b border-border">
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground mb-1">Input alert</div>
          <div className="font-mono text-[12.5px] text-foreground leading-[1.5]">
            <span className="text-signal mr-2">&gt;</span>
            Someone connected a new app to a corporate account.
            <span className="lp-caret text-signal ml-0.5">▌</span>
          </div>
        </div>

        <div className="p-5 space-y-3 flex-1">
          {CREW.map((c, i) => {
            const Portrait = c.portrait;
            const isActive = step === i;
            const isDone = step > i;
            return (
              <div key={c.name} className="flex items-center gap-3">
                <motion.div
                  animate={{ scale: isActive ? 1.08 : 1, opacity: step < i ? 0.35 : 1 }}
                  transition={{ duration: 0.3 }}
                  className={`w-8 h-8 rounded-full bg-muted overflow-hidden flex-shrink-0 ring-1 ${isActive ? "ring-signal/50" : "ring-border"}`}
                >
                  <Portrait className="w-full h-full" />
                </motion.div>
                <div className="flex-1 min-w-0 flex items-baseline gap-2">
                  <span className={`text-[13px] font-medium tracking-[-0.01em] ${step < i ? "text-muted-foreground" : "text-foreground"}`}>
                    {c.name}
                  </span>
                  <span className="font-mono text-[10px] text-muted-foreground">{c.agent}</span>
                </div>
                <div className="font-mono text-[10.5px] text-muted-foreground tabular">{c.latency}</div>
                <div className="w-4 flex justify-center">
                  {isDone ? (
                    <motion.div
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{ type: "spring", stiffness: 500, damping: 22 }}
                      className="w-4 h-4 rounded-full bg-signal flex items-center justify-center"
                    >
                      <Check className="w-2.5 h-2.5 text-white" strokeWidth={3} />
                    </motion.div>
                  ) : isActive ? (
                    <span className="w-1.5 h-1.5 rounded-full bg-signal animate-ping" />
                  ) : null}
                </div>
              </div>
            );
          })}
        </div>

        <div className="px-5 py-3 border-t border-border bg-muted/30 flex items-center justify-between font-mono text-[10.5px] text-muted-foreground">
          <div>
            <span className="text-foreground font-semibold">{Math.max(0, Math.min(step + 1, CREW.length))}</span>
            <span> / {CREW.length} complete</span>
          </div>
          <div>
            Total · <span className="text-foreground font-semibold tabular">11.5s</span>
          </div>
        </div>
      </div>

      {/* generated dossier */}
      <div className="lg:col-span-3 bg-muted/20">
        <div className="flex items-center justify-between px-6 py-3 border-b border-border bg-muted/40">
          <span className="font-mono text-[11px] text-muted-foreground">incident dossier · auto-generated</span>
          {step >= 0 && (
            <motion.span
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="font-mono text-[10px] uppercase tracking-[0.1em] px-2 py-0.5 rounded-full border border-severity-high/30 text-severity-high bg-severity-high/[0.06]"
            >
              High
            </motion.span>
          )}
        </div>
        <div className="p-6 space-y-5">
          {DOSSIER.map((d, i) => {
            const visible = step >= i;
            return (
              <div key={d.label} className="grid grid-cols-[84px_1fr] sm:grid-cols-[110px_1fr] gap-4 items-baseline">
                <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground pt-0.5">
                  {d.label}
                </div>
                {visible ? (
                  <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
                    <div className="text-[14px] font-medium tracking-[-0.01em] text-foreground">{d.title}</div>
                    <p className="text-[13px] text-muted-foreground mt-1 leading-[1.6]">{d.body}</p>
                  </motion.div>
                ) : (
                  <div className="space-y-2 py-1" aria-hidden>
                    <div className="h-2 w-2/3 rounded bg-foreground/[0.05]" />
                    <div className="h-2 w-5/6 rounded bg-foreground/[0.04]" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* bento features */
function BentoCard({
  children,
  className = "",
  delay = 0,
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-60px" }}
      transition={{ duration: 0.55, delay, ease: "easeOut" }}
      className={`rounded-xl border border-border bg-card p-6 transition-all duration-300 hover:-translate-y-0.5 hover:border-signal/40 hover:bg-signal/[0.045] hover:shadow-[0_1px_2px_rgba(16,24,40,0.04),0_12px_28px_-12px_rgba(16,24,40,0.12)] ${className}`}
    >
      {children}
    </motion.div>
  );
}

/* interactive attack simulator */
type SimLine = {
  t: string;
  tag: string;
  text: string;
  tone?: "crit" | "warn";
};

type Scenario = {
  id: string;
  label: string;
  alert: string;
  incident: string;
  total: string;
  lines: SimLine[];
};

const SCENARIOS: Scenario[] = [
  {
    id: "phishing",
    label: "Phishing email",
    alert: "Employee reported a suspicious sign-in page",
    incident: "INC-2042",
    total: "12.2s",
    lines: [
      { t: "00.0s", tag: "INGEST", text: "alert received from mail gateway · MAIL-7741" },
      { t: "01.4s", tag: "OLIVIA · TRIAGE", text: "high severity · credential phishing · T1566.002", tone: "warn" },
      { t: "02.2s", tag: "HENRY · INTEL", text: "91.243.44.7 → AbuseIPDB 94% · domain registered 36h ago" },
      { t: "04.8s", tag: "NATHAN · INVESTIGATION", text: "3 recipients clicked · 1 submitted credentials" },
      { t: "06.6s", tag: "RACHEL · RESPONSE", text: "playbook → force password reset · block domain at proxy" },
      { t: "09.7s", tag: "FRANK · FORENSICS", text: "mail headers and click timeline preserved · 11 events" },
      { t: "12.2s", tag: "CLAIRE · COMPLIANCE", text: "GDPR Art. 33 assessed → no notification required" },
    ],
  },
  {
    id: "bruteforce",
    label: "Brute force",
    alert: "412 failed logins against the VPN gateway in 90 seconds",
    incident: "INC-2043",
    total: "11.1s",
    lines: [
      { t: "00.0s", tag: "INGEST", text: "alert received from SIEM · correlation rule BF-22" },
      { t: "01.3s", tag: "OLIVIA · TRIAGE", text: "critical severity · brute force · T1110.001", tone: "crit" },
      { t: "02.1s", tag: "HENRY · INTEL", text: "185.220.101.42 → TOR exit node · 312 prior reports" },
      { t: "04.6s", tag: "NATHAN · INVESTIGATION", text: "no successful auth · 2 accounts near lockout" },
      { t: "06.5s", tag: "RACHEL · RESPONSE", text: "playbook → geo-block range · enforce MFA on targets" },
      { t: "09.4s", tag: "FRANK · FORENSICS", text: "auth timeline reconstructed · 412 attempts mapped" },
      { t: "11.1s", tag: "CLAIRE · COMPLIANCE", text: "PCI-DSS logged · no cardholder scope touched" },
    ],
  },
  {
    id: "oauth",
    label: "Rogue OAuth app",
    alert: "New third-party app granted mailbox scope",
    incident: "INC-2044",
    total: "11.5s",
    lines: [
      { t: "00.0s", tag: "INGEST", text: "alert received from cloud audit log · GW-EVENTS" },
      { t: "01.4s", tag: "OLIVIA · TRIAGE", text: "high severity · consent abuse · T1550.001", tone: "warn" },
      { t: "02.3s", tag: "HENRY · INTEL", text: "publisher unverified · app registered yesterday" },
      { t: "04.9s", tag: "NATHAN · INVESTIGATION", text: "1 mailbox affected · no exfiltration observed yet" },
      { t: "06.7s", tag: "RACHEL · RESPONSE", text: "playbook → revoke grant · rotate refresh tokens" },
      { t: "09.8s", tag: "FRANK · FORENSICS", text: "consent chain preserved · 14 events" },
      { t: "11.5s", tag: "CLAIRE · COMPLIANCE", text: "SOC 2 evidence attached · GDPR assessed" },
    ],
  },
];

const SIM = {
  text: "oklch(0.88 0.006 250)",
  dim: "oklch(0.62 0.01 250)",
  agent: "oklch(0.78 0.13 158)",
  crit: "oklch(0.72 0.17 25)",
  warn: "oklch(0.79 0.13 75)",
};

function AttackSimulator() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-100px" });
  const [scenario, setScenario] = useState(0);
  const [count, setCount] = useState(0);

  const active = SCENARIOS[scenario];
  const done = count >= active.lines.length;

  useEffect(() => {
    if (!inView) return;
    const iv = setInterval(() => {
      setCount((c) => (c >= SCENARIOS[scenario].lines.length ? c : c + 1));
    }, 560);
    return () => clearInterval(iv);
  }, [inView, scenario]);

  return (
    <div ref={ref}>
      {/* scenario picker */}
      <div className="flex flex-wrap items-center gap-2 mb-6">
        <span className="font-mono text-[10.5px] uppercase tracking-[0.14em] text-muted-foreground mr-2">
          Scenario
        </span>
        {SCENARIOS.map((s, i) => (
          <button
            key={s.id}
            onClick={() => {
              setScenario(i);
              setCount(0);
            }}
            className={`px-3.5 py-1.5 rounded-full text-[12.5px] font-medium border transition-all duration-200 ${
              i === scenario
                ? "bg-foreground text-background border-foreground"
                : "bg-white text-muted-foreground border-border hover:border-foreground/30 hover:text-foreground"
            }`}
          >
            {s.label}
          </button>
        ))}
      </div>

      {/* terminal */}
      <div className="rounded-2xl overflow-hidden border border-border shadow-[0_1px_2px_rgba(16,24,40,0.06),0_24px_48px_-20px_rgba(16,24,40,0.25)] bg-[oklch(0.165_0.012_252)]">
        <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.07]">
          <div className="flex items-center gap-2">
            <div className="flex gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-white/15" />
              <span className="w-2.5 h-2.5 rounded-full bg-white/15" />
              <span className="w-2.5 h-2.5 rounded-full bg-white/15" />
            </div>
            <span className="ml-3 font-mono text-[11px]" style={{ color: SIM.dim }}>
              threatbrain --simulate --scenario={active.id}
            </span>
          </div>
          <div className="flex items-center gap-1.5 font-mono text-[10.5px]" style={{ color: done ? SIM.agent : SIM.dim }}>
            <span
              className={`w-1.5 h-1.5 rounded-full ${done ? "" : "animate-pulse"}`}
              style={{ background: done ? SIM.agent : SIM.warn }}
            />
            <span>{done ? "RESOLVED" : "RUNNING"}</span>
          </div>
        </div>

        <div className="px-5 sm:px-6 py-5 font-mono text-[11.5px] sm:text-[12.5px] leading-[2] min-h-[300px] sm:min-h-[320px] overflow-x-auto">
          <div style={{ color: SIM.text }}>
            <span style={{ color: SIM.dim }}>alert ·</span> {active.alert}
          </div>
          {active.lines.slice(0, count).map((l, i) => {
            const isLast = i === count - 1;
            return (
              <motion.div
                key={`${active.id}-${i}`}
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.25 }}
                className="md:whitespace-nowrap"
              >
                <span style={{ color: SIM.dim }}>{l.t}</span>
                <span className="mx-2" style={{ color: l.tag === "INGEST" ? SIM.dim : SIM.agent }}>
                  [{l.tag}]
                </span>
                <span style={{ color: l.tone === "crit" ? SIM.crit : l.tone === "warn" ? SIM.warn : SIM.text }}>
                  {l.text}
                </span>
                {isLast && !done && (
                  <span className="lp-caret ml-1" style={{ color: SIM.agent }}>▌</span>
                )}
              </motion.div>
            );
          })}
          {done && (
            <motion.div
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35 }}
              className="mt-3 inline-flex items-center gap-2 rounded-md border px-3 py-1.5"
              style={{ borderColor: "oklch(0.78 0.13 158 / 0.3)", color: SIM.agent, background: "oklch(0.78 0.13 158 / 0.08)" }}
            >
              <Check className="w-3.5 h-3.5" strokeWidth={2.5} />
              <span>
                {active.incident} created · resolved in {active.total} · full audit trail written
              </span>
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
}

/* main page */
export default function LandingPage() {
  const { session, loading } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    document.documentElement.style.scrollBehavior = "smooth";
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      document.documentElement.style.scrollBehavior = "auto";
      window.removeEventListener("scroll", onScroll);
    };
  }, []);

  if (loading) return null;
  if (session) return <Navigate to="/dashboard" replace />;

  return (
    <div className="min-h-screen bg-white text-foreground">
      {/* nav */}
      <nav
        className={`sticky top-0 z-50 bg-white/85 backdrop-blur-xl border-b transition-[border-color,box-shadow] duration-300 ${
          scrolled ? "border-border shadow-[0_1px_2px_rgba(16,24,40,0.03)]" : "border-transparent"
        }`}
      >
        <div className="max-w-[1200px] mx-auto px-6 h-[72px] flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3">
            <div className="w-9 h-9 text-foreground">
              <LogoMark className="w-full h-full" />
            </div>
            <span className="flex flex-col leading-none">
              <span className="font-semibold text-[16.5px] tracking-[-0.02em]">ThreatBrain</span>
              <span className="font-mono text-[9px] uppercase tracking-[0.18em] text-muted-foreground mt-1">
                Agentic SOC
              </span>
            </span>
          </Link>

          <div className="hidden md:flex items-center gap-8 text-[13.5px] text-muted-foreground">
            <a href="#showcase" className="lp-underline hover:text-foreground transition-colors">Live demo</a>
            <a href="#features" className="lp-underline hover:text-foreground transition-colors">Features</a>
            <a href="#how" className="lp-underline hover:text-foreground transition-colors">How it works</a>
            <a href="#simulate" className="lp-underline hover:text-foreground transition-colors">Simulator</a>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-full border border-border font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
              <span className="w-1.5 h-1.5 rounded-full bg-signal animate-pulse" />
              Operational
            </div>
            <a
              href="https://github.com/Vansh150705/ThreatBrain"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden sm:inline-flex items-center justify-center w-9 h-9 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground transition-colors"
              aria-label="GitHub"
            >
              <GithubIcon className="w-[18px] h-[18px]" />
            </a>
            <Link to="/signup" className="hidden md:block">
              <Button size="sm" className="group bg-foreground text-background hover:bg-foreground/90 h-10 px-5 text-[13.5px] font-medium">
                Try the demo
                <ArrowRight className="w-3.5 h-3.5 ml-1.5 transition-transform group-hover:translate-x-0.5" />
              </Button>
            </Link>
            <button
              className="md:hidden p-2 text-foreground"
              aria-label="Toggle menu"
              onClick={() => setMenuOpen((v) => !v)}
            >
              {menuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {menuOpen && (
          <div className="md:hidden border-t border-border bg-white">
            <div className="px-6 py-4 flex flex-col gap-3 text-[14px]">
              <a href="#showcase" onClick={() => setMenuOpen(false)}>Live demo</a>
              <a href="#features" onClick={() => setMenuOpen(false)}>Features</a>
              <a href="#how" onClick={() => setMenuOpen(false)}>How it works</a>
              <a href="#simulate" onClick={() => setMenuOpen(false)}>Simulator</a>
              <Link to="/signup">
                <Button size="sm" className="w-full bg-foreground text-background">Try the demo</Button>
              </Link>
            </div>
          </div>
        )}
      </nav>

      {/* hero */}
      <section className="relative overflow-hidden">
        <div className="lp-grid absolute inset-0 pointer-events-none" aria-hidden />

        {/* attack arcs pinned behind the headline block */}
        <div
          className="hidden md:block absolute left-1/2 -translate-x-1/2 top-6 w-full max-w-[1280px] aspect-[1200/520] pointer-events-none"
          aria-hidden
        >
          <AttackArcs className="w-full h-full" />
        </div>

        {/* soft white halo so the headline stays legible over the arcs */}
        <div
          className="hidden md:block absolute inset-x-0 top-0 h-[640px] pointer-events-none bg-[radial-gradient(ellipse_48%_52%_at_50%_44%,white_30%,rgba(255,255,255,0)_70%)]"
          aria-hidden
        />

        <div className="relative max-w-[1200px] mx-auto px-6 pt-24 pb-14 lg:pt-28 lg:pb-16 text-center">
          <motion.div
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: "easeOut" }}
          >
            <div className="inline-flex items-center justify-center gap-2 px-4 py-1.5 rounded-full border border-signal/25 bg-signal/[0.05] font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground mb-9">
              <span className="w-1.5 h-1.5 rounded-full bg-signal animate-pulse" />
              <span className="text-foreground font-semibold">SOC operational</span>
              <span className="text-border">·</span>
              <span>6 agents online</span>
            </div>

            <h1 className="title-serif text-[clamp(46px,7.5vw,92px)] leading-[0.98] tracking-[-0.04em] text-foreground mx-auto">
              Your security team,<br />
              <em className="font-serif italic font-medium text-signal">always on duty.</em>
            </h1>

            <p className="text-[17px] sm:text-[18px] lg:text-[19px] text-muted-foreground mt-8 leading-[1.65] max-w-xl mx-auto">
              Six AI agents triage, enrich, investigate, and respond to security
              alerts end to end. Hours of analyst work becomes a fifteen-second
              auditable pipeline.
            </p>

            <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
              <Link to="/signup">
                <Button size="lg" className="group bg-foreground text-background hover:bg-foreground/90 h-12 px-6 text-[14px] font-medium">
                  Try the live demo
                  <ArrowRight className="w-4 h-4 ml-2 transition-transform group-hover:translate-x-0.5" />
                </Button>
              </Link>
              <a href="https://github.com/Vansh150705/ThreatBrain" target="_blank" rel="noopener noreferrer">
                <Button size="lg" variant="outline" className="h-12 px-6 text-[14px] font-medium border-border hover:border-foreground/25 bg-white">
                  <GithubIcon className="w-4 h-4 mr-2" />
                  View on GitHub
                </Button>
              </a>
            </div>

            <div className="mt-6 font-mono text-[12px] text-muted-foreground">
              <span className="text-signal">free →</span> your own isolated workspace · no email confirmation
            </div>

            <div className="mt-12 hidden sm:flex flex-col items-center gap-2" aria-hidden>
              <span className="font-mono text-[10px] uppercase tracking-[0.3em] text-muted-foreground/70">Scroll</span>
              <span className="w-px h-7 bg-foreground/20 animate-pulse" />
            </div>
          </motion.div>
        </div>

        {/* telemetry rail */}
        <div className="relative border-t border-border">
          <div className="max-w-[1200px] mx-auto px-6 py-4 flex flex-wrap items-center gap-x-10 gap-y-2 font-mono text-[11.5px] text-muted-foreground">
            <div>resolved today <span className="text-foreground font-semibold tabular">154</span></div>
            <div className="hidden sm:block w-px h-4 bg-border" aria-hidden />
            <div>last incident <span className="text-foreground font-semibold">INC-FCBD7B · 11.5s</span></div>
            <div className="hidden sm:block w-px h-4 bg-border" aria-hidden />
            <div>detection to dashboard <span className="text-foreground font-semibold">~200ms</span></div>
            <div className="ml-auto hidden md:flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-signal" />
              <span>all systems operational</span>
            </div>
          </div>
        </div>
      </section>

      {/* sources marquee */}
      <SourceMarquee />

      {/* showcase */}
      <section id="showcase" className="relative">
        <div className="max-w-[1200px] mx-auto px-6 pt-16 pb-20 sm:pt-24 sm:pb-28">
          <div className="grid md:grid-cols-12 gap-8 mb-14 items-end">
            <Reveal className="md:col-span-7">
              <div className="font-mono text-[11px] uppercase tracking-[0.16em] text-signal font-semibold mb-4">
                Watch it work
              </div>
              <h2 className="title-serif text-[clamp(34px,4vw,48px)] tracking-[-0.03em] leading-[1.04] text-foreground">
                One alert in.{" "}
                <em className="font-serif italic font-medium text-signal">A full investigation out.</em>
              </h2>
            </Reveal>
            <Reveal delay={0.08} className="md:col-span-5">
              <p className="text-[15.5px] text-muted-foreground leading-[1.65]">
                The console below runs the real six-agent sequence on a sample
                alert. The dossier on the right fills in as each specialist
                reports. It is exactly what lands in your dashboard.
              </p>
            </Reveal>
          </div>

          {/* panel breaks the grid to the right on wide screens */}
          <Reveal delay={0.05} className="lg:-mr-14 xl:-mr-20">
            <PipelineShowcase />
          </Reveal>
        </div>
      </section>

      {/* features (bento) */}
      <section id="features" className="border-t border-border">
        <div className="max-w-[1200px] mx-auto px-6 py-16 sm:py-24 lg:py-28">
          <div className="grid md:grid-cols-12 gap-8 mb-14 items-end">
            <Reveal className="md:col-span-7">
              <div className="font-mono text-[11px] uppercase tracking-[0.16em] text-signal font-semibold mb-4">
                Built for scrutiny
              </div>
              <h2 className="title-serif text-[clamp(34px,4vw,48px)] tracking-[-0.03em] leading-[1.04] text-foreground">
                Security software that{" "}
                <em className="font-serif italic font-medium text-signal">survives an audit.</em>
              </h2>
            </Reveal>
            <Reveal delay={0.08} className="md:col-span-5">
              <p className="text-[15.5px] text-muted-foreground leading-[1.65]">
                Every layer assumes a hostile reader: a regulator, a red team,
                or a tenant trying to see another tenant's data.
              </p>
            </Reveal>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
            {/* audit trail card */}
            <BentoCard className="md:col-span-4">
              <h3 className="text-[16px] font-semibold tracking-[-0.015em]">Append-only audit trail</h3>
              <p className="text-[14px] text-muted-foreground mt-2 leading-[1.65] max-w-md">
                Postgres triggers physically reject UPDATE and DELETE on audit
                logs. Every agent decision stays verifiable, forever.
              </p>
              <div className="mt-5 rounded-lg border border-border bg-muted/30 p-4 font-mono text-[11.5px] leading-[1.9] overflow-x-auto">
                <div className="text-muted-foreground">12:04:11 <span className="text-foreground">INSERT</span> audit_logs · triage.verdict · <span className="text-signal">ok</span></div>
                <div className="text-muted-foreground">12:04:13 <span className="text-foreground">INSERT</span> audit_logs · intel.enrichment · <span className="text-signal">ok</span></div>
                <div className="text-muted-foreground">12:05:02 <span className="text-foreground">UPDATE</span> audit_logs · n/a · <span className="text-severity-critical">rejected by trigger</span></div>
              </div>
            </BentoCard>

            {/* rls */}
            <BentoCard className="md:col-span-2" delay={0.05}>
              <h3 className="text-[16px] font-semibold tracking-[-0.015em]">Tenant isolation in the database</h3>
              <p className="text-[14px] text-muted-foreground mt-2 leading-[1.65]">
                Row-Level Security binds every query to the JWT's organization
                claim. Buggy app code cannot leak cross-tenant data.
              </p>
              <div className="mt-5 rounded-lg border border-border bg-muted/30 p-4 font-mono text-[11.5px] leading-[1.8] overflow-x-auto">
                <div className="text-muted-foreground">create policy tenant_read</div>
                <div className="text-muted-foreground pl-3">using (org_id = <span className="text-foreground">auth.org()</span>);</div>
              </div>
            </BentoCard>

            {/* mitre */}
            <BentoCard className="md:col-span-2" delay={0.05}>
              <h3 className="text-[16px] font-semibold tracking-[-0.015em]">Speaks MITRE ATT&CK</h3>
              <p className="text-[14px] text-muted-foreground mt-2 leading-[1.65]">
                Verdicts arrive pre-mapped to techniques your team already uses
                in reports and tabletop exercises.
              </p>
              <div className="mt-5 flex flex-wrap gap-1.5 font-mono text-[11px]">
                {["T1078", "T1566", "T1550.001", "T1098"].map((t) => (
                  <span key={t} className="px-2 py-1 rounded border border-border text-muted-foreground">{t}</span>
                ))}
                <span className="px-2 py-1 rounded border border-dashed border-border text-muted-foreground/60">+38 more</span>
              </div>
            </BentoCard>

            {/* human in the loop */}
            <BentoCard className="md:col-span-2" delay={0.1}>
              <h3 className="text-[16px] font-semibold tracking-[-0.015em]">Recommends, never executes</h3>
              <p className="text-[14px] text-muted-foreground mt-2 leading-[1.65]">
                The Response agent proposes a playbook. Real actions need an
                admin role plus per-playbook authorization.
              </p>
              <div className="mt-5 flex items-center justify-between rounded-lg border border-border bg-muted/30 px-4 py-3">
                <span className="font-mono text-[11.5px] text-muted-foreground">revoke_oauth_grant</span>
                <span className="font-mono text-[10px] uppercase tracking-[0.1em] px-2 py-1 rounded border border-severity-medium/35 text-severity-medium bg-severity-medium/[0.07]">
                  awaiting admin
                </span>
              </div>
            </BentoCard>

            {/* schemas */}
            <BentoCard className="md:col-span-2" delay={0.1}>
              <h3 className="text-[16px] font-semibold tracking-[-0.015em]">No free-form LLM output</h3>
              <p className="text-[14px] text-muted-foreground mt-2 leading-[1.65]">
                Every model call is fenced by a strict Pydantic schema. Malformed
                output is rejected, not interpreted.
              </p>
              <div className="mt-5 rounded-lg border border-border bg-muted/30 p-4 font-mono text-[11.5px] leading-[1.8] overflow-x-auto">
                <div className="text-muted-foreground">class <span className="text-foreground">TriageVerdict</span>(BaseModel):</div>
                <div className="text-muted-foreground pl-3">severity: Severity</div>
                <div className="text-muted-foreground pl-3">technique: MitreId</div>
              </div>
            </BentoCard>

            {/* crew card */}
            <BentoCard className="md:col-span-6" delay={0.12}>
              <div className="flex flex-col lg:flex-row lg:items-center gap-6">
                <div className="lg:w-72 flex-shrink-0">
                  <h3 className="text-[16px] font-semibold tracking-[-0.015em]">Six specialists, one pipeline</h3>
                  <p className="text-[14px] text-muted-foreground mt-2 leading-[1.65]">
                    Each agent has one job and a strict contract with the next.
                  </p>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 flex-1">
                  {CREW.map((c) => {
                    const Portrait = c.portrait;
                    return (
                      <div key={c.name} className="flex flex-col items-start gap-2">
                        <div className="w-11 h-11 rounded-full bg-muted overflow-hidden ring-1 ring-border">
                          <Portrait className="w-full h-full" />
                        </div>
                        <div>
                          <div className="text-[13px] font-medium tracking-[-0.01em]">{c.name}</div>
                          <div className="font-mono text-[9.5px] uppercase tracking-[0.08em] text-muted-foreground mt-0.5">{c.agent}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </BentoCard>
          </div>
        </div>
      </section>

      {/* how it works */}
      <section id="how" className="border-t border-border">
        <div className="max-w-[1200px] mx-auto px-6 py-16 sm:py-24 lg:py-28 grid lg:grid-cols-12 gap-12">
          <div className="lg:col-span-4">
            <div className="lg:sticky lg:top-28">
              <Reveal>
                <div className="font-mono text-[11px] uppercase tracking-[0.16em] text-signal font-semibold mb-4">
                  How it works
                </div>
                <h2 className="title-serif text-[clamp(34px,4vw,48px)] tracking-[-0.03em] leading-[1.04] text-foreground">
                  From alert to{" "}
                  <em className="font-serif italic font-medium text-signal">answer.</em>
                </h2>
                <p className="text-[15.5px] text-muted-foreground mt-5 leading-[1.65]">
                  No playbook authoring, no rule tuning. Point your alert
                  sources at one endpoint and the crew takes it from there.
                </p>
              </Reveal>
            </div>
          </div>

          <div className="lg:col-span-8 lg:border-l lg:border-border lg:pl-14">
            {[
              { num: "01", title: "An alert arrives", desc: "A SIEM, firewall, or cloud audit log fires an event. ThreatBrain ingests it through a single FastAPI endpoint, with no connectors to babysit." },
              { num: "02", title: "The crew investigates", desc: "Six specialized agents run in sequence: Triage, Threat Intel, Investigation, Response, Forensics, then Compliance. Each one passes a typed verdict to the next." },
              { num: "03", title: "An incident, documented", desc: "A complete incident lands in the dashboard with attribution, kill chain, recommended playbook, and a chain-of-custody timeline a regulator can read." },
            ].map((s, i) => (
              <Reveal key={s.num} delay={i * 0.06}>
                <div className={`py-10 ${i > 0 ? "border-t border-border" : ""}`}>
                  <div className="flex items-baseline gap-6">
                    <span className="font-mono text-[12px] text-signal font-semibold tabular">{s.num}</span>
                    <div>
                      <h3 className="text-[20px] font-semibold tracking-[-0.02em]">{s.title}</h3>
                      <p className="text-[15px] text-muted-foreground mt-2.5 leading-[1.65] max-w-xl">{s.desc}</p>
                    </div>
                  </div>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* attack simulator */}
      <section id="simulate" className="border-t border-border">
        <div className="max-w-[1200px] mx-auto px-6 py-16 sm:py-24 lg:py-28">
          <div className="grid md:grid-cols-12 gap-8 mb-12 items-end">
            <Reveal className="md:col-span-7">
              <div className="font-mono text-[11px] uppercase tracking-[0.16em] text-signal font-semibold mb-4">
                Try it yourself
              </div>
              <h2 className="title-serif text-[clamp(34px,4vw,48px)] tracking-[-0.03em] leading-[1.04] text-foreground">
                Throw an attack at it.{" "}
                <em className="font-serif italic font-medium text-signal">Right now.</em>
              </h2>
            </Reveal>
            <Reveal delay={0.08} className="md:col-span-5">
              <p className="text-[15.5px] text-muted-foreground leading-[1.65]">
                Pick a scenario and watch the crew take it apart in real time.
                The same sequence runs against every alert in production.
              </p>
            </Reveal>
          </div>

          <Reveal delay={0.05}>
            <AttackSimulator />
          </Reveal>
        </div>
      </section>

      {/* final cta */}
      <section className="border-t border-border relative overflow-hidden">
        <div className="lp-grid absolute inset-0 pointer-events-none rotate-180" aria-hidden />
        <div
          className="absolute inset-x-0 bottom-0 h-[420px] pointer-events-none bg-[radial-gradient(ellipse_60%_70%_at_50%_100%,oklch(0.52_0.13_158/0.07),transparent_70%)]"
          aria-hidden
        />
        <div className="relative max-w-[1200px] mx-auto px-6 py-20 sm:py-28 lg:py-32 text-center">
          <Reveal>
            <div className="inline-flex items-center justify-center gap-2 px-4 py-1.5 rounded-full border border-signal/25 bg-signal/[0.05] font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground mb-8">
              <span className="w-1.5 h-1.5 rounded-full bg-signal animate-pulse" />
              <span className="text-foreground font-semibold">Get started</span>
            </div>

            <h2 className="title-serif text-[clamp(40px,6vw,76px)] tracking-[-0.035em] leading-[1.02] text-foreground max-w-4xl mx-auto">
              Your first investigation is{" "}
              <em className="font-serif italic font-medium text-signal">fifteen seconds away.</em>
            </h2>

            <p className="text-[16px] lg:text-[17px] text-muted-foreground mt-7 leading-[1.65] max-w-xl mx-auto">
              Spin up your own isolated workspace with seeded threat data and
              six agents on duty, or read the code first.
            </p>

            <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
              <Link to="/signup">
                <Button size="lg" className="group bg-foreground text-background hover:bg-foreground/90 h-12 px-7 text-[14px] font-medium">
                  Create your workspace
                  <ArrowRight className="w-4 h-4 ml-2 transition-transform group-hover:translate-x-0.5" />
                </Button>
              </Link>
              <a href="https://github.com/Vansh150705/ThreatBrain" target="_blank" rel="noopener noreferrer">
                <Button size="lg" variant="outline" className="h-12 px-7 text-[14px] font-medium border-border hover:border-foreground/25 bg-white">
                  <GithubIcon className="w-4 h-4 mr-2" />
                  View on GitHub
                </Button>
              </a>
            </div>

            <div className="mt-9 flex flex-wrap items-center justify-center gap-x-8 gap-y-2 font-mono text-[11.5px] text-muted-foreground">
              <span className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-signal" />
                free
              </span>
              <span className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-signal" />
                isolated workspace
              </span>
              <span className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-signal" />
                no email confirmation
              </span>
            </div>
          </Reveal>
        </div>
      </section>

      {/* footer */}
      <footer className="border-t border-border">
        <div className="max-w-[1200px] mx-auto px-6 py-10 flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-2.5">
            <div className="w-5 h-5 text-foreground">
              <LogoMark className="w-full h-full" />
            </div>
            <span className="font-semibold text-[14px] tracking-[-0.02em]">ThreatBrain</span>
            <span className="text-[12px] text-muted-foreground ml-2">© 2026 · Built by Vansh Mahajan · MIT License</span>
          </div>
          <div className="flex items-center gap-7 text-[13px] text-muted-foreground">
            <a href="#showcase" className="lp-underline hover:text-foreground transition-colors">Live demo</a>
            <a href="#features" className="lp-underline hover:text-foreground transition-colors">Features</a>
            <a
              href="https://github.com/Vansh150705/ThreatBrain"
              target="_blank"
              rel="noopener noreferrer"
              className="lp-underline hover:text-foreground transition-colors"
            >
              GitHub
            </a>
            <div className="flex items-center gap-2 font-mono text-[11px]">
              <span className="w-1.5 h-1.5 rounded-full bg-signal" />
              <span>operational</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
