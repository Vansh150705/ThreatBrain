import { useEffect, useRef, useState } from "react";
import { motion, useInView, useAnimation, useScroll, useTransform } from "framer-motion";
import { Link, Navigate } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";

// ============================================================================
// BITMOJI PORTRAITS — refined SVG characters
// ============================================================================

function OliviaPortrait({ size = 96 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 96 96" fill="none">
      {/* shoulders */}
      <ellipse cx="48" cy="86" rx="32" ry="18" fill="#b8362a" />
      <path d="M28 80 Q48 72 68 80 L68 96 L28 96 Z" fill="#9a2c22" />
      {/* neck */}
      <rect x="42" y="58" width="12" height="10" fill="#f0c8a0" />
      {/* head */}
      <ellipse cx="48" cy="42" rx="22" ry="24" fill="#f0c8a0" />
      {/* hair — fire-styled, swept */}
      <path
        d="M26 38 Q26 18 48 16 Q70 18 70 38 L70 32 Q66 22 48 22 Q30 22 26 32 Z"
        fill="#3a2924"
      />
      <path d="M28 36 Q30 26 38 22 L34 30 Z" fill="#2a1814" />
      <path d="M58 22 Q66 26 68 36 L62 30 Z" fill="#2a1814" />
      {/* fire helmet emblem on shirt */}
      <circle cx="48" cy="88" r="6" fill="#fbf8f1" opacity="0.9" />
      <path d="M44 87 Q48 84 52 87 L52 90 L44 90 Z" fill="#b8362a" />
      {/* eyes */}
      <ellipse cx="40" cy="42" rx="3" ry="3.5" fill="#fff" />
      <ellipse cx="56" cy="42" rx="3" ry="3.5" fill="#fff" />
      <circle cx="40.5" cy="43" r="1.8" fill="#1a1a1f" />
      <circle cx="56.5" cy="43" r="1.8" fill="#1a1a1f" />
      <circle cx="41" cy="42.5" r="0.6" fill="#fff" />
      <circle cx="57" cy="42.5" r="0.6" fill="#fff" />
      {/* brows */}
      <path d="M36 36 Q40 34 44 36" stroke="#3a2924" strokeWidth="1.8" strokeLinecap="round" fill="none" />
      <path d="M52 36 Q56 34 60 36" stroke="#3a2924" strokeWidth="1.8" strokeLinecap="round" fill="none" />
      {/* mouth — confident slight smirk */}
      <path d="M42 52 Q48 56 54 52" stroke="#1a1a1f" strokeWidth="1.8" strokeLinecap="round" fill="none" />
      {/* cheek tint */}
      <ellipse cx="36" cy="50" rx="3" ry="2" fill="#e89a85" opacity="0.5" />
      <ellipse cx="60" cy="50" rx="3" ry="2" fill="#e89a85" opacity="0.5" />
      {/* clipboard accessory */}
      <rect x="68" y="62" width="14" height="20" rx="1.5" fill="#f5e6cd" transform="rotate(12 75 72)" />
      <line x1="71" y1="68" x2="80" y2="70" stroke="#1a1a1f" strokeWidth="1" />
      <line x1="70" y1="72" x2="79" y2="74" stroke="#1a1a1f" strokeWidth="1" />
      <line x1="69" y1="76" x2="78" y2="78" stroke="#1a1a1f" strokeWidth="1" />
    </svg>
  );
}

function HenryPortrait({ size = 96 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 96 96" fill="none">
      <ellipse cx="48" cy="86" rx="32" ry="18" fill="#b86a1f" />
      <path d="M28 80 Q48 72 68 80 L68 96 L28 96 Z" fill="#945118" />
      <rect x="42" y="58" width="12" height="10" fill="#f3d4a0" />
      <ellipse cx="48" cy="44" rx="22" ry="24" fill="#f3d4a0" />
      {/* detective fedora */}
      <ellipse cx="48" cy="32" rx="28" ry="4" fill="#3a2010" />
      <path d="M28 30 Q28 14 48 14 Q68 14 68 30 L68 26 Q60 18 48 18 Q36 18 28 26 Z" fill="#5a3a1a" />
      <ellipse cx="48" cy="22" rx="20" ry="5" fill="#3a2010" />
      <rect x="32" y="28" width="32" height="3" fill="#1a1a1f" opacity="0.6" />
      {/* eyes */}
      <ellipse cx="40" cy="46" rx="3" ry="3.5" fill="#fff" />
      <ellipse cx="56" cy="46" rx="3" ry="3.5" fill="#fff" />
      <circle cx="40.5" cy="47" r="1.8" fill="#1a1a1f" />
      <circle cx="56.5" cy="47" r="1.8" fill="#1a1a1f" />
      <circle cx="41" cy="46.5" r="0.6" fill="#fff" />
      <circle cx="57" cy="46.5" r="0.6" fill="#fff" />
      {/* brows — slightly furrowed, thinking */}
      <path d="M36 40 Q40 38 44 40" stroke="#3a2010" strokeWidth="1.8" strokeLinecap="round" fill="none" />
      <path d="M52 40 Q56 38 60 40" stroke="#3a2010" strokeWidth="1.8" strokeLinecap="round" fill="none" />
      {/* mustache */}
      <path d="M38 54 Q44 56 48 54 Q52 56 58 54" stroke="#3a2010" strokeWidth="2.5" strokeLinecap="round" fill="none" />
      <path d="M42 55 Q48 58 54 55" stroke="#1a1a1f" strokeWidth="1.4" strokeLinecap="round" fill="none" />
      {/* magnifying glass */}
      <circle cx="76" cy="66" r="9" fill="rgba(255,255,255,0.3)" stroke="#1a1a1f" strokeWidth="2" />
      <circle cx="76" cy="66" r="6" fill="rgba(184,106,31,0.2)" />
      <line x1="82.5" y1="72.5" x2="89" y2="79" stroke="#1a1a1f" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

function NathanPortrait({ size = 96 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 96 96" fill="none">
      <ellipse cx="48" cy="86" rx="32" ry="18" fill="#2a4d8a" />
      <path d="M28 80 Q48 72 68 80 L68 96 L28 96 Z" fill="#1e3a6e" />
      {/* shirt collar */}
      <path d="M38 70 L48 78 L58 70 L58 80 L38 80 Z" fill="#fbf8f1" />
      <rect x="42" y="58" width="12" height="10" fill="#d4b89a" />
      <ellipse cx="48" cy="44" rx="22" ry="24" fill="#d4b89a" />
      {/* tousled hair */}
      <path d="M26 40 Q26 16 48 16 Q70 16 70 40 L70 34 Q65 22 48 22 Q31 22 26 34 Z" fill="#1a1a1f" />
      <path d="M34 18 Q36 26 32 30 L30 22 Z" fill="#0a0a0f" />
      <path d="M58 18 Q60 26 64 30 L62 22 Z" fill="#0a0a0f" />
      {/* glasses — square */}
      <rect x="34" y="42" width="11" height="9" rx="1.5" fill="none" stroke="#1a1a1f" strokeWidth="1.8" />
      <rect x="51" y="42" width="11" height="9" rx="1.5" fill="none" stroke="#1a1a1f" strokeWidth="1.8" />
      <line x1="45" y1="46" x2="51" y2="46" stroke="#1a1a1f" strokeWidth="1.8" />
      {/* eyes behind glasses */}
      <circle cx="39.5" cy="46.5" r="1.5" fill="#1a1a1f" />
      <circle cx="56.5" cy="46.5" r="1.5" fill="#1a1a1f" />
      {/* small slight smile */}
      <path d="M42 56 Q48 58 54 56" stroke="#1a1a1f" strokeWidth="1.8" strokeLinecap="round" fill="none" />
      <ellipse cx="36" cy="54" rx="3" ry="2" fill="#d49a85" opacity="0.5" />
      <ellipse cx="60" cy="54" rx="3" ry="2" fill="#d49a85" opacity="0.5" />
      {/* connection dots constellation on shirt */}
      <circle cx="34" cy="86" r="2" fill="#fbf8f1" />
      <circle cx="48" cy="92" r="2" fill="#fbf8f1" />
      <circle cx="62" cy="86" r="2" fill="#fbf8f1" />
      <line x1="34" y1="86" x2="48" y2="92" stroke="#fbf8f1" strokeWidth="0.8" opacity="0.7" />
      <line x1="48" y1="92" x2="62" y2="86" stroke="#fbf8f1" strokeWidth="0.8" opacity="0.7" />
      <line x1="34" y1="86" x2="62" y2="86" stroke="#fbf8f1" strokeWidth="0.8" opacity="0.7" />
    </svg>
  );
}

function RachelPortrait({ size = 96 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 96 96" fill="none">
      <ellipse cx="48" cy="86" rx="32" ry="18" fill="#5e3a8a" />
      <path d="M28 80 Q48 72 68 80 L68 96 L28 96 Z" fill="#4a2d6e" />
      <rect x="42" y="58" width="12" height="10" fill="#e8c8a0" />
      <ellipse cx="48" cy="44" rx="22" ry="24" fill="#e8c8a0" />
      {/* long wavy hair */}
      <path d="M24 50 Q22 20 48 16 Q74 20 72 50 L70 36 Q66 22 48 22 Q30 22 26 36 Z" fill="#3a2059" />
      <path d="M26 50 Q24 64 32 76 L28 56 Z" fill="#2a1545" />
      <path d="M70 50 Q72 64 64 76 L68 56 Z" fill="#2a1545" />
      {/* eyes — alert */}
      <ellipse cx="40" cy="44" rx="3" ry="3.5" fill="#fff" />
      <ellipse cx="56" cy="44" rx="3" ry="3.5" fill="#fff" />
      <circle cx="40.5" cy="45" r="1.8" fill="#1a1a1f" />
      <circle cx="56.5" cy="45" r="1.8" fill="#1a1a1f" />
      <circle cx="41" cy="44.5" r="0.6" fill="#fff" />
      <circle cx="57" cy="44.5" r="0.6" fill="#fff" />
      {/* brows — focused */}
      <path d="M36 38 Q40 36 44 38" stroke="#2a1545" strokeWidth="1.8" strokeLinecap="round" fill="none" />
      <path d="M52 38 Q56 36 60 38" stroke="#2a1545" strokeWidth="1.8" strokeLinecap="round" fill="none" />
      <path d="M42 54 Q48 57 54 54" stroke="#1a1a1f" strokeWidth="1.8" strokeLinecap="round" fill="none" />
      <ellipse cx="36" cy="52" rx="3" ry="2" fill="#e89a85" opacity="0.5" />
      <ellipse cx="60" cy="52" rx="3" ry="2" fill="#e89a85" opacity="0.5" />
      {/* small shield emblem */}
      <path d="M40 84 L48 80 L56 84 L56 92 Q48 97 40 92 Z" fill="#fbf8f1" />
      <path d="M44 87 L47 90 L52 84" stroke="#5e3a8a" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" fill="none" />
    </svg>
  );
}

function FrankPortrait({ size = 96 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 96 96" fill="none">
      <ellipse cx="48" cy="86" rx="32" ry="18" fill="#1f6663" />
      <path d="M28 80 Q48 72 68 80 L68 96 L28 96 Z" fill="#175450" />
      {/* lab coat */}
      <path d="M30 78 L48 82 L66 78 L66 96 L30 96 Z" fill="#fbf8f1" />
      <line x1="48" y1="82" x2="48" y2="96" stroke="#d2e8e4" strokeWidth="1" />
      <rect x="42" y="58" width="12" height="10" fill="#e8c8a0" />
      <ellipse cx="48" cy="44" rx="22" ry="24" fill="#e8c8a0" />
      {/* hair — neat side part */}
      <path d="M26 36 Q28 18 48 16 Q68 18 70 36 L70 30 Q60 20 48 20 Q34 20 26 30 Z" fill="#1a1a1f" />
      <path d="M28 32 Q34 24 50 24 L42 30 Z" fill="#0a0a0f" />
      {/* lab goggles */}
      <rect x="22" y="40" width="52" height="3" fill="#1a1a1f" rx="1.5" />
      <circle cx="40" cy="44" r="5.5" fill="rgba(210,232,228,0.4)" stroke="#1a1a1f" strokeWidth="2" />
      <circle cx="56" cy="44" r="5.5" fill="rgba(210,232,228,0.4)" stroke="#1a1a1f" strokeWidth="2" />
      <line x1="45.5" y1="44" x2="50.5" y2="44" stroke="#1a1a1f" strokeWidth="2" />
      <circle cx="40" cy="44.5" r="1.5" fill="#1a1a1f" />
      <circle cx="56" cy="44.5" r="1.5" fill="#1a1a1f" />
      {/* mouth */}
      <path d="M42 55 Q48 57 54 55" stroke="#1a1a1f" strokeWidth="1.8" strokeLinecap="round" fill="none" />
      {/* test tube */}
      <rect x="68" y="64" width="10" height="20" rx="1" fill="#d2e8e4" stroke="#1a1a1f" strokeWidth="1.5" />
      <rect x="67" y="62" width="12" height="4" fill="#1a1a1f" rx="1" />
      <rect x="69" y="74" width="8" height="9" fill="#1f6663" opacity="0.7" />
      <circle cx="72" cy="76" r="1" fill="#fff" opacity="0.8" />
    </svg>
  );
}

function ClairePortrait({ size = 96 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 96 96" fill="none">
      <ellipse cx="48" cy="86" rx="32" ry="18" fill="#2b6e3e" />
      <path d="M28 80 Q48 72 68 80 L68 96 L28 96 Z" fill="#1f5430" />
      {/* judge's collar */}
      <path d="M34 78 L48 82 L62 78 L62 90 L34 90 Z" fill="#fbf8f1" />
      <line x1="48" y1="82" x2="48" y2="90" stroke="#2b6e3e" strokeWidth="1.5" />
      <rect x="42" y="58" width="12" height="10" fill="#e8c8a0" />
      <ellipse cx="48" cy="44" rx="22" ry="24" fill="#e8c8a0" />
      {/* hair — bob */}
      <path d="M24 44 Q22 18 48 16 Q74 18 72 44 L70 32 Q66 22 48 22 Q30 22 26 32 Z" fill="#3a2924" />
      <path d="M24 44 Q28 56 36 56 L30 48 Z" fill="#2a1814" />
      <path d="M72 44 Q68 56 60 56 L66 48 Z" fill="#2a1814" />
      {/* glasses — round, reading */}
      <circle cx="40" cy="46" r="5" fill="none" stroke="#1a1a1f" strokeWidth="1.8" />
      <circle cx="56" cy="46" r="5" fill="none" stroke="#1a1a1f" strokeWidth="1.8" />
      <line x1="45" y1="46" x2="51" y2="46" stroke="#1a1a1f" strokeWidth="1.8" />
      <circle cx="40" cy="46.5" r="1.5" fill="#1a1a1f" />
      <circle cx="56" cy="46.5" r="1.5" fill="#1a1a1f" />
      {/* small smile */}
      <path d="M42 56 Q48 59 54 56" stroke="#1a1a1f" strokeWidth="1.8" strokeLinecap="round" fill="none" />
      <ellipse cx="36" cy="54" rx="3" ry="2" fill="#d49a85" opacity="0.5" />
      <ellipse cx="60" cy="54" rx="3" ry="2" fill="#d49a85" opacity="0.5" />
      {/* gavel accessory */}
      <rect x="68" y="68" width="14" height="6" rx="1" fill="#5a3a1a" transform="rotate(20 75 71)" />
      <rect x="71" y="74" width="3" height="14" fill="#3a2010" transform="rotate(20 73 81)" />
    </svg>
  );
}

// ============================================================================
// LOGO
// ============================================================================
function Logo({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <path
        d="M12 2 L20 5 L20 12 C20 17 16 21 12 22 C8 21 4 17 4 12 L4 5 Z"
        fill="#1a1a1f"
      />
      <circle cx="9" cy="9" r="1.4" fill="#fdfbf5" />
      <circle cx="15" cy="9" r="1.4" fill="#fdfbf5" />
      <circle cx="12" cy="14" r="1.4" fill="#fdfbf5" />
      <line x1="9" y1="9" x2="15" y2="9" stroke="#fdfbf5" strokeWidth="0.6" />
      <line x1="9" y1="9" x2="12" y2="14" stroke="#fdfbf5" strokeWidth="0.6" />
      <line x1="15" y1="9" x2="12" y2="14" stroke="#fdfbf5" strokeWidth="0.6" />
    </svg>
  );
}

// ============================================================================
// THE TEAM DATA
// ============================================================================
const TEAM = [
  {
    Portrait: OliviaPortrait,
    tag: "01 · FIRST RESPONDER",
    name: "Olivia",
    suffix: "the Sorter",
    role: "Triage · MITRE ATT&CK classifier",
    quote: "Show me the alert. I'll tell you how serious it is, and what playbook applies.",
    calls: 287,
    avg: "1.4s",
    bg: "bg-[#f5dcd6]",
  },
  {
    Portrait: HenryPortrait,
    tag: "02 · INVESTIGATOR",
    name: "Henry",
    suffix: "the Investigator",
    role: "Threat Intel · IP enrichment",
    quote: "That IP belongs to APT29. I've seen them before.",
    calls: 104,
    avg: "0.8s",
    bg: "bg-[#f5e6cd]",
  },
  {
    Portrait: NathanPortrait,
    tag: "03 · DETECTIVE",
    name: "Nathan",
    suffix: "the Connector",
    role: "Investigation · Correlation engine",
    quote: "These three events. Same attacker. They're not isolated.",
    calls: 421,
    avg: "2.6s",
    bg: "bg-[#d9e2f0]",
  },
  {
    Portrait: RachelPortrait,
    tag: "04 · DISPATCHER",
    name: "Rachel",
    suffix: "the Responder",
    role: "Response · Playbook recommender",
    quote: "I'll recommend a fix. But I won't run it. That's your call.",
    calls: 298,
    avg: "1.8s",
    bg: "bg-[#e4daee]",
  },
  {
    Portrait: FrankPortrait,
    tag: "05 · HISTORIAN",
    name: "Frank",
    suffix: "the Forensicist",
    role: "Forensics · Timeline reconstructor",
    quote: "Patient zero appeared at 02:14:14 UTC. Here's everything that followed.",
    calls: 612,
    avg: "3.1s",
    bg: "bg-[#d2e8e4]",
  },
  {
    Portrait: ClairePortrait,
    tag: "06 · NOTARY",
    name: "Claire",
    suffix: "the Compliance Officer",
    role: "Compliance · GDPR · PCI-DSS · SOC 2",
    quote: "Personal data was accessed. Article 33 applies. You have 72 hours.",
    calls: 374,
    avg: "2.5s",
    bg: "bg-[#dbe9dd]",
  },
];

// ============================================================================
// TEAM CARD with float + hover animation
// ============================================================================
function TeamCard({
  member,
  index,
}: {
  member: (typeof TEAM)[0];
  index: number;
}) {
  const { Portrait } = member;

  return (
    <motion.div
      initial={{ opacity: 0, y: 32 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-50px" }}
      transition={{
        duration: 0.7,
        delay: index * 0.08,
        ease: [0.16, 1, 0.3, 1],
      }}
      whileHover={{ y: -6 }}
      className="group bg-white border border-[#e8e1cf] rounded-[18px] p-7 transition-shadow duration-300 hover:shadow-[0_20px_48px_-20px_rgba(26,26,31,0.15)] hover:border-[#8a8a8f]"
    >
      <div className="flex gap-5 items-start">
        {/* Portrait with float animation */}
        <motion.div
          className={`flex-shrink-0 w-[88px] h-[88px] rounded-[18px] flex items-center justify-center ${member.bg} relative overflow-hidden`}
          animate={{ y: [0, -3, 0] }}
          transition={{
            duration: 3 + index * 0.3,
            repeat: Infinity,
            ease: "easeInOut",
            delay: index * 0.2,
          }}
          whileHover={{ rotate: -4, scale: 1.06 }}
        >
          <Portrait size={88} />
        </motion.div>

        <div className="flex-1 min-w-0 pt-1">
          <div className="font-mono text-[10px] text-[#8a8a8f] tracking-[0.1em] uppercase font-semibold mb-1.5">
            {member.tag}
          </div>
          <h3 className="font-serif text-[24px] font-semibold tracking-[-0.025em] text-[#1a1a1f] mb-0.5 leading-tight">
            {member.name}{" "}
            <span className="italic font-medium">{member.suffix}</span>
          </h3>
          <div className="text-[13px] text-[#535359] mb-3 font-medium">
            {member.role}
          </div>
          <p className="font-serif italic text-[15px] leading-[1.5] text-[#2d2d33] mb-3.5">
            "{member.quote}"
          </p>
          <div className="flex gap-3 pt-2.5 border-t border-[#e8e1cf] font-mono text-[11px] text-[#8a8a8f] font-medium">
            <span>
              <strong className="text-[#1a1a1f] font-semibold">
                {member.calls}
              </strong>{" "}
              calls / day
            </span>
            <span>
              <strong className="text-[#1a1a1f] font-semibold">
                {member.avg}
              </strong>{" "}
              avg
            </span>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

// ============================================================================
// CTA SECTION with animated mesh + word reveal
// ============================================================================
function CTASection() {
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true, margin: "-100px" });

  const words = ["Your", "first", "investigation"];
  const lineTwo = ["is", "two", "seconds", "away."];

  return (
    <section
      ref={ref}
      className="relative py-[120px] px-8 bg-[#1a1a1f] text-[#e8e4d9] text-center overflow-hidden"
    >
      {/* Animated gradient mesh */}
      <motion.div
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[1200px] h-[800px] pointer-events-none"
        animate={{
          rotate: [0, 360],
        }}
        transition={{ duration: 60, repeat: Infinity, ease: "linear" }}
      >
        <div
          className="absolute top-1/4 left-1/4 w-[500px] h-[500px] rounded-full"
          style={{
            background:
              "radial-gradient(circle, rgba(184,106,31,0.15) 0%, transparent 70%)",
          }}
        />
        <div
          className="absolute bottom-1/4 right-1/4 w-[500px] h-[500px] rounded-full"
          style={{
            background:
              "radial-gradient(circle, rgba(43,110,62,0.12) 0%, transparent 70%)",
          }}
        />
      </motion.div>

      {/* Subtle dot grid */}
      <div
        className="absolute inset-0 opacity-30 pointer-events-none"
        style={{
          backgroundImage:
            "radial-gradient(circle, rgba(255,255,255,0.05) 1px, transparent 1px)",
          backgroundSize: "32px 32px",
        }}
      />

      <div className="relative max-w-[760px] mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6 }}
          className="font-mono text-[11px] text-[#a8a395] tracking-[0.16em] uppercase font-semibold mb-5"
        >
          TRY IT NOW
        </motion.div>

        <h2 className="font-serif font-semibold text-[clamp(48px,7vw,88px)] leading-[0.96] tracking-[-0.04em] text-white mb-6">
          {words.map((word, i) => (
            <motion.span
              key={`w1-${i}`}
              initial={{ opacity: 0, y: 30, filter: "blur(8px)" }}
              animate={
                isInView
                  ? { opacity: 1, y: 0, filter: "blur(0px)" }
                  : {}
              }
              transition={{
                duration: 0.7,
                delay: i * 0.12,
                ease: [0.16, 1, 0.3, 1],
              }}
              className={`inline-block mr-[0.25em] ${
                word === "investigation" ? "italic font-medium" : ""
              }`}
            >
              {word}
            </motion.span>
          ))}
          <br />
          {lineTwo.map((word, i) => (
            <motion.span
              key={`w2-${i}`}
              initial={{ opacity: 0, y: 30, filter: "blur(8px)" }}
              animate={
                isInView
                  ? { opacity: 1, y: 0, filter: "blur(0px)" }
                  : {}
              }
              transition={{
                duration: 0.7,
                delay: 0.36 + i * 0.1,
                ease: [0.16, 1, 0.3, 1],
              }}
              className="inline-block mr-[0.25em]"
            >
              {word}
            </motion.span>
          ))}
        </h2>

        <motion.p
          initial={{ opacity: 0, y: 16 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6, delay: 0.8 }}
          className="text-[17px] text-[#c5beae] max-w-[480px] mx-auto mb-10 leading-[1.55]"
        >
          No signup. Demo credentials included. Trigger a real six-agent pipeline and watch every step resolve in real time.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6, delay: 0.95 }}
          className="flex gap-2.5 justify-center flex-wrap"
        >
          <motion.button
            whileHover={{ y: -2 }}
            whileTap={{ scale: 0.98 }}
            className="relative bg-[#fdfbf5] text-[#1a1a1f] px-[22px] py-[13px] rounded-full text-[14px] font-[550] tracking-[-0.01em] overflow-hidden"
          >
            <motion.div
              className="absolute inset-0 rounded-full opacity-0"
              style={{
                background:
                  "radial-gradient(circle, rgba(253,251,245,0.4) 0%, transparent 70%)",
              }}
              animate={{ opacity: [0, 0.6, 0] }}
              transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
            />
            <span className="relative">Open the demo →</span>
          </motion.button>
          <motion.button
            whileHover={{ y: -2, backgroundColor: "rgba(255,255,255,0.05)" }}
            whileTap={{ scale: 0.98 }}
            className="bg-transparent text-[#fdfbf5] px-[22px] py-[13px] border border-[#3a3833] rounded-full text-[14px] font-[550] tracking-[-0.01em] hover:border-[#5a574e] transition-colors"
          >
            View source on GitHub
          </motion.button>
        </motion.div>
      </div>
    </section>
  );
}

// ============================================================================
// MAIN LANDING PAGE
// ============================================================================
export default function LandingPage() {
  const { session } = useAuth();

  // Console animation state
  const [activeStep, setActiveStep] = useState(-1);
  const [doneSteps, setDoneSteps] = useState<number[]>([]);
  const [thinking, setThinking] = useState(false);
  const [showOutcome, setShowOutcome] = useState(false);
  const [stepCounter, setStepCounter] = useState("0 / 6");
  const [timeCounter, setTimeCounter] = useState("0.0s");
  const [progress, setProgress] = useState(0);

  const cumTimes = [1.4, 2.2, 4.8, 6.6, 9.7, 11.5];

  const runStory = () => {
    setActiveStep(-1);
    setDoneSteps([]);
    setThinking(false);
    setShowOutcome(false);
    setStepCounter("0 / 6");
    setTimeCounter("0.0s");
    setProgress(0);

    const thinkMs = 700;
    const revealMs = 1400;
    const stepTotal = thinkMs + revealMs;
    const timers: ReturnType<typeof setTimeout>[] = [];

    for (let i = 0; i < 6; i++) {
      timers.push(
        setTimeout(() => {
          setDoneSteps((prev) => Array.from(new Set([...prev, ...Array.from({ length: i }, (_, k) => k)])));
          setActiveStep(i);
          setThinking(true);
          setStepCounter(`${i + 1} / 6`);
        }, i * stepTotal)
      );

      timers.push(
        setTimeout(() => {
          setThinking(false);
          setTimeCounter(`${cumTimes[i].toFixed(1)}s`);
          setProgress(((i + 1) / 6) * 100);
        }, i * stepTotal + thinkMs)
      );
    }

    timers.push(
      setTimeout(() => {
        setActiveStep(-1);
        setDoneSteps([0, 1, 2, 3, 4, 5]);
        setShowOutcome(true);
      }, 6 * stepTotal)
    );

    timers.push(setTimeout(runStory, 6 * stepTotal + 5000));

    return () => timers.forEach(clearTimeout);
  };

  useEffect(() => {
    const t = setTimeout(runStory, 800);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (session) return <Navigate to="/dashboard" replace />;

  const steps = [
    {
      Portrait: OliviaPortrait,
      name: "Olivia",
      suffix: "the Sorter",
      took: "1.4s",
      avBg: "bg-[#f5dcd6]",
      avBorder: "border-[#b8362a]",
      finding: (
        <>
          This looks{" "}
          <span className="inline-flex items-center px-2 rounded-[5px] font-mono text-[11px] font-semibold bg-[#f5dcd6] text-[#b8362a] mx-0.5">
            high severity
          </span>
          . Pattern matches MITRE <strong>T1078</strong>, valid accounts being misused. Confidence 92 percent. Escalating.
        </>
      ),
    },
    {
      Portrait: HenryPortrait,
      name: "Henry",
      suffix: "the Investigator",
      took: "0.8s",
      avBg: "bg-[#f5e6cd]",
      avBorder: "border-[#b86a1f]",
      finding: (
        <>
          Checked the IP <strong>203.0.113.42</strong>. AbuseIPDB scores it{" "}
          <span className="inline-flex items-center px-2 rounded-[5px] font-mono text-[11px] font-semibold bg-[#f5dcd6] text-[#b8362a] mx-0.5">
            92/100
          </span>
          . Based in Russia. Fingerprint matches <strong>APT29</strong> (Cozy Bear).
        </>
      ),
    },
    {
      Portrait: NathanPortrait,
      name: "Nathan",
      suffix: "the Connector",
      took: "2.6s",
      avBg: "bg-[#d9e2f0]",
      avBorder: "border-[#2a4d8a]",
      finding: (
        <>
          Found <strong>3 related incidents</strong> from this actor in the last 24 hours. Grouping them under <strong>INC-FCBD7B</strong>.
        </>
      ),
    },
    {
      Portrait: RachelPortrait,
      name: "Rachel",
      suffix: "the Responder",
      took: "1.8s",
      avBg: "bg-[#e4daee]",
      avBorder: "border-[#5e3a8a]",
      finding: (
        <>
          Recommend the <strong>revoke OAuth grant</strong> playbook. Not executing. That needs an admin. Status:{" "}
          <span className="inline-flex items-center px-2 rounded-[5px] font-mono text-[11px] font-semibold bg-[#f5e6cd] text-[#b86a1f] mx-0.5">
            awaiting human
          </span>
          .
        </>
      ),
    },
    {
      Portrait: FrankPortrait,
      name: "Frank",
      suffix: "the Forensicist",
      took: "3.1s",
      avBg: "bg-[#d2e8e4]",
      avBorder: "border-[#1f6663]",
      finding: (
        <>
          Rebuilt the timeline. Patient zero: <strong>02:14:14 UTC</strong>. The attacker touched <strong>4 assets</strong> across 14 events. Full chain of custody saved.
        </>
      ),
    },
    {
      Portrait: ClairePortrait,
      name: "Claire",
      suffix: "the Compliance Officer",
      took: "2.5s",
      avBg: "bg-[#dbe9dd]",
      avBorder: "border-[#2b6e3e]",
      finding: (
        <>
          Personal data was accessed.{" "}
          <span className="inline-flex items-center px-2 rounded-[5px] font-mono text-[11px] font-semibold bg-[#d9e2f0] text-[#2a4d8a] mx-0.5">
            GDPR Article 33
          </span>{" "}
          requires regulator notification within <strong>72 hours</strong>. PCI-DSS doesn't apply.
        </>
      ),
    },
  ];

  return (
    <div className="bg-[#fdfbf5] text-[#2d2d33] font-sans antialiased min-h-screen">
      {/* Status strip */}
      <div className="bg-[#1a1a1f] text-[#e8e4d9] py-2.5 text-center text-[13px] font-medium">
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#7dd8a3] mr-2 align-[1px] animate-pulse" />
        <span>Live · 7 AI agents online · investigating in real time</span>
      </div>

      {/* Sticky nav */}
      <div className="sticky top-0 z-50 pt-[18px] px-8 bg-gradient-to-b from-[#fdfbf5] via-[#fdfbf5] to-transparent">
        <nav className="max-w-[1080px] mx-auto bg-white/90 backdrop-blur-xl border border-[#e8e1cf] rounded-full pl-[22px] pr-2 py-2 flex items-center justify-between shadow-sm">
          <div className="flex items-center gap-2.5">
            <Logo />
            <span className="font-serif font-semibold text-[18px] tracking-[-0.025em] text-[#1a1a1f]">
              ThreatBrain
            </span>
          </div>
          <div className="hidden md:flex gap-7 text-[14px] text-[#535359] font-medium">
            <a className="hover:text-[#1a1a1f] cursor-pointer transition-colors">The Team</a>
            <a className="hover:text-[#1a1a1f] cursor-pointer transition-colors">How It Works</a>
            <a className="hover:text-[#1a1a1f] cursor-pointer transition-colors">Architecture</a>
            <a className="hover:text-[#1a1a1f] cursor-pointer transition-colors">GitHub</a>
          </div>
          <Link
            to="/login"
            className="bg-[#1a1a1f] text-[#fdfbf5] px-[18px] py-[9px] rounded-full text-[13px] font-[550] tracking-[-0.01em] hover:-translate-y-0.5 hover:shadow-[0_8px_20px_-6px_rgba(26,26,31,0.35)] transition-all"
          >
            Open dashboard →
          </Link>
        </nav>
      </div>

      {/* HERO */}
      <section className="relative py-20 px-8 text-center overflow-hidden">
        <div
          className="absolute top-[30%] left-1/2 -translate-x-1/2 w-[900px] h-[500px] pointer-events-none"
          style={{
            background:
              "radial-gradient(ellipse, rgba(184,106,31,0.05) 0%, transparent 60%)",
          }}
        />
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6 }}
          className="relative font-mono text-[11px] text-[#8a8a8f] tracking-[0.16em] uppercase font-semibold mb-8 inline-block"
        >
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#2b6e3e] mr-2.5 align-[1px]" />
          POWERED BY GROQ · LLAMA 3.3 70B
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          className="relative font-serif font-semibold text-[clamp(56px,8.5vw,116px)] leading-[0.92] tracking-[-0.04em] text-[#1a1a1f] max-w-[1080px] mx-auto mb-8"
        >
          Your security team,
          <br />
          <span className="italic font-medium">always on duty.</span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.2, ease: [0.16, 1, 0.3, 1] }}
          className="relative text-[18px] leading-[1.55] text-[#535359] max-w-[600px] mx-auto mb-10"
        >
          When an alert comes in, ThreatBrain hands it to{" "}
          <strong className="text-[#1a1a1f] font-semibold">six specialized AI agents</strong>. They investigate together, decide, and file a complete report in about fifteen seconds. You see every step.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.35 }}
          className="relative flex gap-2.5 justify-center items-center mb-5 flex-wrap"
        >
          <button className="bg-[#1a1a1f] text-[#fdfbf5] px-[22px] py-[13px] rounded-full text-[14px] font-[550] tracking-[-0.01em] hover:-translate-y-0.5 hover:shadow-[0_12px_28px_-8px_rgba(26,26,31,0.35)] transition-all">
            Watch a live investigation →
          </button>
          <button className="bg-white text-[#1a1a1f] px-[22px] py-[13px] border border-[#e8e1cf] rounded-full text-[14px] font-[550] tracking-[-0.01em] hover:bg-[#f3eee2] hover:-translate-y-0.5 hover:border-[#8a8a8f] transition-all">
            ⭐ Star on GitHub
          </button>
        </motion.div>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="relative font-mono text-[12px] text-[#8a8a8f]"
        >
          demo · <span className="text-[#2d2d33] font-semibold">test@acme.example</span> /{" "}
          <span className="text-[#2d2d33] font-semibold">ThreatBrain123!</span>
        </motion.p>
      </section>

      {/* CONSOLE */}
      <section className="px-8 pb-24">
        <div className="max-w-[1080px] mx-auto bg-white border border-[#e8e1cf] rounded-[18px] overflow-hidden shadow-[0_1px_3px_rgba(26,26,31,0.03),0_24px_64px_-24px_rgba(26,26,31,0.15)] relative">
          {/* Head */}
          <div className="px-5 py-3.5 border-b border-[#e8e1cf] flex justify-between items-center">
            <div className="flex items-center gap-3.5">
              <div className="font-serif text-[16px] font-semibold text-[#1a1a1f] tracking-[-0.02em] flex items-center gap-2.5">
                <span className="relative">
                  <span className="absolute inset-[-4px] rounded-full bg-[rgba(184,54,42,0.35)] animate-ping" />
                  <span className="relative block w-1.5 h-1.5 rounded-full bg-[#b8362a]" />
                </span>
                Active <span className="italic font-medium">investigation</span>
              </div>
              <span className="font-mono text-[11px] text-[#8a8a8f] font-medium">incident #FCBD7B</span>
            </div>
            <div className="flex gap-1">
              <button className="font-mono text-[10px] text-[#1a1a1f] px-2.5 py-1.5 border border-[#8a8a8f] rounded-md bg-[#f3eee2] font-semibold">Story</button>
              <button className="font-mono text-[10px] text-[#8a8a8f] px-2.5 py-1.5 border border-[#e8e1cf] rounded-md bg-white font-semibold hover:bg-[#f3eee2]">Trace</button>
              <button className="font-mono text-[10px] text-[#8a8a8f] px-2.5 py-1.5 border border-[#e8e1cf] rounded-md bg-white font-semibold hover:bg-[#f3eee2]">Raw</button>
            </div>
          </div>

          {/* Alert banner */}
          <div className="px-5 py-4 border-b border-[#e8e1cf] flex items-center gap-3.5 relative" style={{ background: "linear-gradient(90deg, rgba(184,54,42,0.06) 0%, transparent 70%)" }}>
            <div className="absolute left-0 top-0 bottom-0 w-[3px] bg-[#b8362a]" />
            <div className="w-9 h-9 rounded-[10px] bg-[#f5dcd6] text-[#b8362a] flex items-center justify-center font-bold text-base flex-shrink-0">
              !
            </div>
            <div className="flex-1">
              <div className="text-[15px] font-semibold text-[#1a1a1f] tracking-[-0.015em] mb-0.5">
                Someone connected a new app to a corporate account
              </div>
              <div className="text-[13px] text-[#535359]">
                marcus.chen authorized access from{" "}
                <code className="font-mono text-[12px] text-[#1a1a1f] bg-[rgba(184,54,42,0.08)] px-1.5 rounded font-semibold">
                  203.0.113.42
                </code>{" "}
                · just now
              </div>
            </div>
            <div className="font-mono text-[11px] text-[#535359] px-2.5 py-1.5 bg-[#f3eee2] border border-[#e8e1cf] rounded-md flex-shrink-0 font-semibold">
              evt_9a3f
            </div>
          </div>

          {/* Narrative */}
          <div className="py-5 pb-2">
            {steps.map((step, i) => {
              const isActive = activeStep === i;
              const isDone = doneSteps.includes(i);
              const isVisible = isActive || isDone;
              const { Portrait } = step;

              return (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, y: 14 }}
                  animate={isVisible ? { opacity: 1, y: 0 } : { opacity: 0, y: 14 }}
                  transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
                  className="grid grid-cols-[56px_1fr] gap-4 px-6 pb-[18px] pt-2.5 relative"
                >
                  {/* Thread */}
                  {i < 5 && (
                    <div
                      className={`absolute left-[51px] top-[54px] -bottom-2.5 w-0.5 rounded-[1px] ${
                        isDone ? "bg-[#2b6e3e]" : isActive ? "bg-gradient-to-b from-[#1a1a1f] to-[#e8e1cf]" : "bg-[#e8e1cf]"
                      }`}
                    />
                  )}
                  {/* Avatar */}
                  <motion.div
                    animate={isActive ? { scale: 1.08, rotate: -3 } : { scale: 1, rotate: 0 }}
                    transition={{ type: "spring", stiffness: 300, damping: 20 }}
                    className={`w-11 h-11 rounded-[12px] flex items-center justify-center relative z-[2] flex-shrink-0 border-[1.5px] ${step.avBg} ${step.avBorder} ${isActive ? "shadow-[0_8px_20px_-6px_rgba(26,26,31,0.2)]" : ""}`}
                  >
                    <Portrait size={32} />
                    {isActive && (
                      <motion.div
                        className="absolute inset-[-6px] rounded-[14px] border-[1.5px] border-[#1a1a1f]"
                        animate={{ scale: [0.94, 1.18], opacity: [0.4, 0] }}
                        transition={{ duration: 1.4, repeat: Infinity, ease: "easeOut" }}
                      />
                    )}
                    {isDone && (
                      <div className="absolute -bottom-1 -right-1 w-[18px] h-[18px] bg-[#2b6e3e] text-white rounded-full text-[11px] flex items-center justify-center font-bold border-2 border-white">
                        ✓
                      </div>
                    )}
                  </motion.div>

                  {/* Body */}
                  <div className="pt-1 min-w-0">
                    <div className="flex items-baseline gap-2.5 mb-2 flex-wrap">
                      <span className="font-serif text-[18px] font-semibold text-[#1a1a1f] tracking-[-0.02em]">
                        {step.name}{" "}
                        <span className="italic font-medium text-[#535359] ml-1.5 text-[14px]">{step.suffix}</span>
                      </span>
                      <span className="font-mono text-[11px] text-[#8a8a8f] ml-auto font-medium">
                        took <strong className="text-[#1a1a1f] font-semibold">{step.took}</strong>
                      </span>
                    </div>
                    <div className={`border rounded-[12px] px-3.5 py-3 text-[14px] leading-[1.6] text-[#2d2d33] max-w-[640px] ${
                      isActive ? "bg-white border-[#8a8a8f] shadow-[0_4px_14px_-4px_rgba(26,26,31,0.08)]" : "bg-[#f3eee2] border-[#e8e1cf]"
                    }`}>
                      {isActive && thinking ? (
                        <div className="inline-flex gap-1 items-center py-1">
                          <span className="w-1.5 h-1.5 rounded-full bg-[#8a8a8f] animate-bounce" style={{ animationDelay: "0ms" }} />
                          <span className="w-1.5 h-1.5 rounded-full bg-[#8a8a8f] animate-bounce" style={{ animationDelay: "200ms" }} />
                          <span className="w-1.5 h-1.5 rounded-full bg-[#8a8a8f] animate-bounce" style={{ animationDelay: "400ms" }} />
                        </div>
                      ) : (
                        step.finding
                      )}
                    </div>
                  </div>
                </motion.div>
              );
            })}

            {/* Outcome */}
            <motion.div
              initial={{ opacity: 0, y: 14, scale: 0.98 }}
              animate={showOutcome ? { opacity: 1, y: 0, scale: 1 } : { opacity: 0, y: 14, scale: 0.98 }}
              transition={{ duration: 0.7, ease: [0.34, 1.56, 0.64, 1] }}
              className="mx-6 mt-3 mb-6 p-4 border border-[#2b6e3e] rounded-[14px]"
              style={{ background: "linear-gradient(135deg, rgba(43,110,62,0.08) 0%, rgba(43,110,62,0.02) 100%)" }}
            >
              <div className="flex items-center gap-3 mb-3.5">
                <div className="w-8 h-8 rounded-full bg-[#2b6e3e] text-white flex items-center justify-center text-base font-semibold flex-shrink-0">
                  ✓
                </div>
                <div>
                  <div className="font-serif text-[18px] font-semibold text-[#1a1a1f] tracking-[-0.02em]">
                    <em className="italic font-medium">Investigation</em> complete
                  </div>
                  <div className="text-[13px] text-[#535359] mt-0.5">
                    A full incident file is now in your queue, ready for human review
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-4 gap-2.5 pt-3.5 border-t border-[rgba(43,110,62,0.25)]">
                {[
                  { label: "Incident", val: "INC-FCBD7B" },
                  { label: "Priority", val: "P1" },
                  { label: "Actor", val: "APT29" },
                  { label: "Total time", val: "11.5s" },
                ].map((s) => (
                  <div key={s.label} className="text-center">
                    <div className="font-mono text-[10px] text-[#8a8a8f] tracking-[0.06em] uppercase font-semibold mb-1">
                      {s.label}
                    </div>
                    <div className="font-mono text-[15px] font-semibold text-[#1a1a1f] tracking-[-0.015em]">
                      {s.val}
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>
          </div>

          {/* Footer */}
          <div className="px-5 py-3 border-t border-[#e8e1cf] bg-[#f3eee2] flex justify-between items-center font-mono text-[11px] text-[#535359] font-medium">
            <div className="flex items-center gap-3.5">
              <span>
                step <strong className="text-[#1a1a1f] font-semibold">{stepCounter}</strong>
              </span>
              <div className="w-[120px] h-1 bg-[#e8e1cf] rounded-[2px] overflow-hidden">
                <div className="h-full bg-[#1a1a1f] rounded-[2px] transition-[width] duration-500 ease-out" style={{ width: `${progress}%` }} />
              </div>
              <span>
                <strong className="text-[#1a1a1f] font-semibold">{timeCounter}</strong>
              </span>
            </div>
            <button
              onClick={runStory}
              className="text-[11px] text-[#535359] px-3 py-1.5 border border-[#e8e1cf] rounded-full cursor-pointer bg-white font-mono font-medium hover:bg-[#f3eee2] hover:border-[#8a8a8f] hover:text-[#1a1a1f] transition-all inline-flex items-center gap-1.5 group"
            >
              <span className="inline-block group-hover:-rotate-180 transition-transform duration-300">↻</span>{" "}
              replay
            </button>
          </div>
        </div>
      </section>

      {/* MEET THE TEAM */}
      <section className="py-24 pb-[120px]">
        <div className="max-w-[1240px] mx-auto px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.7 }}
            className="text-center mb-16"
          >
            <div className="font-mono text-[11px] text-[#8a8a8f] tracking-[0.16em] uppercase font-semibold mb-4.5">
              EVERY ALERT, FULLY STAFFED
            </div>
            <h2 className="font-serif font-semibold text-[clamp(42px,6vw,72px)] leading-[0.96] tracking-[-0.035em] text-[#1a1a1f] mb-4.5 max-w-[920px] mx-auto">
              Meet your <span className="italic font-medium">AI security crew</span>
            </h2>
            <p className="text-[17px] text-[#535359] max-w-[560px] mx-auto leading-[1.55]">
              Six specialists. Each one bounded, schema-strict, and named so you remember who did what.
            </p>
          </motion.div>

          <div className="grid md:grid-cols-2 gap-4 max-w-[1080px] mx-auto">
            {TEAM.map((member, i) => (
              <TeamCard key={member.name} member={member} index={i} />
            ))}
          </div>
        </div>
      </section>

      {/* DARK STATS STRIP */}
      <section className="bg-[#1a1a1f] text-[#e8e4d9] py-16">
        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
          variants={{
            hidden: { opacity: 0 },
            visible: { opacity: 1, transition: { staggerChildren: 0.1 } },
          }}
          className="grid grid-cols-2 md:grid-cols-4 max-w-[1080px] mx-auto px-8"
        >
          {[
            { val: "6", label: "AI Agents" },
            { val: "11.5", suffix: "s", label: "Avg Pipeline" },
            { val: "100", suffix: "%", label: "Audit Coverage" },
            { val: "∞", label: "Alerts Handled" },
          ].map((s, i) => (
            <motion.div
              key={s.label}
              variants={{
                hidden: { opacity: 0, y: 20 },
                visible: { opacity: 1, y: 0, transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] } },
              }}
              className={`text-center px-4 ${i < 3 ? "md:border-r border-white/10" : ""}`}
            >
              <div className="font-serif text-[64px] font-semibold tracking-[-0.04em] leading-none mb-2 text-white">
                {s.val}
                {s.suffix && <em className="italic font-medium">{s.suffix}</em>}
              </div>
              <div className="font-mono text-[11px] text-[#a8a395] tracking-[0.12em] uppercase font-semibold">
                {s.label}
              </div>
            </motion.div>
          ))}
        </motion.div>
      </section>

      {/* CASE STUDY */}
      <section className="py-[120px]">
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.7 }}
          className="max-w-[920px] mx-auto px-8"
        >
          <div className="font-mono text-[11px] text-[#8a8a8f] tracking-[0.16em] uppercase font-semibold mb-4.5">
            FIELD REPORT · INC-FCBD7B
          </div>
          <h2 className="font-serif font-semibold text-[clamp(38px,5.5vw,64px)] leading-none tracking-[-0.035em] text-[#1a1a1f] mb-8 max-w-[780px]">
            What happened at <span className="italic font-medium">02:14 UTC</span>.
          </h2>
          <div className="flex gap-6 py-3.5 border-t border-b border-[#e8e1cf] mb-10 font-mono text-[12px] text-[#535359] flex-wrap">
            <div>filed <strong className="text-[#1a1a1f] font-semibold">by orchestrator</strong></div>
            <div>priority <strong className="text-[#1a1a1f] font-semibold">P1</strong></div>
            <div>attributed to <strong className="text-[#1a1a1f] font-semibold">APT29</strong></div>
            <div>resolved in <strong className="text-[#1a1a1f] font-semibold">11.5 seconds</strong></div>
          </div>

          <div className="grid md:grid-cols-[1fr_1.4fr] gap-16 items-start">
            <p className="font-serif text-[22px] leading-[1.45] text-[#2d2d33]">
              An OAuth grant arrived from a Russian IP.{" "}
              <em className="italic text-[#1a1a1f] font-medium">What looked routine took eleven seconds to unmask</em> as the early move of a coordinated attack already three steps in.
            </p>
            <div>
              <p className="text-[16px] leading-[1.65] text-[#2d2d33] mb-4.5">
                At 02:14:14 UTC, a workstation belonging to <strong className="text-[#1a1a1f] font-semibold">marcus.chen</strong> authorized a new third-party application. The request originated from <strong className="text-[#1a1a1f] font-semibold">203.0.113.42</strong>. A junior analyst would have approved it. Most security stacks would have logged it without comment.
              </p>
              <p className="text-[16px] leading-[1.65] text-[#2d2d33] mb-4.5">
                ThreatBrain passed the event to Olivia first. Within 1.4 seconds, she flagged it as <strong className="text-[#1a1a1f] font-semibold">MITRE T1078</strong>, valid accounts being misused, and escalated. Henry confirmed the IP carried an AbuseIPDB score of 92 and matched APT29's known infrastructure.
              </p>
              <div className="px-6 py-5 bg-white border-l-[3px] border-[#1a1a1f] rounded-r-[12px] my-6 font-serif italic text-[18px] leading-[1.5] text-[#1a1a1f] font-medium">
                "Three more events from the same actor in the last twenty-four hours. This isn't a new attack. It's the next move in one we've been watching."
                <span className="block font-sans not-italic text-[13px] text-[#535359] mt-2.5 font-medium tracking-[-0.01em]">
                  Nathan, Investigation Agent
                </span>
              </div>
              <p className="text-[16px] leading-[1.65] text-[#2d2d33] mb-4.5">
                Nathan grouped the events under incident <strong className="text-[#1a1a1f] font-semibold">INC-FCBD7B</strong>. Rachel drafted a revocation playbook but stopped short of executing, waiting for human authorization. Frank rebuilt a 14-event timeline naming four affected assets. Claire closed the file by triggering the GDPR Article 33 clock.
              </p>
              <p className="text-[16px] leading-[1.65] text-[#2d2d33]">
                Eleven and a half seconds. <strong className="text-[#1a1a1f] font-semibold">Zero analyst hours.</strong>
              </p>
            </div>
          </div>
        </motion.div>
      </section>

      {/* HOW IT WORKS */}
      <section className="py-[120px] border-t border-[#e8e1cf]">
        <div className="max-w-[1240px] mx-auto px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.7 }}
            className="text-center mb-16"
          >
            <div className="font-mono text-[11px] text-[#8a8a8f] tracking-[0.16em] uppercase font-semibold mb-4.5">
              HOW IT WORKS
            </div>
            <h2 className="font-serif font-semibold text-[clamp(42px,6vw,68px)] leading-[0.96] tracking-[-0.035em] text-[#1a1a1f] max-w-[760px] mx-auto mb-4.5">
              Three acts. <span className="italic font-medium">No exceptions.</span>
            </h2>
            <p className="text-[17px] text-[#535359] max-w-[540px] mx-auto leading-[1.55]">
              Whether it's a phishing attempt at 3am or a sophisticated APT campaign, every alert takes the same path. Predictable, auditable, fast.
            </p>
          </motion.div>

          <div className="grid md:grid-cols-3 gap-4.5 max-w-[1080px] mx-auto">
            {[
              {
                step: "i.",
                title: "Alert",
                em: "arrives",
                body: (
                  <>
                    A login from a new IP, an unusual OAuth grant, a failed brute-force, a webshell upload. <strong className="text-[#1a1a1f] font-semibold">Anything your stack already detects.</strong> ThreatBrain takes it from there.
                  </>
                ),
              },
              {
                step: "ii.",
                title: "Crew",
                em: "investigates",
                body: (
                  <>
                    Each agent has a focused job and a strict output format. They pass context forward like analysts at a shift handoff, <strong className="text-[#1a1a1f] font-semibold">in milliseconds, not hours</strong>.
                  </>
                ),
              },
              {
                step: "iii.",
                title: "You",
                em: "decide",
                body: (
                  <>
                    Severity, attribution, related incidents, recommended response, compliance obligations. <strong className="text-[#1a1a1f] font-semibold">Ready for human review</strong>. Nothing destructive runs without your approval.
                  </>
                ),
              },
            ].map((card, i) => (
              <motion.div
                key={card.step}
                initial={{ opacity: 0, y: 24 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.7, delay: i * 0.08, ease: [0.16, 1, 0.3, 1] }}
                whileHover={{ y: -4 }}
                className="bg-white border border-[#e8e1cf] rounded-[18px] p-[36px_28px] transition-shadow duration-300 hover:shadow-[0_16px_40px_-16px_rgba(26,26,31,0.12)] hover:border-[#8a8a8f] relative group overflow-hidden"
              >
                <div className="absolute top-0 left-0 right-0 h-[2px] bg-[#1a1a1f] scale-x-0 group-hover:scale-x-100 origin-left transition-transform duration-500" />
                <div className="font-serif italic text-[48px] text-[#8a8a8f] font-medium leading-none mb-5 opacity-40">
                  {card.step}
                </div>
                <h3 className="font-serif text-[24px] font-semibold tracking-[-0.025em] text-[#1a1a1f] mb-2.5">
                  {card.title} <span className="italic font-medium">{card.em}</span>
                </h3>
                <p className="text-[14.5px] leading-[1.6] text-[#535359]">{card.body}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* SECURITY */}
      <section className="py-[120px] border-t border-[#e8e1cf]">
        <div className="max-w-[1240px] mx-auto px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.7 }}
            className="max-w-[760px] mx-auto mb-16"
          >
            <div className="font-mono text-[11px] text-[#8a8a8f] tracking-[0.16em] uppercase font-semibold mb-4.5">
              SECURITY ARCHITECTURE
            </div>
            <h2 className="font-serif font-semibold text-[clamp(42px,6vw,68px)] leading-[0.96] tracking-[-0.035em] text-[#1a1a1f] mb-4.5">
              Four primitives.
              <br />
              <span className="italic font-medium">Each one structural.</span>
            </h2>
            <p className="text-[17px] text-[#535359] max-w-[520px] leading-[1.55]">
              Every layer assumes the layer above could be compromised. Each primitive is enforced by the database or the schema, not by application code that can have bugs.
            </p>
          </motion.div>

          <div className="max-w-[1080px] mx-auto">
            {[
              {
                num: "i.",
                layer: "Database",
                title: "Multi-tenant by",
                em: "Postgres RLS",
                body: (
                  <>
                    Row-Level Security binds every query to the JWT's organization claim. Even if backend code has a bug, <strong className="text-[#1a1a1f] font-semibold">cross-tenant data cannot leak</strong>. The database enforces the boundary.
                  </>
                ),
              },
              {
                num: "ii.",
                layer: "Audit",
                title: "Append-only",
                em: "audit logs",
                body: (
                  <>
                    A Postgres trigger physically rejects UPDATE and DELETE on audit_logs. <strong className="text-[#1a1a1f] font-semibold">Even the service role key cannot modify history</strong>. Every agent decision is verifiable for regulators.
                  </>
                ),
              },
              {
                num: "iii.",
                layer: "Action",
                title: "Human",
                em: "in the loop",
                body: (
                  <>
                    The Response Agent recommends, never executes. Real actions require <strong className="text-[#1a1a1f] font-semibold">admin role plus per-playbook authorization plus dry-run flag off</strong>.
                  </>
                ),
              },
              {
                num: "iv.",
                layer: "Model",
                title: "Pydantic +",
                em: "JSON mode",
                body: (
                  <>
                    Every LLM call has a strict input and output schema. JSON mode prevents free-form text. <strong className="text-[#1a1a1f] font-semibold">The model has no channel to misbehave through</strong>.
                  </>
                ),
              },
            ].map((row, i) => (
              <motion.div
                key={row.num}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: i * 0.08 }}
                className="grid md:grid-cols-[180px_1fr_2fr] gap-8 py-9 border-t border-[#e8e1cf] hover:bg-[#f3eee2] hover:-mx-4 hover:px-4 hover:rounded-[14px] transition-all duration-200"
              >
                <div className="font-serif italic text-[32px] text-[#8a8a8f] font-medium">
                  <strong className="text-[#1a1a1f] not-italic font-semibold mr-2">{row.num}</strong>
                  {row.layer}
                </div>
                <h3 className="font-serif text-[22px] font-semibold tracking-[-0.025em] text-[#1a1a1f] leading-[1.2]">
                  {row.title} <span className="italic font-medium">{row.em}</span>
                </h3>
                <p className="text-[15px] leading-[1.6] text-[#535359]">{row.body}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <CTASection />

      {/* FOOTER */}
      <footer className="py-12 pb-8 border-t border-[#e8e1cf]">
        <div className="max-w-[1080px] mx-auto px-8 grid md:grid-cols-[2fr_1fr_1fr_1fr] gap-12">
          <div>
            <div className="flex items-center gap-2.5">
              <Logo />
              <span className="font-serif font-semibold text-[18px] tracking-[-0.025em] text-[#1a1a1f]">
                ThreatBrain
              </span>
            </div>
            <p className="text-[14px] text-[#535359] leading-[1.55] mt-3.5 max-w-[280px] font-serif italic">
              The neural SOC. Six AI agents that defend like your best analyst, at the speed of software.
            </p>
          </div>
          {[
            { title: "Platform", links: ["The Team", "Architecture", "Security", "Changelog"] },
            { title: "Resources", links: ["GitHub", "Live demo", "Documentation"] },
            { title: "Status", links: ["● All systems operational", "v1.0 · 2026.06"] },
          ].map((col) => (
            <div key={col.title}>
              <h4 className="font-mono text-[11px] text-[#1a1a1f] tracking-[0.12em] uppercase mb-3.5 font-semibold">
                {col.title}
              </h4>
              {col.links.map((link) => (
                <a key={link} className="block text-[14px] text-[#535359] mb-2 hover:text-[#1a1a1f] hover:translate-x-[3px] transition-all cursor-pointer">
                  {link}
                </a>
              ))}
            </div>
          ))}
        </div>
        <div className="max-w-[1080px] mx-auto mt-9 px-8 pt-4.5 border-t border-[#e8e1cf] font-mono text-[11px] text-[#8a8a8f] flex justify-between font-medium">
          <span>© 2026 ThreatBrain · MIT License</span>
          <span>FastAPI · Supabase · Groq · React · Vercel</span>
        </div>
      </footer>
    </div>
  );
}