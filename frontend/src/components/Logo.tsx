/* ThreatBrain logo mark */
export function LogoMark({ className = "" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="1" y="1" width="22" height="22" rx="6.5" fill="currentColor" />
      {/* mesh edges */}
      <g stroke="var(--background)" strokeWidth="0.8" opacity="0.65">
        <line x1="12" y1="6.4" x2="7.2" y2="11.2" />
        <line x1="12" y1="6.4" x2="16.8" y2="11.2" />
        <line x1="7.2" y1="11.2" x2="16.8" y2="11.2" />
        <line x1="7.2" y1="11.2" x2="12" y2="17.2" />
        <line x1="16.8" y1="11.2" x2="12" y2="17.2" />
      </g>
      {/* nodes */}
      <circle cx="7.2" cy="11.2" r="1.5" fill="var(--background)" />
      <circle cx="16.8" cy="11.2" r="1.5" fill="var(--background)" />
      <circle cx="12" cy="17.2" r="1.5" fill="var(--background)" />
      {/* top node */}
      <circle cx="12" cy="6.4" r="1.9" fill="var(--color-signal)" />
    </svg>
  );
}
