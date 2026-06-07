import { cn } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

const severityStyles: Record<string, string> = {
  critical: "bg-severity-critical/8 text-severity-critical border-severity-critical/30",
  high:     "bg-severity-high/8 text-severity-high border-severity-high/30",
  medium:   "bg-severity-medium/8 text-severity-medium border-severity-medium/30",
  low:      "bg-severity-low/8 text-severity-low border-severity-low/30",
  info:     "bg-severity-info/8 text-severity-info border-severity-info/30",
};

export default function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const style = severityStyles[severity.toLowerCase()] ?? severityStyles.info;
  return (
    <span
      className={cn(
        "inline-flex items-center px-1.5 py-0.5 rounded font-mono text-[10px] font-semibold uppercase tracking-[0.06em] border",
        style,
        className
      )}
    >
      {severity}
    </span>
  );
}
