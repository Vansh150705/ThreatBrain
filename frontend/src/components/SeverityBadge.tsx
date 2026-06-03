import { cn } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

// Color tokens defined in index.css under @theme as --color-severity-*
const severityStyles: Record<string, string> = {
  critical: "bg-severity-critical/10 text-severity-critical border-severity-critical/30",
  high: "bg-severity-high/10 text-severity-high border-severity-high/30",
  medium: "bg-severity-medium/10 text-severity-medium border-severity-medium/30",
  low: "bg-severity-low/10 text-severity-low border-severity-low/30",
  info: "bg-severity-info/10 text-severity-info border-severity-info/30",
};

export default function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const style = severityStyles[severity.toLowerCase()] || severityStyles.info;
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide border",
        style,
        className
      )}
    >
      {severity}
    </span>
  );
}