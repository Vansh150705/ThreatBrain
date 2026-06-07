import { cn } from "@/lib/utils";

interface StatusBadgeProps {
  status: string;
  className?: string;
}

const statusStyles: Record<string, string> = {
  open:           "bg-severity-critical/8 text-severity-critical border-severity-critical/30",
  investigating:  "bg-severity-medium/8 text-severity-medium border-severity-medium/30",
  contained:      "bg-severity-info/8 text-severity-info border-severity-info/30",
  resolved:       "bg-severity-low/8 text-severity-low border-severity-low/30",
  false_positive: "bg-muted text-muted-foreground border-border",
};

const statusLabels: Record<string, string> = {
  open:           "Open",
  investigating:  "Investigating",
  contained:      "Contained",
  resolved:       "Resolved",
  false_positive: "False positive",
};

export default function StatusBadge({ status, className }: StatusBadgeProps) {
  const key = status.toLowerCase();
  const style = statusStyles[key] ?? statusStyles.open;
  const label = statusLabels[key] ?? status;
  return (
    <span
      className={cn(
        "inline-flex items-center px-1.5 py-0.5 rounded font-mono text-[10px] font-semibold uppercase tracking-[0.06em] border",
        style,
        className
      )}
    >
      {label}
    </span>
  );
}
