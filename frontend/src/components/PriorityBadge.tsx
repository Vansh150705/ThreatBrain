import { cn } from "@/lib/utils";

interface PriorityBadgeProps {
  priority: string;
  className?: string;
}

const priorityStyles: Record<string, string> = {
  p1: "bg-severity-critical/8 text-severity-critical border-severity-critical/30",
  p2: "bg-severity-high/8 text-severity-high border-severity-high/30",
  p3: "bg-severity-medium/8 text-severity-medium border-severity-medium/30",
  p4: "bg-severity-info/8 text-severity-info border-severity-info/30",
  p5: "bg-muted text-muted-foreground border-border",
};

export default function PriorityBadge({ priority, className }: PriorityBadgeProps) {
  const key = priority.toLowerCase();
  const style = priorityStyles[key] ?? priorityStyles.p3;
  return (
    <span
      className={cn(
        "inline-flex items-center px-1.5 py-0.5 rounded font-mono text-[10px] font-semibold uppercase tracking-[0.06em] border",
        style,
        className
      )}
    >
      {priority.toUpperCase()}
    </span>
  );
}
