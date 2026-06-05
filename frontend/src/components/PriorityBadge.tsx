import { cn } from "@/lib/utils";

interface PriorityBadgeProps {
  priority: string;
  className?: string;
}

const priorityStyles: Record<string, string> = {
  p1: "bg-red-100 text-red-700 border-red-300",
  p2: "bg-orange-100 text-orange-700 border-orange-300",
  p3: "bg-amber-100 text-amber-700 border-amber-300",
  p4: "bg-blue-100 text-blue-700 border-blue-300",
  p5: "bg-slate-100 text-slate-600 border-slate-300",
};

export default function PriorityBadge({ priority, className }: PriorityBadgeProps) {
  const key = priority.toLowerCase();
  const style = priorityStyles[key] || priorityStyles.p3;
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase border font-mono",
        style,
        className
      )}
    >
      {priority.toUpperCase()}
    </span>
  );
}