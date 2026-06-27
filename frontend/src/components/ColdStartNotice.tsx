import { motion } from "motion/react";

// Shown while the free-tier backend cold-starts (see withColdStartRetry).
// Styled to match the SOC theme: standard card chrome, a pulsing signal node
// like the live indicator, a mono eyebrow, and an indeterminate progress bar
// echoing the pipeline-health bars.
export default function ColdStartNotice({ className = "" }: { className?: string }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={`relative overflow-hidden bg-card border border-border rounded-xl px-5 py-4 ${className}`}
      role="status"
      aria-live="polite"
    >
      <div className="flex items-start gap-3.5">
        {/* pulsing signal node, matching the live indicator motif */}
        <span className="relative flex items-center justify-center mt-1 flex-shrink-0">
          <span className="w-2 h-2 rounded-full bg-signal" />
          <span className="absolute w-2 h-2 rounded-full bg-signal animate-ping opacity-75" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-signal font-semibold mb-1.5">
            Cold start · booting
          </div>
          <div className="text-[14px] font-semibold tracking-[-0.015em] text-foreground">
            Waking the backend
          </div>
          <p className="text-[12.5px] text-muted-foreground mt-1 leading-[1.55] max-w-2xl">
            The demo backend sleeps when idle to conserve resources. The first
            request can take up to a minute. This view refreshes automatically
            the moment it responds.
          </p>
          {/* indeterminate progress, echoing the pipeline-health bars */}
          <div className="mt-3 h-1 rounded-full bg-muted overflow-hidden">
            <motion.div
              className="h-full w-1/3 rounded-full bg-signal/80"
              animate={{ x: ["-110%", "330%"] }}
              transition={{ duration: 1.4, repeat: Infinity, ease: "easeInOut" }}
            />
          </div>
        </div>
      </div>
    </motion.div>
  );
}
