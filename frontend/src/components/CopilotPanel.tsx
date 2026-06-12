import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Sparkles, X, Send, Loader2 } from "lucide-react";

import { askCopilot, type CopilotMessage } from "@/lib/api/copilot";
import { ApiError } from "@/lib/api";

const SUGGESTIONS = [
  "Summarize the most critical incident",
  "Which threats came from Russia?",
  "What is waiting for my approval?",
  "Which MITRE techniques appear most?",
];

export default function CopilotPanel() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, loading]);

  const send = async (question: string) => {
    const q = question.trim();
    if (!q || loading) return;
    setError(null);
    setInput("");
    const nextMessages: CopilotMessage[] = [...messages, { role: "user", content: q }];
    setMessages(nextMessages);
    setLoading(true);
    try {
      const res = await askCopilot(q, messages);
      setMessages([...nextMessages, { role: "assistant", content: res.answer }]);
    } catch (err) {
      if (err instanceof ApiError) setError(`${err.status}: ${err.message}`);
      else setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {/* Floating launcher */}
      <button
        onClick={() => setOpen(true)}
        aria-label="Ask the SOC copilot"
        className={`fixed bottom-6 right-6 z-40 inline-flex items-center gap-2 h-11 px-4 rounded-full bg-foreground text-background shadow-[0_8px_24px_-8px_rgba(16,24,40,0.45)] hover:bg-foreground/90 transition-all ${
          open ? "opacity-0 pointer-events-none" : "opacity-100"
        }`}
      >
        <Sparkles className="w-4 h-4 text-signal" />
        <span className="text-[13px] font-medium">Ask the SOC</span>
      </button>

      {/* Slide-over panel */}
      <AnimatePresence>
        {open && (
          <motion.aside
            initial={{ x: 420, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 420, opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeOut" }}
            className="fixed top-0 right-0 bottom-0 z-50 w-full sm:w-[400px] bg-white border-l border-border shadow-[-16px_0_48px_-24px_rgba(16,24,40,0.25)] flex flex-col"
          >
            {/* Header */}
            <div className="flex items-center justify-between px-5 h-16 border-b border-border flex-shrink-0">
              <div className="flex items-center gap-2.5">
                <span className="w-8 h-8 rounded-lg bg-foreground flex items-center justify-center">
                  <Sparkles className="w-4 h-4 text-signal" />
                </span>
                <div>
                  <div className="text-[14px] font-semibold tracking-[-0.01em]">Ask the SOC</div>
                  <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
                    Grounded in your org's data
                  </div>
                </div>
              </div>
              <button
                onClick={() => setOpen(false)}
                aria-label="Close copilot"
                className="p-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Messages */}
            <div ref={scrollRef} className="flex-1 overflow-y-auto px-5 py-5 space-y-4">
              {messages.length === 0 && (
                <div className="space-y-3">
                  <p className="text-[13px] text-muted-foreground leading-[1.6]">
                    Ask anything about your threats, incidents, or approval
                    queue. Answers come only from your organization's data.
                  </p>
                  <div className="space-y-2">
                    {SUGGESTIONS.map((s) => (
                      <button
                        key={s}
                        onClick={() => send(s)}
                        className="block w-full text-left px-3.5 py-2.5 rounded-lg border border-border text-[13px] text-foreground/85 hover:border-signal/40 hover:bg-signal/[0.04] transition-colors"
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {messages.map((m, i) => (
                <div key={i} className={m.role === "user" ? "flex justify-end" : "flex justify-start"}>
                  <div
                    className={`max-w-[85%] rounded-xl px-3.5 py-2.5 text-[13px] leading-[1.6] whitespace-pre-wrap ${
                      m.role === "user"
                        ? "bg-foreground text-background"
                        : "bg-muted/60 border border-border text-foreground"
                    }`}
                  >
                    {m.content}
                  </div>
                </div>
              ))}

              {loading && (
                <div className="flex items-center gap-2 text-muted-foreground text-[12.5px]">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  Reading your org's data...
                </div>
              )}

              {error && (
                <div className="text-[12.5px] text-severity-critical border border-severity-critical/30 bg-severity-critical/5 rounded-lg px-3 py-2">
                  {error}
                </div>
              )}
            </div>

            {/* Input */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                send(input);
              }}
              className="flex items-center gap-2 px-4 py-3.5 border-t border-border flex-shrink-0"
            >
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask about your threats, incidents..."
                className="flex-1 h-10 px-3.5 rounded-lg border border-border bg-white text-[13.5px] outline-none focus:border-foreground/30 placeholder:text-muted-foreground/70"
              />
              <button
                type="submit"
                disabled={loading || !input.trim()}
                aria-label="Send"
                className="w-10 h-10 rounded-lg bg-foreground text-background flex items-center justify-center hover:bg-foreground/90 disabled:opacity-40 transition-colors"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
          </motion.aside>
        )}
      </AnimatePresence>
    </>
  );
}
