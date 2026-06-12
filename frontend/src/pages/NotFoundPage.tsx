import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";

export default function NotFoundPage() {
  return (
    <div className="min-h-screen bg-white flex items-center justify-center p-6 relative overflow-hidden">
      <div className="lp-grid absolute inset-0 pointer-events-none" aria-hidden />
      <div className="relative text-center max-w-sm">
        <div className="inline-flex items-center gap-2 font-mono text-[10.5px] uppercase tracking-[0.16em] text-muted-foreground mb-6">
          <span className="w-1.5 h-1.5 rounded-full bg-severity-medium" />
          Signal lost
        </div>
        <div className="title-serif text-[clamp(80px,18vw,120px)] tracking-[-0.04em] text-foreground leading-none mb-5">
          4<em className="font-serif italic font-medium text-signal">0</em>4
        </div>
        <h1 className="text-[18px] font-semibold tracking-[-0.02em] text-foreground mb-2">
          Page not found.
        </h1>
        <p className="text-[14px] text-muted-foreground mb-8 leading-[1.65]">
          The page you are looking for does not exist or has been moved.
        </p>
        <Link to="/dashboard">
          <Button className="bg-foreground text-background hover:bg-foreground/90 h-10 px-5 text-[13px] font-medium">
            Back to dashboard
          </Button>
        </Link>
      </div>
    </div>
  );
}
