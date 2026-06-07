import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";

export default function NotFoundPage() {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-6">
      <div className="text-center max-w-sm">
        <div className="text-[72px] font-semibold tabular tracking-[-0.04em] text-foreground leading-none mb-4">
          404
        </div>
        <h1 className="text-[18px] font-semibold tracking-[-0.02em] text-foreground mb-2">
          Page not found.
        </h1>
        <p className="text-[14px] text-muted-foreground mb-8 leading-[1.6]">
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
