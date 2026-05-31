import { Link } from "react-router-dom";
import { Compass } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function NotFoundPage() {
  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
      <div className="text-center max-w-md">
        <div className="w-12 h-12 rounded-xl bg-slate-200 flex items-center justify-center mx-auto mb-4">
          <Compass className="w-6 h-6 text-slate-500" />
        </div>
        <h1 className="text-2xl font-bold text-slate-900 mb-2">
          Page not found
        </h1>
        <p className="text-sm text-slate-500 mb-6">
          The page you're looking for doesn't exist or has been moved.
        </p>
        <Link to="/dashboard">
          <Button>Back to dashboard</Button>
        </Link>
      </div>
    </div>
  );
}