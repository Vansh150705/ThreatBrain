import { Link, useLocation } from "react-router-dom";
import { ChevronRight, LogOut, User } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { signOut } from "@/lib/supabase";
import { useUserStore } from "@/store/useUserStore";

// Map URL segments to readable labels
const labelMap: Record<string, string> = {
  dashboard: "Dashboard",
  agents: "Agents",
  incidents: "Incidents",
  runs: "Run history",
};

function getBreadcrumbs(pathname: string) {
  const parts = pathname.split("/").filter(Boolean);
  return parts.map((part, idx) => {
    const path = "/" + parts.slice(0, idx + 1).join("/");
    const label = labelMap[part] || part;
    return { label, path };
  });
}

export default function Topbar() {
  const location = useLocation();
  const profile = useUserStore((s) => s.profile);
  const crumbs = getBreadcrumbs(location.pathname);

  const initials = profile?.full_name
    ? profile.full_name
        .split(" ")
        .map((w) => w[0])
        .join("")
        .slice(0, 2)
        .toUpperCase()
    : profile?.email?.[0]?.toUpperCase() ?? "?";

  return (
    <header className="h-14 bg-white border-b border-slate-200 flex items-center justify-between px-6 sticky top-0 z-10">
      {/* Breadcrumbs */}
      <nav className="flex items-center gap-1.5 text-sm">
        {crumbs.length === 0 && (
          <span className="text-slate-400">ThreatBrain</span>
        )}
        {crumbs.map((c, idx) => {
          const isLast = idx === crumbs.length - 1;
          return (
            <div key={c.path} className="flex items-center gap-1.5">
              {idx > 0 && (
                <ChevronRight className="w-3.5 h-3.5 text-slate-300" />
              )}
              {isLast ? (
                <span className="font-medium text-slate-900">{c.label}</span>
              ) : (
                <Link
                  to={c.path}
                  className="text-slate-500 hover:text-slate-900 transition-colors"
                >
                  {c.label}
                </Link>
              )}
            </div>
          );
        })}
      </nav>

      {/* User menu */}
      <div className="flex items-center gap-2">
        {profile?.organization && (
          <Badge variant="outline" className="text-xs hidden sm:inline-flex">
            {profile.organization.name}
          </Badge>
        )}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="gap-2 h-9 px-2">
              <div className="w-7 h-7 rounded-full bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center text-white text-xs font-semibold shadow-sm">
                {initials}
              </div>
              <span className="text-sm font-medium text-slate-700 hidden md:inline">
                {profile?.full_name || profile?.email}
              </span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel className="font-normal">
              <div className="flex flex-col">
                <span className="text-sm font-medium">
                  {profile?.full_name || "User"}
                </span>
                <span className="text-xs text-slate-500">
                  {profile?.email}
                </span>
                <div className="mt-2 flex items-center gap-1.5">
                  <Badge variant="outline" className="text-xs capitalize">
                    {profile?.role || "user"}
                  </Badge>
                </div>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem disabled>
              <User className="w-4 h-4 mr-2" />
              Profile (soon)
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => signOut()}
              className="text-severity-critical focus:text-severity-critical"
            >
              <LogOut className="w-4 h-4 mr-2" />
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}