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

const labelMap: Record<string, string> = {
  dashboard: "Dashboard",
  threats: "Threats",
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
    <header className="h-16 bg-background/85 backdrop-blur-xl border-b border-border flex items-center justify-between px-8 sticky top-0 z-10">
      {/* Breadcrumbs */}
      <nav className="flex items-center gap-2 text-[13.5px]">
        {crumbs.length === 0 && (
          <span className="font-mono text-muted-foreground uppercase tracking-[0.14em] text-[11px] font-semibold">
            ThreatBrain
          </span>
        )}
        {crumbs.map((c, idx) => {
          const isLast = idx === crumbs.length - 1;
          return (
            <div key={c.path} className="flex items-center gap-2">
              {idx > 0 && (
                <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/60" strokeWidth={1.8} />
              )}
              {isLast ? (
                <span className="font-serif italic font-medium text-foreground tracking-[-0.015em] text-[16px]">
                  {c.label}
                </span>
              ) : (
                <Link
                  to={c.path}
                  className="text-muted-foreground hover:text-foreground transition-colors font-medium tracking-[-0.01em]"
                >
                  {c.label}
                </Link>
              )}
            </div>
          );
        })}
      </nav>

      {/* User menu */}
      <div className="flex items-center gap-3">
        {profile?.organization && (
          <Badge
            variant="outline"
            className="text-[11px] font-mono font-semibold tracking-[0.06em] uppercase hidden sm:inline-flex bg-background border-border text-muted-foreground"
          >
            {profile.organization.name}
          </Badge>
        )}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="gap-2.5 h-10 px-2 hover:bg-accent"
            >
              <div className="w-8 h-8 rounded-full bg-foreground flex items-center justify-center text-background text-[12px] font-semibold shadow-sm tracking-[-0.01em]">
                {initials}
              </div>
              <span className="text-[13.5px] font-medium text-foreground hidden md:inline tracking-[-0.01em]">
                {profile?.full_name || profile?.email}
              </span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-60">
            <DropdownMenuLabel className="font-normal py-3">
              <div className="flex flex-col gap-1">
                <span className="text-[14px] font-serif font-semibold tracking-[-0.02em]">
                  {profile?.full_name || "User"}
                </span>
                <span className="text-[11px] font-mono text-muted-foreground">
                  {profile?.email}
                </span>
                <div className="mt-2 flex items-center gap-1.5">
                  <Badge
                    variant="outline"
                    className="text-[10px] font-mono font-semibold uppercase tracking-[0.06em] capitalize"
                  >
                    {profile?.role || "user"}
                  </Badge>
                </div>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem disabled className="text-[13px]">
              <User className="w-4 h-4 mr-2" />
              Profile <span className="ml-auto text-[10px] font-mono text-muted-foreground">soon</span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => signOut()}
              className="text-severity-critical focus:text-severity-critical text-[13px]"
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