import { Link, Outlet, useLocation } from "react-router-dom";
import { Shield, LogOut, LayoutDashboard, Bot, ShieldAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { signOut } from "@/lib/supabase";
import { useUserStore } from "@/store/useUserStore";

const navItems = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/agents", label: "Agents", icon: Bot },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
];

export default function AppLayout() {
  const location = useLocation();
  const profile = useUserStore((s) => s.profile);

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Top bar */}
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <Link to="/dashboard" className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center shadow-md shadow-primary-500/30">
                <Shield className="w-4 h-4 text-white" />
              </div>
              <span className="font-bold text-slate-900 text-sm tracking-tight">
                ThreatBrain
              </span>
              {profile?.organization && (
                <span className="text-xs text-slate-400 hidden md:inline">
                  · {profile.organization.name}
                </span>
              )}
            </Link>

            <nav className="flex items-center gap-1">
              {navItems.map((item) => {
                const Icon = item.icon;
                const active = location.pathname.startsWith(item.to);
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                      active
                        ? "bg-primary-50 text-primary-700"
                        : "text-slate-600 hover:bg-slate-100"
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    {item.label}
                  </Link>
                );
              })}
            </nav>
          </div>

          <div className="flex items-center gap-3">
            {profile && (
              <div className="flex items-center gap-2">
                <div className="text-right hidden sm:block">
                  <div className="text-xs font-medium text-slate-900">
                    {profile.full_name || profile.email}
                  </div>
                  <div className="text-xs text-slate-500">
                    {profile.email}
                  </div>
                </div>
                <Badge
                  variant="outline"
                  className="text-xs font-mono capitalize"
                >
                  {profile.role}
                </Badge>
              </div>
            )}
            <Button variant="ghost" size="sm" onClick={() => signOut()}>
              <LogOut className="w-4 h-4 mr-2" />
              Sign out
            </Button>
          </div>
        </div>
      </header>

      {/* Page content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}