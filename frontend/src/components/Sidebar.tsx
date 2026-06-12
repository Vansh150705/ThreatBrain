import { Link, useLocation } from "react-router-dom";
import { motion } from "motion/react";
import {
  LayoutDashboard,
  Bot,
  ShieldAlert,
  AlertOctagon,
  Activity,
  ChevronLeft,
  Globe,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useUIStore } from "@/store/useUIStore";
import { LogoMark } from "@/components/Logo";

const navSections = [
  {
    title: "Operations",
    items: [
      { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { to: "/threats", label: "Threats", icon: ShieldAlert },
      { to: "/incidents", label: "Incidents", icon: AlertOctagon },
      { to: "/attack-map", label: "Attack Map", icon: Globe },
    ],
  },
  {
    title: "Intelligence",
    items: [
      { to: "/agents", label: "Agents", icon: Bot },
      { to: "/runs", label: "Run history", icon: Activity },
    ],
  },
];

export default function Sidebar() {
  const location = useLocation();
  const collapsed = useUIStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);

  return (
    <TooltipProvider delayDuration={0}>
      <motion.aside
        animate={{ width: collapsed ? 72 : 272 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        className="bg-sidebar border-r border-sidebar-border flex flex-col h-screen sticky top-0 overflow-hidden"
      >
        {/* Logo */}
        <div className="h-[68px] flex items-center px-4 flex-shrink-0 border-b border-sidebar-border">
          <Link to="/dashboard" className="flex items-center gap-3 group">
            <div className="w-9 h-9 text-foreground flex-shrink-0">
              <LogoMark className="w-full h-full" />
            </div>
            {!collapsed && (
              <motion.div
                initial={{ opacity: 0, x: -4 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1, duration: 0.2 }}
                className="overflow-hidden whitespace-nowrap"
              >
                <div className="font-semibold text-foreground text-[16px] tracking-[-0.02em] leading-none">
                  ThreatBrain
                </div>
                <div className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-muted-foreground mt-1.5 flex items-center gap-1.5">
                  <span className="w-1 h-1 rounded-full bg-signal" />
                  Operational
                </div>
              </motion.div>
            )}
          </Link>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-4 overflow-y-auto">
          {navSections.map((section) => (
            <div key={section.title} className="mb-6">
              {!collapsed && (
                <div className="px-5 mb-2 font-mono text-[10.5px] font-semibold text-muted-foreground uppercase tracking-[0.14em]">
                  {section.title}
                </div>
              )}
              <div className="px-2.5 space-y-1">
                {section.items.map((item) => {
                  const Icon = item.icon;
                  const active =
                    location.pathname === item.to ||
                    location.pathname.startsWith(item.to + "/");
                  const link = (
                    <Link
                      to={item.to}
                      className={`relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-[14px] font-medium transition-all ${
                        active
                          ? "bg-accent text-foreground"
                          : "text-muted-foreground hover:bg-accent hover:text-foreground"
                      } ${collapsed ? "justify-center" : ""}`}
                    >
                      {active && (
                        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[2.5px] h-5 rounded-full bg-signal" aria-hidden />
                      )}
                      <Icon className="w-[18px] h-[18px] flex-shrink-0" strokeWidth={active ? 2.1 : 1.7} />
                      {!collapsed && (
                        <span className="truncate tracking-[-0.01em]">{item.label}</span>
                      )}
                    </Link>
                  );

                  if (collapsed) {
                    return (
                      <Tooltip key={item.to}>
                        <TooltipTrigger asChild>{link}</TooltipTrigger>
                        <TooltipContent side="right" className="font-medium">
                          {item.label}
                        </TooltipContent>
                      </Tooltip>
                    );
                  }
                  return <div key={item.to}>{link}</div>;
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Collapse toggle */}
        <div className="p-2.5 flex-shrink-0 border-t border-sidebar-border">
          <Button
            variant="ghost"
            size="sm"
            onClick={toggleSidebar}
            className={`w-full text-muted-foreground hover:text-foreground hover:bg-accent h-9 ${
              collapsed ? "px-0 justify-center" : "justify-start px-3"
            }`}
          >
            <ChevronLeft
              className={`w-4 h-4 transition-transform ${collapsed ? "rotate-180" : ""}`}
            />
            {!collapsed && <span className="ml-2 text-[13px]">Collapse</span>}
          </Button>
        </div>
      </motion.aside>
    </TooltipProvider>
  );
}