import { Link, useLocation } from "react-router-dom";
import { motion } from "motion/react";
import {
  LayoutDashboard,
  Bot,
  ShieldAlert,
  AlertOctagon,
  Activity,
  ChevronLeft,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useUIStore } from "@/store/useUIStore";

function LogoMark({ className = "" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M12 2 L20 5 L20 12 C20 17 16 21 12 22 C8 21 4 17 4 12 L4 5 Z"
        fill="currentColor"
      />
      <circle cx="9" cy="9" r="1.4" fill="#ffffff" />
      <circle cx="15" cy="9" r="1.4" fill="#ffffff" />
      <circle cx="12" cy="14" r="1.4" fill="#ffffff" />
      <line x1="9" y1="9" x2="15" y2="9" stroke="#ffffff" strokeWidth="0.6" />
      <line x1="9" y1="9" x2="12" y2="14" stroke="#ffffff" strokeWidth="0.6" />
      <line x1="15" y1="9" x2="12" y2="14" stroke="#ffffff" strokeWidth="0.6" />
    </svg>
  );
}

const navSections = [
  {
    title: "Operations",
    items: [
      { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { to: "/threats", label: "Threats", icon: ShieldAlert },
      { to: "/incidents", label: "Incidents", icon: AlertOctagon },
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
        animate={{ width: collapsed ? 64 : 232 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        className="bg-sidebar border-r border-sidebar-border flex flex-col h-screen sticky top-0 overflow-hidden"
      >
        {/* Logo */}
        <div className="h-14 flex items-center px-4 flex-shrink-0">
          <Link to="/dashboard" className="flex items-center gap-2.5 group">
            <div className="w-6 h-6 text-foreground flex-shrink-0">
              <LogoMark className="w-full h-full" />
            </div>
            {!collapsed && (
              <motion.div
                initial={{ opacity: 0, x: -4 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1, duration: 0.2 }}
                className="overflow-hidden whitespace-nowrap"
              >
                <div className="font-semibold text-foreground text-[14px] tracking-[-0.02em] leading-none">
                  ThreatBrain
                </div>
              </motion.div>
            )}
          </Link>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 overflow-y-auto">
          {navSections.map((section) => (
            <div key={section.title} className="mb-5">
              {!collapsed && (
                <div className="px-4 mb-1.5 font-mono text-[10px] font-semibold text-muted-foreground uppercase tracking-[0.12em]">
                  {section.title}
                </div>
              )}
              <div className="px-2 space-y-0.5">
                {section.items.map((item) => {
                  const Icon = item.icon;
                  const active =
                    location.pathname === item.to ||
                    location.pathname.startsWith(item.to + "/");
                  const link = (
                    <Link
                      to={item.to}
                      className={`relative flex items-center gap-2.5 px-2.5 py-1.5 rounded-md text-[13px] font-medium transition-all ${
                        active
                          ? "bg-accent text-foreground"
                          : "text-muted-foreground hover:bg-accent hover:text-foreground"
                      } ${collapsed ? "justify-center" : ""}`}
                    >
                      <Icon className="w-[15px] h-[15px] flex-shrink-0" strokeWidth={active ? 2.2 : 1.8} />
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
        <div className="p-2 flex-shrink-0">
          <Button
            variant="ghost"
            size="sm"
            onClick={toggleSidebar}
            className={`w-full text-muted-foreground hover:text-foreground hover:bg-accent h-8 ${
              collapsed ? "px-0 justify-center" : "justify-start px-2.5"
            }`}
          >
            <ChevronLeft
              className={`w-3.5 h-3.5 transition-transform ${collapsed ? "rotate-180" : ""}`}
            />
            {!collapsed && <span className="ml-2 text-[12px]">Collapse</span>}
          </Button>
        </div>
      </motion.aside>
    </TooltipProvider>
  );
}