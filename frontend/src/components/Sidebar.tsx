import { Link, useLocation } from "react-router-dom";
import { motion } from "motion/react";
import {
  Shield,
  LayoutDashboard,
  Bot,
  ShieldAlert,
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

const navSections = [
  {
    title: "Operations",
    items: [
      { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { to: "/incidents", label: "Incidents", icon: ShieldAlert },
    ],
  },
  {
    title: "AI",
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
        animate={{ width: collapsed ? 68 : 240 }}
        transition={{ duration: 0.2, ease: "easeInOut" }}
        className="bg-white border-r border-slate-200 flex flex-col h-screen sticky top-0 overflow-hidden"
      >
        {/* Logo */}
        <div className="h-14 flex items-center px-4 border-b border-slate-200 flex-shrink-0">
          <Link to="/dashboard" className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center shadow-md shadow-primary-500/30 flex-shrink-0">
              <Shield className="w-4 h-4 text-white" />
            </div>
            {!collapsed && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.1 }}
                className="overflow-hidden whitespace-nowrap"
              >
                <div className="font-bold text-slate-900 text-sm tracking-tight leading-none">
                  ThreatBrain
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">
                  Neural SOC
                </div>
              </motion.div>
            )}
          </Link>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-4 overflow-y-auto">
          {navSections.map((section) => (
            <div key={section.title} className="mb-4">
              {!collapsed && (
                <div className="px-4 mb-1.5 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
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
                      className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                        active
                          ? "bg-primary-50 text-primary-700"
                          : "text-slate-600 hover:bg-slate-100"
                      } ${collapsed ? "justify-center" : ""}`}
                    >
                      <Icon className="w-4 h-4 flex-shrink-0" />
                      {!collapsed && (
                        <span className="truncate">{item.label}</span>
                      )}
                    </Link>
                  );

                  if (collapsed) {
                    return (
                      <Tooltip key={item.to}>
                        <TooltipTrigger asChild>{link}</TooltipTrigger>
                        <TooltipContent side="right">
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
        <div className="p-3 border-t border-slate-200 flex-shrink-0">
          <Button
            variant="ghost"
            size="sm"
            onClick={toggleSidebar}
            className={`w-full ${collapsed ? "px-0 justify-center" : "justify-start"}`}
          >
            <ChevronLeft
              className={`w-4 h-4 transition-transform ${collapsed ? "rotate-180" : ""}`}
            />
            {!collapsed && <span className="ml-2">Collapse</span>}
          </Button>
        </div>
      </motion.aside>
    </TooltipProvider>
  );
}