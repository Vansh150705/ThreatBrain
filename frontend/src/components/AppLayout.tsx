import { Outlet } from "react-router-dom";

import Sidebar from "./Sidebar";
import Topbar from "./Topbar";
import CopilotPanel from "./CopilotPanel";

export default function AppLayout() {
  return (
    <div className="min-h-screen bg-background flex">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <Topbar />
        <main className="flex-1 px-4 py-5 sm:px-6 sm:py-6 lg:px-8 lg:py-7 max-w-[1400px] w-full">
          <Outlet />
        </main>
      </div>
      <CopilotPanel />
    </div>
  );
}