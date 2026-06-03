import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

import App from "./App";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import AgentsPage from "./pages/AgentsPage";
import IncidentsPage from "./pages/IncidentsPage";
import RunsPage from "./pages/RunsPage";
import NotFoundPage from "./pages/NotFoundPage";
import RequireAuth from "./components/RequireAuth";
import AppLayout from "./components/AppLayout";
import { AuthProvider } from "./contexts/AuthContext";
import ThreatsPage from "./pages/ThreatsPage";
import ThreatDetailPage from "./pages/ThreatDetailPage";

import "./index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<App />}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="login" element={<LoginPage />} />

            {/* Protected routes */}
            <Route
              element={
                <RequireAuth>
                  <AppLayout />
                </RequireAuth>
              }
            >
            <Route path="dashboard" element={<DashboardPage />} />
              <Route path="threats" element={<ThreatsPage />} />
              <Route path="threats/:identifier" element={<ThreatDetailPage />} />
              <Route path="agents" element={<AgentsPage />} />
              <Route path="agents/:agentKey" element={<AgentsPage />} />
              <Route path="incidents" element={<IncidentsPage />} />
              <Route path="runs" element={<RunsPage />} />
            </Route>

            {/* 404 */}
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>
);