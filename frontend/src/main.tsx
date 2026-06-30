import { StrictMode, Suspense, lazy } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import App from "./App";
import RequireAuth from "./components/RequireAuth";
import AppLayout from "./components/AppLayout";
import { AuthProvider } from "./contexts/AuthContext";

// Route components are code-split so each page loads on demand, keeping the
// initial bundle small (heavy deps like Leaflet ship only with the map route).
const LandingPage = lazy(() => import("./pages/LandingPage"));
const LoginPage = lazy(() => import("./pages/LoginPage"));
const SignupPage = lazy(() => import("./pages/SignupPage"));
const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const AgentsPage = lazy(() => import("./pages/AgentsPage"));
const IncidentsPage = lazy(() => import("./pages/IncidentsPage"));
const IncidentDetailPage = lazy(() => import("./pages/IncidentDetailPage"));
const RunsPage = lazy(() => import("./pages/RunsPage"));
const RunDetailPage = lazy(() => import("./pages/RunDetailPage"));
const ThreatsPage = lazy(() => import("./pages/ThreatsPage"));
const ThreatDetailPage = lazy(() => import("./pages/ThreatDetailPage"));
const AttackMapPage = lazy(() => import("./pages/AttackMapPage"));
const AuditPage = lazy(() => import("./pages/AuditPage"));
const ApprovalsPage = lazy(() => import("./pages/ApprovalsPage"));
const NotFoundPage = lazy(() => import("./pages/NotFoundPage"));

import "leaflet/dist/leaflet.css";
import "./index.css";

function RouteFallback() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background text-muted-foreground">
      <div className="h-6 w-6 animate-spin rounded-full border-2 border-current border-t-transparent" />
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <Suspense fallback={<RouteFallback />}>
          <Routes>
            <Route path="/" element={<App />}>
              {/* Public routes */}
              <Route index element={<LandingPage />} />
              <Route path="login" element={<LoginPage />} />
              <Route path="signup" element={<SignupPage />} />

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
                <Route path="incidents/:identifier" element={<IncidentDetailPage />} />
                <Route path="runs" element={<RunsPage />} />
                <Route path="runs/:runId" element={<RunDetailPage />} />
                <Route path="attack-map" element={<AttackMapPage />} />
                <Route path="audit" element={<AuditPage />} />
                <Route path="approvals" element={<ApprovalsPage />} />
              </Route>

              {/* 404 */}
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </Suspense>
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>
);
