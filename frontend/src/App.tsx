import { NavLink, Outlet, Route, Routes } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import {
  LayoutDashboard,
  FileText,
  ScrollText,
  Bug,
  Network,
  BarChart3,
} from "lucide-react";
import Header from "./components/Header";
import RequireSession from "./components/RequireSession";
import Dashboard from "./pages/Dashboard";
import Records from "./pages/Records";
import AuditTrail from "./pages/AuditTrail";
import SecurityTesting from "./pages/SecurityTesting";
import Architecture from "./pages/Architecture";
import Evaluation from "./pages/Evaluation";
import Landing from "./pages/Landing";
import LoginOwner from "./pages/LoginOwner";
import LoginCustodian from "./pages/LoginCustodian";
import LoginRequester from "./pages/LoginRequester";
import OwnerPortal from "./pages/OwnerPortal";
import CustodianPortal from "./pages/CustodianPortal";
import RequesterPortal from "./pages/RequesterPortal";

// This console is the demonstration/monitoring side of the app -- the
// Owner/Custodian/Requester portals (reached via the three logins) are
// where the actual protect/request/approve/recover actions happen now,
// so this nav sticks to the six observe-and-explain tabs only.
const NAV = [
  { to: "/console", label: "Dashboard", end: true, icon: LayoutDashboard },
  { to: "/console/records", label: "Records", icon: FileText },
  { to: "/console/audit", label: "Audit Trail", icon: ScrollText },
  { to: "/console/security-tests", label: "Security Testing", icon: Bug },
  { to: "/console/architecture", label: "Architecture", icon: Network },
  { to: "/console/evaluation", label: "Evaluation", icon: BarChart3 },
];

function ConsoleLayout() {
  return (
    <div className="flex flex-1">
      <aside className="w-56 shrink-0 border-r border-slate-800 bg-slate-950 p-4">
        <nav className="space-y-1">
          {NAV.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium ${
                    isActive
                      ? "bg-violet-500/10 text-violet-300"
                      : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                  }`
                }
              >
                <Icon className="h-4 w-4 shrink-0" strokeWidth={1.75} />
                {item.label}
              </NavLink>
            );
          })}
        </nav>
      </aside>

      <main className="flex-1 overflow-y-auto p-8">
        <Outlet />
      </main>
    </div>
  );
}

export default function App() {
  return (
    <div className="flex min-h-screen flex-col">
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: "#0f172a",
            color: "#e6e9f0",
            border: "1px solid #1e293b",
            fontSize: "0.875rem",
          },
          success: { iconTheme: { primary: "#34d399", secondary: "#0f172a" } },
          error: { iconTheme: { primary: "#fb7185", secondary: "#0f172a" } },
        }}
      />
      <Header />

      <div className="flex flex-1 flex-col">
        <Routes>
          {/* Landing + per-role email-OTP login */}
          <Route path="/" element={<Landing />} />
          <Route path="/login/owner" element={<LoginOwner />} />
          <Route path="/login/custodian" element={<LoginCustodian />} />
          <Route path="/login/requester" element={<LoginRequester />} />

          {/* Signed-in, role-scoped portals */}
          <Route
            path="/portal/owner"
            element={
              <RequireSession kind="owner">
                <OwnerPortal />
              </RequireSession>
            }
          />
          <Route
            path="/portal/custodian"
            element={
              <RequireSession kind="custodian">
                <CustodianPortal />
              </RequireSession>
            }
          />
          <Route
            path="/portal/requester"
            element={
              <RequireSession kind="requester">
                <RequesterPortal />
              </RequireSession>
            }
          />

          {/* The demonstration console -- dashboard, records, audit trail,
              live security testing, architecture, and evaluation. Protect /
              request / approve / recover now happen in the three portals
              above, reached via the role logins. */}
          <Route path="/console" element={<ConsoleLayout />}>
            <Route index element={<Dashboard />} />
            <Route path="records" element={<Records />} />
            <Route path="audit" element={<AuditTrail />} />
            <Route path="security-tests" element={<SecurityTesting />} />
            <Route path="architecture" element={<Architecture />} />
            <Route path="evaluation" element={<Evaluation />} />
          </Route>
        </Routes>
      </div>
    </div>
  );
}
