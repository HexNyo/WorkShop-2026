import { Navigate, Route, Routes } from "react-router-dom";

import { ROLE_GROUPS, useAuth } from "./auth/AuthProvider";
import { EditorialLayout } from "./components/EditorialLayout";
import { Layout } from "./components/Layout";
import { Spinner } from "./components/ui";
import { AdminPage } from "./features/admin/AdminPage";
import { AssistantPage } from "./features/assistant/AssistantPage";
import { LoginPage } from "./features/auth/LoginPage";
import { PaymentsPage } from "./features/payments/PaymentsPage";
import { SupervisionPage } from "./features/supervision/SupervisionPage";
import { Forbidden, RequireRole, homeFor } from "./routes";

function Home() {
  const { status, principal } = useAuth();
  if (status === "restoring") {
    return (
      <div className="flex justify-center py-20">
        <Spinner label="Restauration de la session…" />
      </div>
    );
  }
  return <Navigate to={principal ? homeFor(principal.roles) : "/login"} replace />;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={document.documentElement.classList.contains("editorial") ? <EditorialLayout /> : <Layout />}>
        <Route index element={<Home />} />
        <Route
          path="/payments"
          element={
            <RequireRole roles={ROLE_GROUPS.payments}>
              <PaymentsPage />
            </RequireRole>
          }
        />
        <Route
          path="/supervision"
          element={
            <RequireRole roles={ROLE_GROUPS.supervision}>
              <SupervisionPage />
            </RequireRole>
          }
        />
        <Route
          path="/assistant"
          element={
            <RequireRole roles={ROLE_GROUPS.assistant}>
              <AssistantPage />
            </RequireRole>
          }
        />
        <Route
          path="/admin"
          element={
            <RequireRole roles={ROLE_GROUPS.admin}>
              <AdminPage />
            </RequireRole>
          }
        />
        <Route path="/forbidden" element={<Forbidden />} />
        <Route path="*" element={<Home />} />
      </Route>
    </Routes>
  );
}
