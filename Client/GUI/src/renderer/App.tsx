import { AnimatePresence } from "framer-motion";
import { useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Toaster } from "sonner";
import { useTheme } from "next-themes";
import Dashboard from "./routes/Dashboard";
import Login from "./routes/Login";
import Register from "./routes/Register";
import Settings from "./routes/Settings";
import News from "./routes/News";
import SplashScreen from "./components/SplashScreen";
import { antivirusService, useAntivirus } from "./services/antivirusService";
import { useAuth } from "./services/authService";

const RequireAuth = ({ children }: { children: JSX.Element }) => {
  const { user, loading } = useAuth();
  if (loading) {
    return null;
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return children;
};

const App = () => {
  const location = useLocation();
  const { resolvedTheme } = useTheme();
  const antivirus = useAntivirus();
  const [showSplash, setShowSplash] = useState(true);

  useEffect(() => {
    antivirusService.init();
  }, []);

  useEffect(() => {
    // Hide splash screen when connected or if we hit an error
    if (antivirus.connectionState === "connected" || antivirus.error) {
      // Increase delay to allow the "Architected By" credits to be seen
      const timer = setTimeout(() => setShowSplash(false), 4000);
      return () => clearTimeout(timer);
    }
  }, [antivirus.connectionState, antivirus.error]);

  return (
    <div className="min-h-screen" dir="ltr">
      <SplashScreen
        isVisible={showSplash}
        status={
          antivirus.connectionState === "connecting"
            ? "Establishing secure link..."
            : antivirus.statusMessage
        }
      />

      <Toaster
        theme={resolvedTheme === "light" ? "light" : "dark"}
        richColors
        closeButton
      />
      <AnimatePresence mode="wait">
        <Routes location={location} key={location.pathname}>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route
            path="/dashboard"
            element={
              <RequireAuth>
                <Dashboard />
              </RequireAuth>
            }
          />
          <Route
            path="/news"
            element={
              <RequireAuth>
                <News />
              </RequireAuth>
            }
          />
          <Route
            path="/settings"
            element={
              <RequireAuth>
                <Settings />
              </RequireAuth>
            }
          />
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </AnimatePresence>
    </div>
  );
};

export default App;
