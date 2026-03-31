import { Button, Input } from "@nextui-org/react";
import { motion, AnimatePresence } from "framer-motion";
import { Lock } from "lucide-react";
import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { authService, useAuth } from "../services/authService";
import logoUrl from "../assets/logo.png";
import BridgeDebug from "../components/BridgeDebug";
import ThemeToggle from "../components/ThemeToggle";
import { useAntivirus } from "../services/antivirusService";

const Login = () => {
  const navigate = useNavigate();
  const { loading, error } = useAuth();
  const antivirus = useAntivirus();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showDebug, setShowDebug] = useState(false);
  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const resolvedServerUrl =
      antivirus.settings.serverUrl || authService.getStoredServerUrl();
    const result = await authService.login(email, password, resolvedServerUrl);
    if (result.ok) {
      navigate("/dashboard");
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center px-6">
      <div className="absolute right-6 top-6">
        <ThemeToggle />
      </div>
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -20 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="w-full max-w-xl"
      >
        <div className="glass-panel rounded-3xl p-10 shadow-glow">
          <div className="flex flex-col gap-4">
            <img
              src={logoUrl}
              alt="Aydo Security"
              className="h-12 w-auto object-contain"
            />
            <div>
              <p className="text-xs uppercase tracking-[0.3em] text-muted">
                Security Console
              </p>
              <h1 className="font-display text-3xl font-semibold text-slate-900 dark:text-white">
                Threat Operations Login
              </h1>
              <p className="mt-2 text-sm text-muted">
                Authenticate to the AV command center to monitor telemetry and
                trigger scans.
              </p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="mt-8 flex flex-col gap-4">
            <Input
              type="email"
              label="Email"
              variant="bordered"
              value={email}
              onValueChange={setEmail}
              classNames={{
                inputWrapper: "border-white/10 bg-white/5",
                label: "text-muted",
              }}
              isRequired
            />
            <Input
              type="password"
              label="Password"
              variant="bordered"
              value={password}
              onValueChange={setPassword}
              classNames={{
                inputWrapper: "border-white/10 bg-white/5",
                label: "text-muted",
              }}
              isRequired
            />

            <AnimatePresence>
              {error ? (
                <motion.div
                  initial={{ opacity: 0, y: -6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -6 }}
                  className="rounded-2xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger"
                >
                  {error}
                </motion.div>
              ) : null}
            </AnimatePresence>

            {error?.toLowerCase().includes("bridge") ? (
              <button
                type="button"
                onClick={() => setShowDebug((value) => !value)}
                className="text-left text-xs font-semibold uppercase tracking-[0.2em] text-accent"
              >
                {showDebug ? "Hide diagnostics" : "Show diagnostics"}
              </button>
            ) : null}

            <BridgeDebug visible={showDebug} />

            <Button
              type="submit"
              className="mt-2 bg-accent text-white font-semibold"
              isLoading={loading}
            >
              {loading ? "Signing in" : "Access Console"}
            </Button>

            <Button
              variant="light"
              className="mt-1 text-muted hover:text-white"
              onClick={async () => {
                const result = await authService.continueAsGuest();
                if (result.ok) navigate("/dashboard");
              }}
              isDisabled={loading}
            >
              Continue as Guest
            </Button>
          </form>

          <div className="mt-6 flex items-center gap-3 rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-xs text-muted">
            <Lock size={14} className="text-accent" />
            <span>
              Secure access · Engine connection required · Audit-ready session
            </span>
          </div>

          <div className="mt-6 flex justify-between items-center">
            <button
              onClick={() => navigate("/register")}
              className="text-xs font-semibold uppercase tracking-[0.25em] text-accent"
            >
              New here? Register
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default Login;
