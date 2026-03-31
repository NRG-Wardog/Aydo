import { Button, Avatar } from "@nextui-org/react";
import { Moon, Sun, Play, Plug, PlugZap, FolderSearch } from "lucide-react";
import { useState } from "react";
import FilePicker, { type PickerMode } from "./FilePicker";
import { useTheme } from "next-themes";
import { useAuth } from "../services/authService";
import { antivirusService, useAntivirus } from "../services/antivirusService";

const connectionDot: Record<string, string> = {
  connected: "bg-success",
  connecting: "bg-warning status-dot-animate",
  reconnecting: "bg-warning status-dot-animate",
  disconnected: "bg-danger",
};

const Topbar = ({ title, subtitle }: { title: string; subtitle?: string }) => {
  const { user } = useAuth();
  const { theme, setTheme } = useTheme();
  const antivirus = useAntivirus();

  const toggleTheme = () => {
    setTheme(theme === "dark" ? "light" : "dark");
  };

  const [pickerOpen, setPickerOpen] = useState(false);
  const [pickerMode, setPickerMode] = useState<PickerMode>("file");

  const openPicker = (mode: PickerMode) => {
    setPickerMode(mode);
    setPickerOpen(true);
  };

  const handlePickerSelect = async (
    path: string,
    recursive?: boolean,
    deepScan?: boolean,
  ) => {
    await antivirusService.startScan({
      depth: deepScan ? "deep" : antivirus.settings.scanDepth,
      paths: [path],
      recursive,
    });
  };

  const handleConnection = async () => {
    if (antivirus.connectionState === "connected") {
      await antivirusService.disconnect();
    } else {
      await antivirusService.connect();
    }
  };

  const isConnected = antivirus.connectionState === "connected";
  const isScanInProgress = antivirus.scan.inProgress;

  return (
    <>
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200/70 bg-slate-50/90 px-8 py-5 backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/40">
        {/* Left: page title */}
        <div>
          <p className="section-header">Aydo Command</p>
          <h1 className="font-display text-2xl font-semibold text-slate-900 dark:text-white">
            {title}
          </h1>
          {subtitle ? (
            <p className="mt-0.5 text-sm text-muted">{subtitle}</p>
          ) : null}
        </div>

        {/* Right: compact actions */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Compact connection indicator */}
          <button
            onClick={handleConnection}
            className="flex items-center gap-2 rounded-full border border-slate-200/60 bg-white/70 px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:border-accent/40 dark:border-white/10 dark:bg-white/5 dark:text-white/80 dark:hover:border-accent/40"
          >
            <span
              className={`h-2 w-2 rounded-full ${connectionDot[antivirus.connectionState] ?? "bg-danger"}`}
            />
            {isConnected ? (
              <>
                <PlugZap size={13} className="text-success" />
                <span>Connected</span>
              </>
            ) : (
              <>
                <Plug size={13} className="text-muted" />
                <span className="capitalize">{antivirus.connectionState}</span>
              </>
            )}
          </button>

          {/* Scan buttons */}
          <Button
            size="sm"
            className="bg-accent text-white font-semibold shadow-md shadow-accent/20"
            startContent={<Play size={14} />}
            onClick={() => openPicker("file")}
            isDisabled={!isConnected || isScanInProgress}
            isLoading={isScanInProgress}
          >
            Scan File
          </Button>
          <Button
            size="sm"
            className="bg-white/10 text-white font-semibold border border-white/15 shadow-md hover:bg-white/15"
            startContent={<FolderSearch size={14} />}
            onClick={() => openPicker("directory")}
            isDisabled={!isConnected}
          >
            Scan Dir
          </Button>

          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            className="flex h-9 w-9 items-center justify-center rounded-full border border-slate-200/60 bg-white/70 text-slate-700 transition hover:text-slate-900 dark:border-white/10 dark:bg-white/5 dark:text-white/70 dark:hover:text-white"
            aria-label="Toggle theme"
          >
            {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
          </button>

          {/* User avatar */}
          <div className="flex items-center gap-2.5 pl-1">
            <Avatar
              size="sm"
              name={user?.name ?? "Analyst"}
              src={user?.avatarUrl ?? undefined}
              className="bg-accent/20 text-accent"
            />
            <div className="hidden text-xs sm:block">
              <p className="font-semibold text-slate-900 dark:text-white">
                {user?.name ?? "Analyst"}
              </p>
              <p className="text-muted">{user?.role ?? "Security"}</p>
            </div>
          </div>
        </div>
      </header>

      {/* File/Directory Picker modal */}
      <FilePicker
        open={pickerOpen}
        mode={pickerMode}
        onClose={() => setPickerOpen(false)}
        onSelect={handlePickerSelect}
      />
    </>
  );
};

export default Topbar;
