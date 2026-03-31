import { Button, Skeleton } from "@nextui-org/react";
import { motion } from "framer-motion";
import {
  BellRing,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Cpu,
  Database,
  Radar,
  Sigma,
  Cloud,
  Timer,
  ArrowRight,
  FolderSearch,
} from "lucide-react";
import FilePicker, { type PickerMode } from "../components/FilePicker";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import ActivityChart from "../components/ActivityChart";
import DonutChart from "../components/DonutChart";
import EventsTable from "../components/EventsTable";
import KpiCard from "../components/KpiCard";
import Shell from "../components/Shell";
import { antivirusService, useAntivirus } from "../services/antivirusService";

/* ── stagger children ── */
const container = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.07 },
  },
};
const child = {
  hidden: { opacity: 0, y: 14 },
  show: { opacity: 1, y: 0, transition: { duration: 0.35, ease: "easeOut" } },
};

/* ── Deduplicate similar events ── */
function deduplicateEvents<
  T extends { id: string; message: string; type: string },
>(events: T[]): (T & { count: number })[] {
  const seen = new Map<string, T & { count: number }>();
  for (const event of events) {
    // Normalize the key — strip timestamps, whitespace diffs, etc.
    const key = `${event.type}::${event.message.trim().toLowerCase()}`;
    const existing = seen.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      seen.set(key, { ...event, count: 1 });
    }
  }
  return Array.from(seen.values());
}

const Dashboard = () => {
  const antivirus = useAntivirus();
  const [severityFilter, setSeverityFilter] = useState<
    "all" | "high" | "medium" | "low"
  >("all");
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
    const result = await antivirusService.startScan({
      depth: deepScan ? "deep" : antivirus.settings.scanDepth,
      paths: [path],
      recursive,
    });
    if (!result.ok) {
      toast.message(result.message);
    }
  };

  useEffect(() => {
    const unsubscribe = antivirusService.onEvent(({ event }) => {
      if (event.type === "threat_detected") {
        toast.error(event.message, {
          description: "Immediate remediation applied.",
        });
      }
      if (event.type === "scan_complete") {
        toast.success("Scan completed", { description: "No action required - file is safe." });
      }
      if (event.type === "status" && event.severity !== "low") {
        toast.message(event.message);
      }
    });

    return () => unsubscribe();
  }, []);

  const lastScanMinutes = antivirus.stats.lastScanAt
    ? Math.max(
        1,
        Math.round(
          (Date.now() - new Date(antivirus.stats.lastScanAt).getTime()) / 60000,
        ),
      )
    : 0;
  const lastScanLabel = antivirus.stats.lastScanAt
    ? `${lastScanMinutes} min ago`
    : "Never";

  /* ── Filtered + deduplicated events ── */
  const filteredEvents = useMemo(() => {
    const base =
      severityFilter === "all"
        ? antivirus.recentEvents
        : antivirus.recentEvents.filter(
            (event) => event.severity === severityFilter,
          );
    return deduplicateEvents(base);
  }, [antivirus.recentEvents, severityFilter]);

  const capabilities = [
    {
      key: "driver",
      label: "Driver",
      icon: Cpu,
      state: antivirus.capabilities.driver ? "online" : "unknown",
    },
    {
      key: "hashdb",
      label: "Hash DB",
      icon: Database,
      state: antivirus.capabilities.hashdb ? "online" : "unknown",
    },
    {
      key: "yara",
      label: "YARA",
      icon: Radar,
      state: antivirus.capabilities.yara ? "online" : "unknown",
    },
    {
      key: "entropy",
      label: "Entropy",
      icon: Sigma,
      state: antivirus.capabilities.entropy ? "online" : "unknown",
    },
    {
      key: "cloud",
      label: "Cloud",
      icon: Cloud,
      state: antivirus.capabilities.cloud ? "online" : "unknown",
    },
  ];

  const capabilityStyle = (state: "online" | "standby" | "unknown") => {
    switch (state) {
      case "online":
        return "border-accent/40 bg-accent/10 text-accent";
      case "standby":
        return "border-white/10 bg-white/5 text-muted";
      default:
        return "border-white/10 bg-white/5 text-slate-500 dark:text-white/40";
    }
  };

  const onlineCount = capabilities.filter((c) => c.state === "online").length;

  return (
    <Shell
      title="Dashboard"
      subtitle="Realtime engine telemetry and incident stream."
    >
      <motion.div
        variants={container}
        initial="hidden"
        animate="show"
        className="flex flex-col gap-6"
      >
        {/* ── Hero status banner ── */}
        <motion.div variants={child}>
          <div className="glass-panel relative overflow-hidden rounded-2xl p-6">
            {/* Subtle accent glow */}
            <div className="pointer-events-none absolute -right-20 -top-20 h-60 w-60 rounded-full bg-accent/10 blur-3xl" />
            <div className="relative flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-4">
                <div
                  className={`flex h-12 w-12 items-center justify-center rounded-2xl ${
                    antivirus.connectionState === "connected"
                      ? "bg-success/15 text-success"
                      : antivirus.connectionState === "connecting" ||
                          antivirus.connectionState === "reconnecting"
                        ? "bg-warning/15 text-warning animate-pulse"
                        : "bg-danger/15 text-danger"
                  }`}
                >
                  {antivirus.connectionState === "connected" ? (
                    <ShieldCheck size={24} />
                  ) : antivirus.connectionState === "connecting" ||
                    antivirus.connectionState === "reconnecting" ? (
                    <ShieldAlert size={24} className="animate-spin-slow" />
                  ) : (
                    <ShieldAlert size={24} />
                  )}
                </div>
                <div>
                  <h2 className="font-display text-lg font-semibold text-slate-900 dark:text-white">
                    {antivirus.connectionState === "connected"
                      ? "Protection Active"
                      : antivirus.connectionState === "connecting"
                        ? "Starting Engine..."
                        : antivirus.connectionState === "reconnecting"
                          ? "Reconnecting..."
                          : "Engine Offline"}
                  </h2>
                  <p className="text-sm text-muted">
                    {antivirus.connectionState === "connected"
                      ? `${onlineCount}/${capabilities.length} modules online · Last scan ${lastScanLabel}`
                      : antivirus.statusMessage || "Waiting for service..."}
                  </p>
                </div>
              </div>

              {antivirus.scan.inProgress ? (
                <div className="flex items-center gap-3 rounded-full border border-accent/30 bg-accent/10 px-4 py-2">
                  <div className="h-2 w-2 rounded-full bg-accent status-dot-animate" />
                  <span className="text-xs font-semibold text-accent">
                    Scanning {antivirus.scan.target ?? "file"} ·{" "}
                    {antivirus.scan.progress}%
                  </span>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    className="bg-accent text-white font-semibold shadow-md shadow-accent/20"
                    startContent={<ArrowRight size={14} />}
                    onClick={() => openPicker("file")}
                    isDisabled={antivirus.connectionState !== "connected"}
                  >
                    Scan File
                  </Button>
                  <Button
                    size="sm"
                    className="bg-white/10 text-white font-semibold border border-white/15 shadow-md hover:bg-white/15"
                    startContent={<FolderSearch size={14} />}
                    onClick={() => openPicker("directory")}
                    isDisabled={antivirus.connectionState !== "connected"}
                  >
                    Scan Directory
                  </Button>
                </div>
              )}
            </div>
          </div>
        </motion.div>

        {/* ── KPI cards ── */}
        <motion.div
          variants={child}
          className="grid gap-4 md:grid-cols-2 xl:grid-cols-4"
        >
          {antivirus.loading ? (
            Array.from({ length: 4 }).map((_, index) => (
              <Skeleton key={index} className="h-32 rounded-2xl" />
            ))
          ) : (
            <>
              <KpiCard
                title="Daily Events"
                value={antivirus.stats.dailyActivity}
                helper="Processed today"
                icon={<BellRing size={18} />}
              />
              <KpiCard
                title="Detections"
                value={antivirus.stats.detections}
                helper="Threats blocked"
                icon={<ShieldAlert size={18} />}
              />
              <KpiCard
                title="Quarantined"
                value={antivirus.stats.quarantined}
                helper="Isolated files"
                icon={<ShieldX size={18} />}
              />
              <KpiCard
                title="Last Scan"
                value={lastScanMinutes}
                helper={
                  antivirus.stats.lastScanAt ? "Minutes ago" : "No scan yet"
                }
                icon={<Timer size={18} />}
              />
            </>
          )}
        </motion.div>

        {/* ── Capabilities row ── */}
        <motion.div variants={child} className="glass-panel rounded-2xl p-5">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div>
              <p className="section-header">Modules</p>
              <h2 className="section-title">Engine Capabilities</h2>
            </div>
            <p className="text-xs text-muted">
              {onlineCount} of {capabilities.length} active
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {capabilities.map((cap) => {
              const Icon = cap.icon;
              return (
                <div
                  key={cap.key}
                  className={`flex items-center gap-2 rounded-full border px-3.5 py-2 text-xs font-semibold transition-colors duration-200 ${capabilityStyle(cap.state)}`}
                >
                  <Icon size={14} />
                  {cap.label}
                  {cap.state === "online" && (
                    <span className="h-1.5 w-1.5 rounded-full bg-current status-dot-animate" />
                  )}
                </div>
              );
            })}
          </div>
        </motion.div>

        {/* ── Charts row ── */}
        <motion.div
          variants={child}
          className="grid gap-4 lg:grid-cols-[2fr_1fr]"
        >
          <div className="glass-panel rounded-2xl p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="section-header">Activity</p>
                <h2 className="section-title">Protection Pulse</h2>
              </div>
            </div>
            <div className="mt-5">
              <ActivityChart data={antivirus.activity} />
            </div>
          </div>

          <div className="glass-panel rounded-2xl p-6">
            <p className="section-header">Distribution</p>
            <h2 className="section-title">Threat Breakdown</h2>
            <div className="mt-5">
              <DonutChart data={antivirus.breakdown} />
            </div>
            <div className="mt-4 grid gap-1.5 text-xs text-muted">
              {antivirus.breakdown.map((item) => (
                <div
                  key={item.label}
                  className="flex items-center justify-between py-0.5"
                >
                  <span>{item.label}</span>
                  <span className="font-semibold text-slate-900 dark:text-white">
                    {item.value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* ── Event log ── */}
        <motion.div variants={child} className="glass-panel rounded-2xl p-6">
          <div className="flex flex-wrap items-center justify-between gap-4 mb-5">
            <div>
              <p className="section-header">Live Feed</p>
              <h2 className="section-title">Engine Logs</h2>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-muted mr-1">
                {filteredEvents.length} events
              </span>
              {(["all", "high", "medium", "low"] as const).map((level) => (
                <button
                  key={level}
                  type="button"
                  onClick={() => setSeverityFilter(level)}
                  className={`rounded-full px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.15em] transition-all duration-200 ${
                    severityFilter === level
                      ? "bg-accent text-white shadow-sm shadow-accent/30"
                      : "border border-white/10 bg-white/5 text-muted hover:border-accent/30 hover:text-accent"
                  }`}
                >
                  {level}
                </button>
              ))}
            </div>
          </div>
          <EventsTable events={filteredEvents} />
        </motion.div>
      </motion.div>

      {/* File/Directory Picker Modal */}
      <FilePicker
        open={pickerOpen}
        mode={pickerMode}
        onClose={() => setPickerOpen(false)}
        onSelect={handlePickerSelect}
      />
    </Shell>
  );
};

export default Dashboard;
