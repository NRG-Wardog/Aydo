import { useCallback, useEffect, useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  File,
  Folder,
  FolderOpen,
  ArrowLeft,
  HardDrive,
  Check,
  X,
  ChevronRight,
  Search,
  FolderTree,
  ToggleLeft,
  ToggleRight,
} from "lucide-react";

/* ── Types ─────────────────────────────────────────────── */

export type PickerMode = "file" | "directory";

interface FileEntry {
  name: string;
  path: string;
  isDirectory: boolean;
  size?: number;
  extension?: string;
}

interface FilePickerProps {
  open: boolean;
  mode: PickerMode;
  onClose: () => void;
  onSelect: (path: string, recursive?: boolean, deepScan?: boolean) => void;
}

/* ── Helpers ───────────────────────────────────────────── */

const formatSize = (bytes?: number): string => {
  if (bytes === undefined || bytes === null) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

const getFileIcon = (entry: FileEntry) => {
  if (entry.isDirectory) return Folder;
  return File;
};

const extensionColor = (ext?: string): string => {
  if (!ext) return "text-slate-400 dark:text-white/40";
  const e = ext.toLowerCase();
  if ([".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1"].includes(e))
    return "text-danger";
  if (
    [
      ".js",
      ".ts",
      ".tsx",
      ".jsx",
      ".py",
      ".lua",
      ".cpp",
      ".c",
      ".h",
      ".rs",
    ].includes(e)
  )
    return "text-accent";
  if ([".zip", ".rar", ".7z", ".tar", ".gz"].includes(e)) return "text-warning";
  if ([".jpg", ".png", ".gif", ".svg", ".webp", ".ico"].includes(e))
    return "text-success";
  return "text-slate-400 dark:text-white/40";
};

/* ── Animations ────────────────────────────────────────── */

const overlayVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { duration: 0.2 } },
  exit: { opacity: 0, transition: { duration: 0.15 } },
};

const panelVariants = {
  hidden: { opacity: 0, scale: 0.95, y: 20 },
  visible: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: { duration: 0.3, ease: [0.16, 1, 0.3, 1] },
  },
  exit: {
    opacity: 0,
    scale: 0.97,
    y: 10,
    transition: { duration: 0.15 },
  },
};

const listItemVariants = {
  hidden: { opacity: 0, x: -8 },
  visible: (i: number) => ({
    opacity: 1,
    x: 0,
    transition: { delay: i * 0.02, duration: 0.2 },
  }),
};

/* ── Drive letters (Windows) ──────────────────────────── */

const COMMON_DRIVES = ["C:\\", "D:\\", "E:\\", "F:\\"];

/* ── Component ─────────────────────────────────────────── */

const FilePicker = ({ open, mode, onClose, onSelect }: FilePickerProps) => {
  const [currentPath, setCurrentPath] = useState<string>("C:\\");
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [recursive, setRecursive] = useState(false);
  const [deepScan, setDeepScan] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [isEditingPath, setIsEditingPath] = useState(false);
  const [pathInput, setPathInput] = useState(currentPath);

  // Sync path input with current path when not editing
  useEffect(() => {
    if (!isEditingPath) {
      setPathInput(currentPath);
    }
  }, [currentPath, isEditingPath]);

  /* ── Read dir via IPC ── */
  const readDirectory = useCallback(async (dirPath: string) => {
    setLoading(true);
    setError(null);
    setSearchQuery("");
    try {
      const bridge = (window as any).avBridge;
      if (!bridge) {
        setError("Bridge unavailable");
        setLoading(false);
        return;
      }
      const result = await bridge.readDirectory(dirPath);
      if (!result.ok) {
        setError(result.error ?? "Failed to read directory");
        setEntries([]);
      } else {
        setEntries(result.entries ?? []);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to read directory");
      setEntries([]);
    } finally {
      setLoading(false);
    }
  }, []);

  /* ── Navigate to path ── */
  const navigateTo = useCallback(
    (path: string) => {
      setHistory((prev) => [...prev, currentPath]);
      setCurrentPath(path);
      setSelectedPath(null);
      readDirectory(path);
    },
    [currentPath, readDirectory],
  );

  /* ── Go back ── */
  const goBack = useCallback(() => {
    if (history.length > 0) {
      const prev = history[history.length - 1];
      setHistory((h) => h.slice(0, -1));
      setCurrentPath(prev);
      setSelectedPath(null);
      readDirectory(prev);
    }
  }, [history, readDirectory]);

  /* ── Go up ── */
  const goUp = useCallback(() => {
    // Navigate to parent directory
    const parts = currentPath.replace(/[\\/]+$/, "").split(/[\\/]/);
    if (parts.length <= 1) return; // Already at root
    const parent = parts.slice(0, -1).join("\\") || parts[0] + "\\";
    navigateTo(parent);
  }, [currentPath, navigateTo]);

  const handlePathSubmit = useCallback(() => {
    setIsEditingPath(false);
    if (pathInput.trim() && pathInput !== currentPath) {
      // Basic normalization - ensure windows paths have trailing slash if it's just a drive
      let target = pathInput.trim();
      if (target.length === 2 && target.endsWith(":")) {
        target += "\\";
      }
      navigateTo(target);
    }
  }, [pathInput, currentPath, navigateTo]);

  /* ── Load initial dir ── */
  useEffect(() => {
    if (open) {
      setHistory([]);
      setSelectedPath(null);
      setRecursive(false);
      setDeepScan(false);
      setSearchQuery("");
      readDirectory(currentPath);
    }
  }, [open]);

  /* ── Filtered entries ── */
  const filteredEntries = useMemo(() => {
    let result = [...entries];

    // In file mode, show everything. In directory mode, only show directories.
    if (mode === "directory") {
      result = result.filter((e) => e.isDirectory);
    }

    // Search filter
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter((e) => e.name.toLowerCase().includes(q));
    }

    // Sort: directories first, then alphabetical
    result.sort((a, b) => {
      if (a.isDirectory && !b.isDirectory) return -1;
      if (!a.isDirectory && b.isDirectory) return 1;
      return a.name.localeCompare(b.name);
    });

    return result;
  }, [entries, mode, searchQuery]);

  /* ── Handle click ── */
  const handleEntryClick = (entry: FileEntry) => {
    if (entry.isDirectory) {
      if (mode === "directory") {
        // In directory mode, single click selects, double click navigates
        setSelectedPath(entry.path);
      } else {
        // In file mode, clicking a directory navigates into it
        navigateTo(entry.path);
      }
    } else {
      // File: select it
      setSelectedPath(entry.path);
    }
  };

  const handleEntryDoubleClick = (entry: FileEntry) => {
    if (entry.isDirectory) {
      navigateTo(entry.path);
    } else {
      // Double-click a file: select and confirm
      onSelect(entry.path);
      onClose();
    }
  };

  /* ── Confirm selection ── */
  const handleConfirm = () => {
    const target = selectedPath ?? (mode === "directory" ? currentPath : null);
    if (target) {
      onSelect(target, mode === "directory" ? recursive : undefined, deepScan);
      onClose();
    }
  };

  /* ── Breadcrumb parts ── */
  const breadcrumbs = useMemo(() => {
    const parts = currentPath.split(/[\\/]/).filter(Boolean);
    const crumbs: { label: string; path: string }[] = [];
    let accumulated = "";
    for (const part of parts) {
      accumulated += part + "\\";
      crumbs.push({ label: part, path: accumulated });
    }
    return crumbs;
  }, [currentPath]);

  if (!open) return null;

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-[100] flex items-center justify-center"
          variants={overlayVariants}
          initial="hidden"
          animate="visible"
          exit="exit"
        >
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={onClose}
          />

          {/* Panel */}
          <motion.div
            variants={panelVariants}
            className="relative z-10 flex flex-col w-[720px] max-h-[80vh] rounded-2xl border border-white/10 bg-gradient-to-b from-slate-900/98 to-slate-950/98 shadow-2xl shadow-black/50 backdrop-blur-xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* ── Header ── */}
            <div className="flex items-center justify-between border-b border-white/10 px-6 py-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent/15 text-accent">
                  {mode === "file" ? (
                    <File size={20} />
                  ) : (
                    <FolderTree size={20} />
                  )}
                </div>
                <div>
                  <h2 className="font-display text-base font-semibold text-white">
                    {mode === "file"
                      ? "Select File to Scan"
                      : "Select Directory to Scan"}
                  </h2>
                  <p className="text-xs text-white/50">
                    {mode === "file"
                      ? "Choose a file for malware analysis"
                      : "Choose a directory for batch scanning"}
                  </p>
                </div>
              </div>
              <button
                onClick={onClose}
                className="flex h-8 w-8 items-center justify-center rounded-lg text-white/40 transition hover:bg-white/10 hover:text-white"
              >
                <X size={18} />
              </button>
            </div>

            {/* ── Toolbar ── */}
            <div className="flex items-center gap-2 border-b border-white/5 px-6 py-3">
              {/* Back */}
              <button
                onClick={goBack}
                disabled={history.length === 0}
                className="flex h-8 w-8 items-center justify-center rounded-lg text-white/50 transition hover:bg-white/10 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
                title="Go back"
              >
                <ArrowLeft size={16} />
              </button>

              {/* Up */}
              <button
                onClick={goUp}
                className="flex h-8 w-8 items-center justify-center rounded-lg text-white/50 transition hover:bg-white/10 hover:text-white"
                title="Go up"
              >
                <Folder size={16} />
              </button>

              {/* Path / Breadcrumbs */}
              <div
                className="flex-1 flex items-center min-w-0 h-8 rounded-lg bg-white/5 border border-white/5 hover:border-white/10 transition-colors cursor-text overflow-hidden group"
                onClick={() => !isEditingPath && setIsEditingPath(true)}
              >
                {isEditingPath ? (
                  <input
                    autoFocus
                    type="text"
                    value={pathInput}
                    onChange={(e) =>
                      setPathInput((e.target as HTMLInputElement).value)
                    }
                    onKeyDown={(e) => {
                      if (e.key === "Enter") handlePathSubmit();
                      if (e.key === "Escape") {
                        setIsEditingPath(false);
                        setPathInput(currentPath);
                      }
                    }}
                    onBlur={handlePathSubmit}
                    className="flex-1 bg-transparent px-3 text-xs text-white outline-none w-full"
                  />
                ) : (
                  <div className="flex items-center gap-1 overflow-x-auto text-xs scrollbar-none flex-1 px-2">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        navigateTo("C:\\");
                      }}
                      className="shrink-0 flex items-center gap-1 rounded px-1.5 py-0.5 text-white/50 transition hover:bg-white/10 hover:text-white"
                    >
                      <HardDrive size={12} />
                    </button>
                    {breadcrumbs.map((crumb, i) => (
                      <div
                        key={crumb.path}
                        className="flex items-center gap-1 shrink-0"
                      >
                        <ChevronRight size={10} className="text-white/20" />
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            navigateTo(crumb.path);
                          }}
                          className={`rounded px-1.5 py-0.5 transition hover:bg-white/10 ${
                            i === breadcrumbs.length - 1
                              ? "text-white font-medium"
                              : "text-white/50 hover:text-white"
                          }`}
                        >
                          {crumb.label}
                        </button>
                      </div>
                    ))}
                    {/* Clickable filler to trigger editing when clicking empty space */}
                    <div className="flex-1 min-w-[20px] h-full" />
                  </div>
                )}
              </div>

              {/* Search */}
              <div className="relative">
                <Search
                  size={14}
                  className="absolute left-2.5 top-1/2 -translate-y-1/2 text-white/30"
                />
                <input
                  type="text"
                  placeholder="Filter..."
                  value={searchQuery}
                  onChange={(e) =>
                    setSearchQuery((e.target as HTMLInputElement).value)
                  }
                  className="h-8 w-40 rounded-lg border border-white/10 bg-white/5 pl-8 pr-3 text-xs text-white placeholder:text-white/30 outline-none focus:border-accent/40 transition"
                />
              </div>
            </div>

            {/* ── Drive bar ── */}
            <div className="flex items-center gap-1.5 border-b border-white/5 px-6 py-2">
              <span className="text-[10px] uppercase tracking-wider text-white/30 mr-2">
                Drives
              </span>
              {COMMON_DRIVES.map((drive) => (
                <button
                  key={drive}
                  onClick={() => navigateTo(drive)}
                  className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-medium transition ${
                    currentPath.startsWith(drive)
                      ? "bg-accent/15 text-accent border border-accent/30"
                      : "text-white/50 hover:bg-white/10 hover:text-white border border-transparent"
                  }`}
                >
                  <HardDrive size={12} />
                  {drive.replace("\\", "")}
                </button>
              ))}
            </div>

            {/* ── File list ── */}
            <div className="flex-1 overflow-y-auto px-3 py-2 min-h-[300px]">
              {loading ? (
                <div className="flex flex-col items-center justify-center h-full gap-3">
                  <div className="h-8 w-8 rounded-full border-2 border-accent/30 border-t-accent animate-spin" />
                  <p className="text-xs text-white/40">Loading directory...</p>
                </div>
              ) : error ? (
                <div className="flex flex-col items-center justify-center h-full gap-2">
                  <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-danger/15 text-danger">
                    <X size={24} />
                  </div>
                  <p className="text-sm text-danger font-medium">
                    Access Denied
                  </p>
                  <p className="text-xs text-white/40 text-center max-w-xs">
                    {error}
                  </p>
                </div>
              ) : filteredEntries.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full gap-2">
                  <Folder size={32} className="text-white/20" />
                  <p className="text-sm text-white/40">
                    {searchQuery
                      ? "No matching items"
                      : mode === "directory"
                        ? "No subdirectories"
                        : "Empty directory"}
                  </p>
                </div>
              ) : (
                <div className="flex flex-col gap-0.5">
                  {filteredEntries.map((entry, i) => {
                    const Icon = getFileIcon(entry);
                    const isSelected = selectedPath === entry.path;
                    return (
                      <motion.button
                        key={entry.path}
                        custom={i}
                        variants={listItemVariants}
                        initial="hidden"
                        animate="visible"
                        onClick={() => handleEntryClick(entry)}
                        onDoubleClick={() => handleEntryDoubleClick(entry)}
                        className={`group flex items-center gap-3 rounded-xl px-3 py-2.5 text-left transition-all duration-150 ${
                          isSelected
                            ? "bg-accent/15 border border-accent/30 shadow-[0_0_12px_rgba(90,130,255,0.1)]"
                            : "border border-transparent hover:bg-white/5"
                        }`}
                      >
                        <div
                          className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition ${
                            entry.isDirectory
                              ? isSelected
                                ? "bg-accent/20 text-accent"
                                : "bg-amber-500/15 text-amber-400"
                              : `bg-white/5 ${extensionColor(entry.extension)}`
                          }`}
                        >
                          {entry.isDirectory && isSelected ? (
                            <FolderOpen size={16} />
                          ) : (
                            <Icon size={16} />
                          )}
                        </div>

                        <div className="flex-1 min-w-0">
                          <p
                            className={`text-sm truncate ${
                              isSelected
                                ? "text-white font-medium"
                                : "text-white/80 group-hover:text-white"
                            }`}
                          >
                            {entry.name}
                          </p>
                        </div>

                        {!entry.isDirectory && entry.size !== undefined && (
                          <span className="shrink-0 text-[11px] text-white/30">
                            {formatSize(entry.size)}
                          </span>
                        )}

                        {entry.isDirectory && (
                          <ChevronRight
                            size={14}
                            className="shrink-0 text-white/20 group-hover:text-white/40 transition"
                          />
                        )}
                      </motion.button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* ── Footer ── */}
            <div className="border-t border-white/10 px-6 py-4">
              {/* Deep scan toggle (always visible) */}
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Search size={14} className="text-white/40" />
                  <span className="text-xs text-white/60">
                    Deep scan (sandbox/dynamic analysis)
                  </span>
                </div>
                <button
                  onClick={() => setDeepScan(!deepScan)}
                  className={`flex items-center gap-2 rounded-full px-3 py-1 text-xs font-medium transition ${
                    deepScan
                      ? "bg-accent/15 text-accent border border-accent/30"
                      : "bg-white/5 text-white/40 border border-white/10 hover:border-white/20"
                  }`}
                >
                  {deepScan ? (
                    <ToggleRight size={16} className="text-accent" />
                  ) : (
                    <ToggleLeft size={16} />
                  )}
                  {deepScan ? "Enabled" : "Disabled"}
                </button>
              </div>

              {/* Recursive toggle (directory mode only) */}
              {mode === "directory" && (
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <FolderTree size={14} className="text-white/40" />
                    <span className="text-xs text-white/60">
                      Scan subdirectories recursively
                    </span>
                  </div>
                  <button
                    onClick={() => setRecursive(!recursive)}
                    className={`flex items-center gap-2 rounded-full px-3 py-1 text-xs font-medium transition ${
                      recursive
                        ? "bg-accent/15 text-accent border border-accent/30"
                        : "bg-white/5 text-white/40 border border-white/10 hover:border-white/20"
                    }`}
                  >
                    {recursive ? (
                      <ToggleRight size={16} className="text-accent" />
                    ) : (
                      <ToggleLeft size={16} />
                    )}
                    {recursive ? "Enabled" : "Disabled"}
                  </button>
                </div>
              )}

              <div className="flex items-center justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-white/30 truncate">
                    {selectedPath
                      ? `Selected: ${selectedPath}`
                      : mode === "directory"
                        ? `Current: ${currentPath}`
                        : "No file selected"}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={onClose}
                    className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-white/60 transition hover:bg-white/10 hover:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleConfirm}
                    disabled={mode === "file" && !selectedPath}
                    className="flex items-center gap-2 rounded-xl bg-accent px-5 py-2 text-sm font-semibold text-white shadow-lg shadow-accent/25 transition hover:bg-accent-soft disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <Check size={14} />
                    {mode === "file" ? "Scan File" : "Scan Directory"}
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default FilePicker;
