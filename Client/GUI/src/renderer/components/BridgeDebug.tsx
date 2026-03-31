const getDiagnostics = () => {
  if (typeof window === "undefined") {
    return {
      hasWindow: false,
      isElectron: false,
      protocol: "n/a",
      userAgent: "n/a",
      bridgeKeys: "n/a"
    };
  }

  const userAgent = typeof navigator !== "undefined" ? navigator.userAgent : "n/a";
  const isElectron = /Electron/i.test(userAgent);
  const protocol = window.location?.protocol ?? "n/a";
  const bridge = (window as typeof window & { avBridge?: unknown }).avBridge;
  const bridgeKeys = bridge ? Object.keys(bridge as Record<string, unknown>).join(", ") : "none";
  const preloadStatus = (window as typeof window & { __preloadStatus?: { ok: boolean; error: string | null; sandboxed: boolean } })
    .__preloadStatus;

  return {
    hasWindow: true,
    isElectron,
    protocol,
    userAgent,
    bridgeKeys,
    preloadStatus
  };
};

const BridgeDebug = ({ visible }: { visible: boolean }) => {
  if (!visible) {
    return null;
  }

  const diagnostics = getDiagnostics();

  return (
    <div className="mt-4 rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-[11px] text-muted">
      <p className="text-xs font-semibold uppercase tracking-[0.3em] text-muted">Bridge Diagnostics</p>
      <div className="mt-3 grid gap-2">
        <div>
          <span className="text-muted">Electron UA:</span>{" "}
          <span className="text-slate-900 dark:text-white">
            {diagnostics.isElectron ? "yes" : "no"}
          </span>
        </div>
        <div>
          <span className="text-muted">Protocol:</span>{" "}
          <span className="text-slate-900 dark:text-white">{diagnostics.protocol}</span>
        </div>
        <div>
          <span className="text-muted">Bridge API:</span>{" "}
          <span className="text-slate-900 dark:text-white">{diagnostics.bridgeKeys}</span>
        </div>
        <div>
          <span className="text-muted">Preload status:</span>{" "}
          <span className="text-slate-900 dark:text-white">
            {diagnostics.preloadStatus
              ? diagnostics.preloadStatus.ok
                ? `ok (sandboxed: ${diagnostics.preloadStatus.sandboxed ? "yes" : "no"})`
                : `error: ${diagnostics.preloadStatus.error ?? "unknown"}`
              : "missing"}
          </span>
        </div>
        <div className="text-[10px] text-muted/80">{diagnostics.userAgent}</div>
      </div>
    </div>
  );
};

export default BridgeDebug;
