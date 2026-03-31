import { X, Minus, Square } from "lucide-react";

const TitleBar = () => {
  const handleClose = () => {
    if (typeof window !== "undefined" && (window as any).avBridge) {
      (window as any).avBridge.closeWindow();
    }
  };

  const handleMinimize = () => {
    if (typeof window !== "undefined" && (window as any).avBridge) {
      (window as any).avBridge.minimizeWindow();
    }
  };

  const handleMaximize = () => {
    if (typeof window !== "undefined" && (window as any).avBridge) {
      (window as any).avBridge.maximizeWindow();
    }
  };

  return (
    <div
      className="flex items-center justify-between h-11 bg-slate-900/95 backdrop-blur-2xl border-b border-white/[0.06] select-none fixed top-0 left-0 right-0 z-50"
      style={{ WebkitAppRegion: "drag" as any }}
      data-tauri-drag-region
    >
      <div className="flex items-center gap-2 px-4">
        <div className="absolute left-1/2 transform -translate-x-1/2 pointer-events-none">
          <p className="text-[11px] text-white/50 font-medium tracking-wider">
            Aydo Security
          </p>
        </div>
      </div>

      <div className="flex items-center px-4">
        <div className="flex gap-2">
          <button
            onClick={handleMinimize}
            className="w-3 h-3 rounded-full bg-yellow-500/90 hover:bg-yellow-500 transition-all duration-150 flex items-center justify-center group"
            style={{ WebkitAppRegion: "no-drag" as any }}
            title="Minimize"
          >
            <Minus
              size={8}
              className="opacity-0 group-hover:opacity-100 text-yellow-900 transition-opacity"
            />
          </button>
          <button
            onClick={handleMaximize}
            className="w-3 h-3 rounded-full bg-green-500/90 hover:bg-green-500 transition-all duration-150 flex items-center justify-center group"
            style={{ WebkitAppRegion: "no-drag" as any }}
            title="Maximize"
          >
            <Square
              size={7}
              className="opacity-0 group-hover:opacity-100 text-green-900 transition-opacity"
            />
          </button>
          <button
            onClick={handleClose}
            className="w-3 h-3 rounded-full bg-red-500/90 hover:bg-red-500 transition-all duration-150 flex items-center justify-center group"
            style={{ WebkitAppRegion: "no-drag" as any }}
            title="Close"
          >
            <X
              size={8}
              className="opacity-0 group-hover:opacity-100 text-red-900 transition-opacity"
            />
          </button>
        </div>
      </div>
    </div>
  );
};

export default TitleBar;
