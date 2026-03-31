import type { AvConnectionState } from "@shared/antivirus";

const statusMap: Record<
  AvConnectionState,
  { label: string; className: string; animate: boolean }
> = {
  connected: {
    label: "Connected",
    className: "bg-success/15 text-success",
    animate: false,
  },
  connecting: {
    label: "Connecting",
    className: "bg-warning/15 text-warning",
    animate: true,
  },
  reconnecting: {
    label: "Reconnecting",
    className: "bg-warning/15 text-warning",
    animate: true,
  },
  disconnected: {
    label: "Disconnected",
    className: "bg-danger/15 text-danger",
    animate: false,
  },
};

const StatusPill = ({
  state,
  message,
}: {
  state: AvConnectionState;
  message?: string;
}) => {
  const { label, className, animate } = statusMap[state];
  return (
    <div
      className={`flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold ${className}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full bg-current ${animate ? "status-dot-animate" : ""}`}
      />
      <span>{label}</span>
      {message ? (
        <span className="hidden text-[10px] font-normal text-muted md:inline">
          {message}
        </span>
      ) : null}
    </div>
  );
};

export default StatusPill;
