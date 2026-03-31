import { ReactNode } from "react";
import AnimatedNumber from "./AnimatedNumber";

const KpiCard = ({
  title,
  value,
  helper,
  icon,
}: {
  title: string;
  value: number;
  helper: string;
  icon: ReactNode;
}) => {
  return (
    <div className="glass-panel group relative overflow-hidden rounded-2xl p-5 shadow-soft transition-all duration-300 hover:scale-[1.02] hover:shadow-glow">
      {/* Subtle corner glow on hover */}
      <div className="pointer-events-none absolute -right-6 -top-6 h-20 w-20 rounded-full bg-accent/0 blur-2xl transition-all duration-500 group-hover:bg-accent/15" />
      <div className="relative">
        <div className="flex items-center justify-between text-sm text-muted">
          <span>{title}</span>
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/10 text-accent transition-colors duration-300 group-hover:bg-accent/20">
            {icon}
          </span>
        </div>
        <div className="mt-3">
          <AnimatedNumber value={value} />
        </div>
        <p className="mt-2 text-xs text-muted">{helper}</p>
      </div>
    </div>
  );
};

export default KpiCard;
