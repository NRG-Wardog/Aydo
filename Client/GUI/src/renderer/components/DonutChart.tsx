import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import type { AvBreakdownItem } from "@shared/antivirus";

const COLORS = ["#3c6cff", "#f4b740", "#f0677c", "#7b8fb3"];

const DonutChart = ({ data }: { data: AvBreakdownItem[] }) => {
  const activeData = data
    .map((item, index) => ({ ...item, originalIndex: index }))
    .filter((item) => item.value > 0);

  if (!activeData.length) {
    return (
      <div className="flex h-56 items-center justify-center text-sm text-muted">
        Waiting for scan results.
      </div>
    );
  }

  if (activeData.length === 1) {
    const color = COLORS[activeData[0].originalIndex % COLORS.length];
    return (
      <div className="flex h-[240px] items-center justify-center">
        <div
          style={{
            width: 180,
            height: 180,
            borderRadius: "50%",
            background: `conic-gradient(${color} 0deg 360deg)`,
            WebkitMask: "radial-gradient(circle, transparent 58px, black 59px)",
            mask: "radial-gradient(circle, transparent 58px, black 59px)",
          }}
        />
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie
          data={activeData}
          innerRadius={60}
          outerRadius={90}
          paddingAngle={3}
          stroke="none"
          dataKey="value"
        >
          {activeData.map((item) => (
            <Cell
              key={`cell-${item.originalIndex}`}
              fill={COLORS[item.originalIndex % COLORS.length]}
            />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: "rgba(10,15,23,0.9)",
            border: "1px solid rgba(90,130,255,0.5)",
            borderRadius: 12,
            color: "#e7edf5",
          }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
};

export default DonutChart;
