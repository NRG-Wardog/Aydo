import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import type { AvActivityPoint } from "@shared/antivirus";

const MAX_VISIBLE_POINTS = 180;
const TARGET_RENDER_POINTS = 90;

const ActivityChart = ({ data }: { data: AvActivityPoint[] }) => {
  if (!data.length) {
    return (
      <div className="flex h-56 items-center justify-center text-sm text-muted">
        No activity yet. The engine will stream data once scanning starts.
      </div>
    );
  }

  const accent = "rgb(var(--color-accent))";
  const recentData = data.slice(-MAX_VISIBLE_POINTS);
  const sampleStep = Math.max(
    1,
    Math.ceil(recentData.length / TARGET_RENDER_POINTS),
  );
  const chartData = recentData.filter(
    (_, index) => index % sampleStep === 0 || index === recentData.length - 1,
  );

  return (
    <ResponsiveContainer width="100%" height={240}>
      <LineChart
        data={chartData}
        margin={{ top: 10, right: 16, left: -10, bottom: 0 }}
      >
        <CartesianGrid stroke="rgba(139,153,173,0.16)" vertical={false} />
        <XAxis
          dataKey="time"
          stroke="rgba(139,153,173,0.6)"
          fontSize={11}
          minTickGap={60}
          tickFormatter={(value) =>
            value.split(":")[0] + ":" + value.split(":")[1]
          } // Hide seconds in axis
        />
        <YAxis
          stroke="rgba(139,153,173,0.6)"
          fontSize={11}
          width={32}
          allowDecimals={false}
          domain={[0, "dataMax + 1"]}
        />
        <Tooltip
          contentStyle={{
            background: "rgba(10,15,23,0.9)",
            border: `1px solid ${accent}`,
            borderRadius: 12,
            color: "#e7edf5",
          }}
          cursor={{ stroke: "rgba(90,130,255,0.35)" }}
        />
        <Line
          type="stepAfter"
          dataKey="value"
          stroke={accent}
          strokeWidth={2.25}
          strokeLinecap="round"
          strokeLinejoin="round"
          isAnimationActive={false}
          dot={false}
          activeDot={{ r: 3, strokeWidth: 0, fill: accent }}
        />
      </LineChart>
    </ResponsiveContainer>
  );
};

export default ActivityChart;
