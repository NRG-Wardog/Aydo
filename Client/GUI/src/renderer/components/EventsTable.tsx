import {
  Chip,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@nextui-org/react";
import type { AvEvent } from "@shared/antivirus";
import { formatDistanceToNow } from "date-fns";

const severityColor = (severity: AvEvent["severity"]) => {
  switch (severity) {
    case "high":
      return "danger";
    case "medium":
      return "warning";
    default:
      return "success";
  }
};

type DedupedEvent = AvEvent & { count?: number };

const EventsTable = ({ events }: { events: DedupedEvent[] }) => {
  if (!events.length) {
    return (
      <div className="flex h-40 flex-col items-center justify-center gap-2 rounded-2xl border border-slate-200/60 bg-white/70 dark:border-white/10 dark:bg-white/5">
        <p className="text-sm font-medium text-slate-500 dark:text-white/50">
          No logs yet
        </p>
        <p className="text-xs text-muted">
          The engine will stream scans, server calls, and alerts here.
        </p>
      </div>
    );
  }

  return (
    <Table
      aria-label="Recent events"
      removeWrapper
      classNames={{
        base: "rounded-2xl border border-slate-200/60 bg-white/70 dark:border-white/10 dark:bg-white/5",
        th: "bg-transparent text-xs text-muted",
        td: "text-sm text-slate-700 dark:text-white/80",
      }}
    >
      <TableHeader>
        <TableColumn>Time</TableColumn>
        <TableColumn>Type</TableColumn>
        <TableColumn>Severity</TableColumn>
        <TableColumn>Message</TableColumn>
      </TableHeader>
      <TableBody>
        {events.map((event) => (
          <TableRow key={event.id}>
            <TableCell className="text-muted whitespace-nowrap">
              {formatDistanceToNow(new Date(event.timestamp), {
                addSuffix: true,
              })}
            </TableCell>
            <TableCell className="capitalize whitespace-nowrap">
              {event.type.replace(/_/g, " ")}
            </TableCell>
            <TableCell>
              <Chip
                size="sm"
                color={severityColor(event.severity)}
                variant="flat"
              >
                {event.severity}
              </Chip>
            </TableCell>
            <TableCell>
              <span>{event.message}</span>
              {event.count && event.count > 1 ? (
                <span className="ml-2 inline-flex h-5 min-w-[20px] items-center justify-center rounded-full bg-accent/15 px-1.5 text-[10px] font-bold text-accent">
                  ×{event.count}
                </span>
              ) : null}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
};

export default EventsTable;
