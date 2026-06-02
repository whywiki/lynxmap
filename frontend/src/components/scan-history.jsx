import { Plus, Circle, Loader2, CheckCircle2, XCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

const STATUS_MAP = {
  pending: {
    label: 'PENDING',
    className: 'text-muted-foreground bg-muted',
    icon: <Circle className="size-2 fill-current" />,
  },
  running: {
    label: 'RUNNING',
    className: 'text-sky-400 bg-sky-400/10',
    icon: <Loader2 className="size-2.5 animate-spin" />,
  },
  complete: {
    label: 'COMPLETE',
    className: 'text-emerald-400 bg-emerald-400/15',
    icon: <CheckCircle2 className="size-2.5" />,
  },
  error: {
    label: 'ERROR',
    className: 'text-red-400 bg-red-400/10',
    icon: <XCircle className="size-2.5" />,
  },
};

function StatusBadge({ status }) {
  const { label, className, icon } = STATUS_MAP[status] ?? STATUS_MAP.error;
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold font-mono tracking-wide',
        className,
      )}
    >
      {icon}
      {label}
    </span>
  );
}

function formatTime(isoString) {
  if (!isoString) return '--:--:--';
  return new Date(isoString).toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function ScanHistory({ scans, activeScanId, onSelect, onNewScan }) {
  return (
    <aside className="flex flex-col w-70 shrink-0 border-r border-sidebar-border bg-sidebar h-screen sticky top-0 overflow-hidden">
      {/* Logo */}
      <div className="px-4 py-4 border-b border-sidebar-border">
        <div className="flex items-center gap-2.5">
          <div className="size-8 rounded border border-border flex items-center justify-center bg-background">
            {/* Pulse icon matching Image 2 */}
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              className="size-4 text-primary"
            >
              <polyline points="2 12 6 12 8 4 10 20 13 10 15 16 17 12 22 12" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-semibold text-sidebar-foreground leading-tight">LynxMap</p>
            <p className="text-[10px] font-mono text-muted-foreground tracking-wide">
              v0.1.0 · SCANNER
            </p>
          </div>
        </div>
      </div>

      {/* New Scan */}
      <div className="px-3 pt-3">
        <Button
          variant="outline"
          onClick={onNewScan}
          className="w-full h-10 gap-2 text-sm font-medium border-border bg-secondary hover:bg-accent hover:text-foreground text-foreground"
        >
          <Plus className="size-4" />
          New Scan
        </Button>
      </div>

      {/* History label */}
      <div className="flex items-center justify-between px-4 pt-5 pb-2">
        <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground/60 font-mono">
          History
        </p>
        <span className="text-[10px] font-mono text-muted-foreground/40">
          {String(scans.length).padStart(2, '0')}
        </span>
      </div>

      {/* Scan list */}
      <nav className="flex-1 overflow-y-auto px-3 pb-4 space-y-1" aria-label="Scan history">
        {scans.length === 0 && (
          <div className="px-2 py-4 text-center">
            <p className="text-xs text-muted-foreground">No scans yet.</p>
            <p className="text-xs text-muted-foreground/50 mt-0.5">Launch one to begin.</p>
          </div>
        )}
        {scans.map((scan) => {
          const isActive = scan.scan_id === activeScanId;
          const openCount = scan.open_ports ?? 0;
          return (
            <button
              key={scan.scan_id}
              onClick={() => onSelect(scan.scan_id)}
              className={cn(
                'w-full text-left rounded-md px-3 py-2.5 transition-colors',
                isActive ? 'bg-accent/80' : 'hover:bg-accent/40',
              )}
              aria-current={isActive ? 'page' : undefined}
            >
              <div className="flex items-start justify-between gap-2 mb-1.5">
                <span className="font-mono text-sm text-sidebar-foreground truncate leading-tight font-medium">
                  {scan.target}
                </span>
                <StatusBadge status={scan.status} />
              </div>
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-muted-foreground">
                <span>
                  {scan.port_range_start ?? scan.port_start}-{scan.port_range_end ?? scan.port_end}
                </span>
                <span className="text-border">·</span>
                <span>{formatTime(scan.created_at ?? scan.started_at)}</span>
                {scan.status === 'complete' && (
                  <span className="ml-auto text-emerald-400 font-semibold">{openCount} open</span>
                )}
              </div>
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-sidebar-border">
        <p className="text-[10px] font-mono text-muted-foreground/80 leading-relaxed">
          Session-only history.
          <br />
          Scans cleared on reload.
        </p>
      </div>
    </aside>
  );
}
