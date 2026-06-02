import { Loader2, XCircle } from 'lucide-react';

// scan shape from real API poll response:
// { status, target, port_range_start, port_range_end, error? }

export function ScanStatus({ scan }) {
  if (scan.status === 'error') {
    return (
      <div
        className="flex items-start gap-3 rounded border border-red-500/30 bg-red-500/5 p-4"
        role="alert"
      >
        <XCircle className="size-4 text-red-400 mt-0.5 shrink-0" aria-hidden="true" />
        <div className="space-y-1">
          <p className="text-sm font-medium text-red-400">Scan failed</p>
          <p className="text-xs text-red-400/70 font-mono">
            {scan.error ?? 'An unknown error occurred.'}
          </p>
        </div>
      </div>
    );
  }

  const portStart = scan.port_range_start ?? scan.port_start;
  const portEnd = scan.port_range_end ?? scan.port_end;

  const label =
    scan.status === 'pending'
      ? `Initializing scan for ${scan.target}…`
      : `Scanning ${scan.target} — ports ${portStart}–${portEnd}…`;

  return (
    <div
      className="flex items-center gap-3 rounded border border-border bg-card p-4"
      role="status"
      aria-live="polite"
    >
      <Loader2 className="size-4 text-primary animate-spin shrink-0" aria-hidden="true" />
      <span className="text-sm font-mono text-foreground">{label}</span>
    </div>
  );
}
