import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AlertTriangle, Play, Loader2, Info, Zap, Search, Ban } from 'lucide-react';
import { cn } from '@/lib/utils';

const INPUT_CLS =
  'font-mono text-sm h-10 bg-input border-border text-foreground placeholder:text-muted-foreground/40 focus-visible:ring-ring';

// CVE mode definitions - label, description, icon, and what gets shown in the sidebar badge
const CVE_MODES = [
  {
    value: 'skip',
    label: 'Skip',
    icon: Ban,
    description: 'No CVE lookups. Fastest - port + service detection only.',
    badge: 'No CVE',
    badgeCls: 'text-muted-foreground bg-muted',
  },
  {
    value: 'quick',
    label: 'Quick',
    icon: Zap,
    description: 'CPE + versioned keyword. One attempt, no retries. May miss some CVEs.',
    badge: 'Quick CVE',
    badgeCls: 'text-sky-400 bg-sky-400/10',
  },
  {
    value: 'full',
    label: 'Full',
    icon: Search,
    description: 'CPE + keyword + name fallback. 3 retries on rate limits. Recommended.',
    badge: 'Full CVE',
    badgeCls: 'text-emerald-400 bg-emerald-400/15',
  },
];

function CveModeSelector({ value, onChange, disabled }) {
  return (
    <div className="space-y-1.5">
      <span className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono">
        CVE Lookup
      </span>
      <div className="grid grid-cols-3 gap-1.5 p-1 rounded-md border border-border bg-secondary/40">
        {CVE_MODES.map((mode) => {
          const Icon = mode.icon;
          const isActive = value === mode.value;
          return (
            <button
              key={mode.value}
              type="button"
              disabled={disabled}
              onClick={() => onChange(mode.value)}
              title={mode.description}
              className={cn(
                'relative flex flex-col items-center gap-1 rounded px-2 py-2 text-[10px] font-semibold font-mono uppercase tracking-wide transition-all select-none',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                'disabled:pointer-events-none disabled:opacity-50',
                isActive
                  ? 'bg-card text-foreground shadow-sm border border-border/80'
                  : 'text-muted-foreground hover:text-foreground hover:bg-card/50',
              )}
              aria-pressed={isActive}
            >
              <Icon
                className={cn(
                  'size-3.5',
                  isActive ? 'text-foreground' : 'text-muted-foreground/60',
                )}
              />
              {mode.label}
            </button>
          );
        })}
      </div>
      {/* Active mode description */}
      <p className="text-[10px] font-mono text-muted-foreground/60 leading-relaxed px-0.5">
        {CVE_MODES.find((m) => m.value === value)?.description}
      </p>
    </div>
  );
}

export { CVE_MODES };

export function ScanForm({ onSubmit, isScanning, className }) {
  const [target, setTarget] = useState('');
  const [portStart, setPortStart] = useState('1');
  const [portEnd, setPortEnd] = useState('1024');
  const [timeout, setTimeoutVal] = useState('1');
  const [cveMode, setCveMode] = useState('full');
  const [error, setError] = useState(null);

  function sanitizeNumericInput(value) {
    return value.replace(/\D/g, '');
  }

  function parseNumericValue(value) {
    if (value.trim() === '') return NaN;
    return Number(value);
  }

  function handleSubmit(e) {
    e.preventDefault();
    setError(null);

    const parsedPortStart = parseNumericValue(portStart);
    const parsedPortEnd = parseNumericValue(portEnd);
    const parsedTimeout = parseNumericValue(timeout);

    if (!target.trim()) {
      setError('Target is required.');
      return;
    }
    if (!Number.isInteger(parsedPortStart) || parsedPortStart < 1 || parsedPortStart > 65535) {
      setError('Port start must be between 1 and 65535.');
      return;
    }
    if (
      !Number.isInteger(parsedPortEnd) ||
      parsedPortEnd < parsedPortStart ||
      parsedPortEnd > 65535
    ) {
      setError('Port end must be >= port start and <= 65535.');
      return;
    }
    if (!Number.isInteger(parsedTimeout) || parsedTimeout <= 0 || parsedTimeout > 300) {
      setError('Port wait must be between 1 and 300 seconds.');
      return;
    }

    onSubmit({
      target: target.trim(),
      port_start: parsedPortStart,
      port_end: parsedPortEnd,
      timeout: parsedTimeout,
      cve_mode: cveMode,
    });
  }

  return (
    <div className={cn('rounded-md border border-border bg-card', className)}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <span className="text-xs font-semibold uppercase tracking-[0.15em] text-foreground font-mono">
          New Scan
        </span>
        <span className="text-[10px] font-mono text-muted-foreground tracking-wide">
          POST /api/scan
        </span>
      </div>

      {/* Form body */}
      <div className="p-4">
        <form onSubmit={handleSubmit} aria-label="Scan configuration">
          {/* Top row: target + port range + timeout */}
          <div className="grid grid-cols-1 md:grid-cols-[minmax(0,2.8fr)_repeat(3,minmax(0,1fr))] gap-3 items-end">
            {/* Target */}
            <div className="space-y-1.5 min-w-0">
              <label
                htmlFor="target"
                className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono"
              >
                Target - IP or Hostname
              </label>
              <Input
                id="target"
                type="text"
                placeholder="192.168.1.1 / host.docker.internal"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isScanning}
                autoComplete="off"
                spellCheck={false}
                className={cn(INPUT_CLS, 'w-full')}
              />
            </div>

            {/* Port Start */}
            <div className="space-y-1.5 min-w-0">
              <label
                htmlFor="port-start"
                className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono"
              >
                Port Start
              </label>
              <Input
                id="port-start"
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                value={portStart}
                onChange={(e) => setPortStart(sanitizeNumericInput(e.target.value))}
                disabled={isScanning}
                className={cn(INPUT_CLS, 'text-center w-full')}
              />
            </div>

            {/* Port End */}
            <div className="space-y-1.5 min-w-0">
              <label
                htmlFor="port-end"
                className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono"
              >
                Port End
              </label>
              <Input
                id="port-end"
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                value={portEnd}
                onChange={(e) => setPortEnd(sanitizeNumericInput(e.target.value))}
                disabled={isScanning}
                className={cn(INPUT_CLS, 'text-center w-full')}
              />
            </div>

            {/* Port wait */}
            <div className="space-y-1.5 min-w-0">
              <label
                htmlFor="timeout"
                className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono"
              >
                Port Wait - S
              </label>
              <Input
                id="timeout"
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                value={timeout}
                onChange={(e) => setTimeoutVal(sanitizeNumericInput(e.target.value))}
                disabled={isScanning}
                className={cn(INPUT_CLS, 'text-center w-full')}
              />
            </div>
          </div>

          {/* CVE mode row */}
          <div className="mt-4">
            <CveModeSelector value={cveMode} onChange={setCveMode} disabled={isScanning} />
          </div>

          {error && (
            <p className="mt-3 text-xs text-red-400 flex items-center gap-1.5" role="alert">
              <span className="font-mono">!</span> {error}
            </p>
          )}

          {/* Footer row */}
          <div className="flex items-center justify-between mt-5 pt-4 border-t border-border">
            <div>
              <p className="flex items-center gap-1.5 text-[11px] text-muted-foreground/60">
                <AlertTriangle className="size-3 shrink-0" />
                Only scan hosts you own or have explicit permission to scan.
              </p>
              <p className="flex items-center gap-1.5 text-[11px] text-muted-foreground/60">
                <Info className="size-3 shrink-0" />
                If running in Docker, use <code>host.docker.internal</code> as the target to scan
                the host machine.
              </p>
            </div>
            <Button
              type="submit"
              disabled={isScanning}
              className="bg-foreground text-background hover:bg-foreground/90 font-semibold gap-2 h-9 px-5"
            >
              {isScanning ? (
                <>
                  <Loader2 className="size-3.5 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Play className="size-3.5 fill-current" />
                  Start Scan
                </>
              )}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
