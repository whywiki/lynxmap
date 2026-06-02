import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AlertTriangle, Play, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

// Shared input class — explicit bg so it matches the dark card bg
const INPUT_CLS =
  'font-mono text-sm h-10 bg-input border-border text-foreground placeholder:text-muted-foreground/40 focus-visible:ring-ring';

export function ScanForm({ onSubmit, isScanning, className }) {
  const [target, setTarget] = useState('');
  const [portStart, setPortStart] = useState(1);
  const [portEnd, setPortEnd] = useState(1024);
  const [timeout, setTimeoutVal] = useState(1);
  const [error, setError] = useState(null);

  function handleSubmit(e) {
    e.preventDefault();
    setError(null);

    if (!target.trim()) {
      setError('Target is required.');
      return;
    }
    if (portStart < 1 || portStart > 65535) {
      setError('Port start must be between 1 and 65535.');
      return;
    }
    if (portEnd < portStart || portEnd > 65535) {
      setError('Port end must be >= port start and <= 65535.');
      return;
    }
    if (timeout <= 0 || timeout > 300) {
      setError('Timeout must be between 1 and 300 seconds.');
      return;
    }

    onSubmit({ target: target.trim(), port_start: portStart, port_end: portEnd, timeout });
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
          {/* Inputs row */}
          <div className="grid grid-cols-[1fr_auto_auto_auto] gap-3 items-end">
            {/* Target */}
            <div className="space-y-1.5">
              <label
                htmlFor="target"
                className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono"
              >
                Target · IP or Hostname
              </label>
              <Input
                id="target"
                type="text"
                placeholder="192.168.1.1 / scanme.nmap.org"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isScanning}
                autoComplete="off"
                spellCheck={false}
                className={INPUT_CLS}
              />
            </div>

            {/* Port Start */}
            <div className="space-y-1.5 w-24">
              <label
                htmlFor="port-start"
                className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono"
              >
                Port Start
              </label>
              <Input
                id="port-start"
                type="number"
                min={1}
                max={65535}
                value={portStart}
                onChange={(e) => setPortStart(Number(e.target.value))}
                disabled={isScanning}
                className={cn(INPUT_CLS, 'text-center')}
              />
            </div>

            {/* Port End */}
            <div className="space-y-1.5 w-24">
              <label
                htmlFor="port-end"
                className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono"
              >
                Port End
              </label>
              <Input
                id="port-end"
                type="number"
                min={1}
                max={65535}
                value={portEnd}
                onChange={(e) => setPortEnd(Number(e.target.value))}
                disabled={isScanning}
                className={cn(INPUT_CLS, 'text-center')}
              />
            </div>

            {/* Timeout */}
            <div className="space-y-1.5 w-24">
              <label
                htmlFor="timeout"
                className="block text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono"
              >
                Timeout · S
              </label>
              <Input
                id="timeout"
                type="number"
                min={1}
                max={300}
                step={1}
                value={timeout}
                onChange={(e) => setTimeoutVal(Number(e.target.value))}
                disabled={isScanning}
                className={cn(INPUT_CLS, 'text-center')}
              />
            </div>
          </div>

          {error && (
            <p className="mt-3 text-xs text-red-400 flex items-center gap-1.5" role="alert">
              <span className="font-mono">!</span> {error}
            </p>
          )}

          {/* Footer row */}
          <div className="flex items-center justify-between mt-5 pt-4 border-t border-border">
            <p className="flex items-center gap-1.5 text-[11px] text-muted-foreground/60">
              <AlertTriangle className="size-3 shrink-0" />
              Only scan hosts you own or have explicit permission to scan.
            </p>
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
