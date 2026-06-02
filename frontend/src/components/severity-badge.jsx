import { cn } from '@/lib/utils';

const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-500/15 text-red-400 border border-red-500/25',
  HIGH: 'bg-orange-500/15 text-orange-400 border border-orange-500/25',
  MEDIUM: 'bg-amber-500/15 text-amber-400 border border-amber-500/25',
  LOW: 'bg-blue-500/15 text-blue-400 border border-blue-500/25',
  NONE: 'bg-muted text-muted-foreground border border-border',
};

export function SeverityBadge({ severity, className }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold font-mono uppercase tracking-wider',
        SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.NONE,
        className,
      )}
    >
      {severity}
    </span>
  );
}
