import { useState } from 'react';
import { ChevronDown, ChevronRight, Circle } from 'lucide-react';
import { SeverityBadge } from '@/components/severity-badge';
import { worstSeverity } from '@/lib/severity';
import { cn } from '@/lib/utils';

// Real API PortResult shape:
// { port, state, protocol, service: { name, version, raw_banner, cves: [...] } | null }
//
// Real API CVE shape:
// { cve_id, description, severity, cvss_score, published_date }
//
// Real API ScanResult shape:
// { scan_id, target, start_time, end_time, ports_scanned, open_ports (int!), results: PortResult[] }

// ---- Stat card ----
function StatCard({ label, value, sub }) {
  return (
    <div className="flex flex-col gap-0.5 px-5 py-4 border-r border-border last:border-r-0">
      <span className="text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono">
        {label}
      </span>
      <span className="font-mono text-3xl font-bold text-foreground leading-tight">{value}</span>
      {sub && <span className="text-[11px] text-muted-foreground font-mono">{sub}</span>}
    </div>
  );
}

// ---- Port state badge ----
function StateBadge({ state }) {
  if (state === 'open') {
    return (
      <span className="inline-flex items-center gap-1.5 text-emerald-400 font-mono text-xs">
        <Circle className="size-2 fill-emerald-400" />
        open
      </span>
    );
  }
  const cls = state === 'filtered' ? 'text-amber-400' : 'text-muted-foreground';
  return <span className={cn('font-mono text-xs', cls)}>{state}</span>;
}

// ---- CVE sub-table ----
function CveTable({ cves, serviceName, version }) {
  if (!cves || cves.length === 0) {
    return (
      <tr>
        <td colSpan={7} className="py-0">
          <div className="px-6 py-3 text-xs text-muted-foreground bg-secondary/20 border-t border-border">
            No known CVEs for this service.
          </div>
        </td>
      </tr>
    );
  }

  return (
    <tr>
      <td colSpan={7} className="py-0">
        <div className="bg-secondary/20 border-t border-border">
          <div className="flex items-center justify-between px-6 py-2 border-b border-border/60">
            <span className="text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground/70 font-mono">
              CVE Detail · {serviceName?.toUpperCase() || 'SERVICE'} ({version || 'unknown'})
            </span>
            <span className="text-[10px] font-mono text-muted-foreground/50">
              {cves.length} records
            </span>
          </div>
          <table className="w-full text-xs" aria-label={`CVEs for ${serviceName}`}>
            <thead>
              <tr className="border-b border-border/40">
                <th className="px-6 py-2 text-left text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground/60 font-mono w-40">
                  CVE ID
                </th>
                <th className="px-4 py-2 text-left text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground/60 font-mono w-24">
                  Severity
                </th>
                <th className="px-4 py-2 text-left text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground/60 font-mono w-16">
                  CVSS
                </th>
                <th className="px-4 py-2 text-left text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground/60 font-mono">
                  Description
                </th>
              </tr>
            </thead>
            <tbody>
              {cves.map((cve) => (
                <tr key={cve.cve_id} className="border-b border-border/30 last:border-0">
                  <td className="px-6 py-3 font-mono text-foreground whitespace-nowrap">
                    {cve.cve_id}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <SeverityBadge severity={cve.severity ?? 'NONE'} />
                  </td>
                  <td className="px-4 py-3 font-mono whitespace-nowrap text-foreground">
                    {cve.cvss_score != null ? Number(cve.cvss_score).toFixed(1) : 'N/A'}
                  </td>
                  <td className="px-4 py-3 text-muted-foreground leading-relaxed whitespace-normal wrap-break-word align-top">
                    <span>{cve.description}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </td>
    </tr>
  );
}

// ---- Port row ----
function PortRow({ port }) {
  const [expanded, setExpanded] = useState(false);

  // Real API: service is an object { name, version, cves } or null
  const svc = port.service;
  const name = svc?.name ?? '—';
  const version = svc?.version ?? '—';
  const cves = svc?.cves ?? [];
  const worst = worstSeverity(cves);

  return (
    <>
      <tr
        className={cn(
          'border-b border-border/40 cursor-pointer select-none transition-colors',
          expanded ? 'bg-accent/30' : 'hover:bg-accent/20',
        )}
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
      >
        <td className="pl-4 pr-2 py-3 w-8">
          {expanded ? (
            <ChevronDown className="size-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="size-4 text-muted-foreground" />
          )}
        </td>
        <td className="px-4 py-3 font-mono text-sm text-foreground whitespace-nowrap">
          {port.port}/{port.protocol}
        </td>
        <td className="px-4 py-3">
          <StateBadge state={port.state} />
        </td>
        <td className="px-4 py-3 font-mono text-sm text-foreground">{name}</td>
        <td className="px-4 py-3 font-mono text-sm text-muted-foreground">{version}</td>
        <td className="px-4 py-3 text-sm font-mono text-center">
          {cves.length > 0 ? (
            <span className="text-foreground">{cves.length}</span>
          ) : (
            <span className="text-muted-foreground/40">0</span>
          )}
        </td>
        <td className="px-4 py-3">
          {cves.length > 0 ? (
            <SeverityBadge severity={worst} />
          ) : (
            <span className="text-xs text-muted-foreground/40">—</span>
          )}
        </td>
      </tr>
      {expanded && <CveTable cves={cves} serviceName={name} version={version} />}
    </>
  );
}

// ---- Main ResultsView ----
export function ResultsView({ scan }) {
  // Real API: results array contains open + filtered ports
  // open_ports is an int count, not an array
  const allResults = scan.results ?? [];
  const openPorts = allResults.filter((p) => p.state === 'open');
  const filteredCount = allResults.filter((p) => p.state === 'filtered').length;

  const duration =
    scan.end_time && scan.start_time
      ? `${((new Date(scan.end_time) - new Date(scan.start_time)) / 1000).toFixed(1)}s`
      : '—';

  const portStart = scan.port_range_start ?? 1;
  const portEnd = scan.port_range_end ?? 1024;

  return (
    <section aria-label="Scan results" className="space-y-6">
      {/* Status Header */}
      <div className="flex items-center justify-between rounded-md border border-border bg-card px-5 py-3">
        <div className="flex items-center gap-3">
          <Circle className="size-2.5 fill-emerald-400 text-emerald-400" />
          <span className="text-xs font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono">
            Scan Complete
          </span>
          <span className="text-muted-foreground">→</span>
          <span className="font-mono text-foreground font-semibold">{scan.target}</span>
        </div>
        <span className="text-[10px] font-mono text-muted-foreground">
          scan_id · {scan.scan_id?.slice(0, 8)}
        </span>
      </div>

      {/* Stat cards */}
      <div className="flex rounded-md border border-border bg-card overflow-hidden">
        <StatCard
          label="Ports Scanned"
          value={(scan.ports_scanned ?? 0).toLocaleString()}
          sub={`range ${portStart}-${portEnd}`}
        />
        <StatCard
          label="Open Ports"
          value={openPorts.length}
          sub={filteredCount > 0 ? `${filteredCount} filtered` : undefined}
        />
        <StatCard label="Scan Duration" value={duration} sub={`timeout ${scan.timeout ?? '—'}s`} />
      </div>

      {/* Ports table */}
      <div className="rounded-md border border-border overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3 border-b border-border bg-card">
          <span className="text-xs font-semibold uppercase tracking-[0.15em] text-foreground font-mono">
            Open Ports
          </span>
          <span className="text-[10px] font-mono text-muted-foreground">
            {openPorts.length} records · click row to expand
          </span>
        </div>

        {openPorts.length === 0 ? (
          <div className="px-5 py-8 text-center text-sm text-muted-foreground">
            No open ports found.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm" aria-label="Open ports">
              <thead>
                <tr className="border-b border-border bg-secondary/30">
                  <th className="pl-4 pr-2 py-2.5 w-8" aria-label="Expand" />
                  <th className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono whitespace-nowrap">
                    Port
                  </th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono">
                    State
                  </th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono">
                    Service
                  </th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono">
                    Version
                  </th>
                  <th className="px-4 py-2.5 text-center text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono">
                    CVEs
                  </th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground font-mono">
                    Severity
                  </th>
                </tr>
              </thead>
              <tbody>
                {openPorts.map((port) => (
                  <PortRow key={`${port.port}/${port.protocol}`} port={port} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
