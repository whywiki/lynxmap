import { useState, useEffect, useRef, useCallback } from 'react';
import { ScanHistory } from '@/components/scan-history';
import { ScanForm } from '@/components/scan-form';
import { ScanStatus } from '@/components/scan-status';
import { ResultsView } from '@/components/results-view';
import { startScan, getScan } from '@/api/scannerApi';

// Poll interval in ms
const POLL_MS = 2000;

export default function Dashboard() {
  // Local scan registry: scan_id → { status, target, port_range_start, port_range_end, ... }
  const [scans, setScans] = useState([]);
  const [activeScanId, setActiveScanId] = useState(null);
  const [showForm, setShowForm] = useState(true);
  const pollRef = useRef(null);

  const activeScan = scans.find((s) => s.scan_id === activeScanId) ?? null;
  const displayedScan = activeScan ?? scans[0] ?? null;
  // eslint-disable-next-line no-unused-vars
  const isScanning = activeScan?.status === 'pending' || activeScan?.status === 'running';

  // ---- Update single scan in list ----
  const updateScan = useCallback((scan_id, patch) => {
    setScans((prev) => prev.map((s) => (s.scan_id === scan_id ? { ...s, ...patch } : s)));
  }, []);

  // ---- Poll until complete/error ----
  const pollScan = useCallback(
    (scan_id) => {
      // Clear any existing poll
      if (pollRef.current) clearTimeout(pollRef.current);

      const tick = async () => {
        try {
          const data = await getScan(scan_id);

          if (data.status === 'complete') {
            // Merge result fields into our local entry
            // Real API: data.result = full ScanResult object
            const result = data.result;
            updateScan(scan_id, {
              status: 'complete',
              ...result,
            });
            setActiveScanId(scan_id);
            setShowForm(false);
            return; // stop polling
          }

          if (data.status === 'error') {
            updateScan(scan_id, { status: 'error', error: data.error });
            setActiveScanId(scan_id);
            setShowForm(false);
            return; // stop polling
          }

          // Still pending/running - update status and schedule next poll
          updateScan(scan_id, { status: data.status });
          pollRef.current = setTimeout(tick, POLL_MS);
        } catch (err) {
          updateScan(scan_id, { status: 'error', error: err.message });
        }
      };

      tick();
    },
    [updateScan],
  );

  // ---- Submit new scan ----
  const handleSubmit = useCallback(
    async (values) => {
      try {
        const data = await startScan(
          values.target,
          values.port_start,
          values.port_end,
          values.timeout,
        );

        const newEntry = {
          scan_id: data.scan_id,
          status: 'pending',
          target: values.target,
          port_range_start: values.port_start,
          port_range_end: values.port_end,
          timeout: values.timeout,
          created_at: new Date().toISOString(),
        };

        setScans((prev) => [newEntry, ...prev]);
        setActiveScanId(data.scan_id);
        setShowForm(false);

        pollScan(data.scan_id);
      } catch (err) {
        // If POST /scan itself fails, show form error (rare)
        console.error('Failed to start scan:', err);
        alert(`Failed to start scan: ${err.message}`);
      }
    },
    [pollScan],
  );

  const handleNewScan = useCallback(() => {
    setActiveScanId(null);
    setShowForm(true);
  }, []);

  const handleSelect = useCallback((scan_id) => {
    setActiveScanId(scan_id);
    setShowForm(false);
  }, []);

  // Cleanup poll on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) clearTimeout(pollRef.current);
    };
  }, []);

  return (
    <div className="flex h-screen bg-background text-foreground overflow-hidden">
      {/* Sidebar */}
      <ScanHistory
        scans={scans}
        activeScanId={activeScanId}
        onSelect={handleSelect}
        onNewScan={handleNewScan}
      />

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        <div
          className={
            showForm ? 'w-full px-8 py-10 space-y-8' : 'max-w-5xl mx-auto px-8 py-10 space-y-8'
          }
        >
          {/* ── Idle / new-scan state ── */}
          {showForm && (
            <div className="space-y-8">
              <p className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted-foreground/60">
                // Network Vulnerability Scanner
              </p>
              <h1 className="text-5xl font-bold tracking-tight leading-none">
                <span className="text-foreground">Lynx</span>
                <span className="text-muted-foreground/50">Map</span>
              </h1>
              <p className="text-lg text-muted-foreground leading-relaxed max-w-2xl">
                Targeted TCP port discovery with service fingerprinting and CVE enrichment. Submit a
                scan to inspect open ports and known vulnerabilities.
              </p>
              <div className="pt-4">
                <ScanForm onSubmit={handleSubmit} isScanning={false} className="w-full" />
              </div>
            </div>
          )}

          {/* ── Active scan view ── */}
          {!showForm && displayedScan && (
            <div className="space-y-6">
              {/* In-progress or error */}
              {(displayedScan.status === 'pending' ||
                displayedScan.status === 'running' ||
                displayedScan.status === 'error') && (
                <>
                  <p className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted-foreground/60">
                    // Scanning {displayedScan.target}
                  </p>
                  <h1 className="text-4xl font-bold tracking-tight leading-none font-mono">
                    {displayedScan.target}
                  </h1>
                  <p className="text-sm font-mono text-muted-foreground">
                    ports {displayedScan.port_range_start}-{displayedScan.port_range_end} · port
                    wait {displayedScan.timeout}s
                  </p>
                  <ScanStatus scan={displayedScan} />
                </>
              )}

              {/* Complete */}
              {displayedScan.status === 'complete' && (
                <>
                  <p className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted-foreground/60">
                    // Scan Results
                  </p>
                  <h1 className="text-4xl font-bold tracking-tight leading-none font-mono">
                    {displayedScan.target}
                  </h1>
                  <p className="text-sm font-mono text-muted-foreground">
                    ports {displayedScan.port_range_start}-{displayedScan.port_range_end} · port
                    wait {displayedScan.timeout}s
                  </p>
                  <ResultsView scan={displayedScan} />
                </>
              )}
            </div>
          )}

          {!showForm && !displayedScan && (
            <div className="rounded-md border border-border bg-card px-6 py-8 text-sm text-muted-foreground">
              No scan is available yet. Start a new scan from the sidebar.
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
