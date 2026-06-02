const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 };

export function worstSeverity(cves) {
  if (!cves || cves.length === 0) return 'NONE';
  return cves.reduce((worst, cve) => {
    const s = cve.severity ?? 'NONE';
    return (SEVERITY_ORDER[s] ?? 4) < (SEVERITY_ORDER[worst] ?? 4) ? s : worst;
  }, 'NONE');
}
