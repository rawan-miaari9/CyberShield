import React, { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, SeverityBadge, EmptyState, LoadingState, Mono, inputClass } from '../components/ui';
import { api } from '../services/api';

export const FindingsPage: React.FC = () => {
  const {
    findings,
    assetById,
    assets,
    user,
    findingsLoading,
    findingsError,
    findingsTotal,
    findingsPage,
    findingsNumPages,
    findingsHasNext,
    findingsHasPrevious,
    loadFindingsPage,
    refreshFindings,
  } = useApp();

  const [zapStatus, setZapStatus] = useState<'unknown' | 'connected' | 'disconnected'>('unknown');
  const [zapVersion, setZapVersion] = useState('');
  const [testingZap, setTestingZap] = useState(false);
  const [syncingZap, setSyncingZap] = useState(false);
  const [syncMessage, setSyncMessage] = useState('');
  // ZAP orchestration (test/scan/sync) is analyst-only — the backend
  // enforces the same rule with 403s, this just hides dead controls.
  const canManageZap = user?.role === 'Administrator' || user?.role === 'Security Analyst';
  const [zapAssetId, setZapAssetId] = useState('3');
  // Scan Website (ZAP Spider) state. scan_id lives in component state
  // only; polling stops at 100%, on error, on asset change, or unmount.
  // Sync Findings stays a separate explicit analyst action — never auto.
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState<number | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanStarting, setScanStarting] = useState(false);
  const [scanMessage, setScanMessage] = useState('');
  const [scanDone, setScanDone] = useState(false);
  const [syncDone, setSyncDone] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const clearScan = () => {
    stopPolling();
    setScanId(null);
    setScanProgress(null);
    setScanning(false);
    setScanStarting(false);
    setScanMessage('');
    setScanDone(false);
    setSyncDone(false);
  };

  // Timer cleanup on unmount.
  useEffect(() => () => stopPolling(), []);

  // A new target invalidates the previous scan's state/progress.
  const handleZapAssetChange = (nextId: string) => {
    setZapAssetId(nextId);
    clearScan();
  };
  // If the selected ZAP target disappears (e.g. asset deleted), fall
  // back to OWASP Juice Shop when present, else the first asset.
  // Never triggers a sync — selection only.
  useEffect(() => {
    if (assets.length > 0 && !assets.some((a) => String(a.id) === String(zapAssetId))) {
      const juice = assets.find((a) => String(a.id) === '3');
      setZapAssetId(String((juice || assets[0]).id));
    }
  }, [assets, zapAssetId]);
  // Global header search navigates here as ?search= — seed state from it
  // so the FIRST request already carries the filter. (Previously the page
  // mounted with empty state, fired an unfiltered page-1 load, and only
  // then applied the param after debounce — the heavy unfiltered response
  // could resolve last and overwrite the filtered rows, since nothing
  // orders concurrent loads.)
  const [searchParams] = useSearchParams();
  const paramSearch = searchParams.get('search') || '';
  const [search, setSearch] = useState(paramSearch);
  const [debouncedSearch, setDebouncedSearch] = useState(paramSearch.trim());
  const [sev, setSev] = useState('all');
  const [status, setStatus] = useState('all');
  // Adopt later ?search= navigations while mounted (URL stays source of
  // truth, including param removal); local typing never triggers this
  // because it doesn't change the param.
  useEffect(() => {
    if (paramSearch !== search) setSearch(paramSearch);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paramSearch]);

  // Day 9 Task 5: filtering is server-side (?search=&severity=&status=) so a
  // filter searches the whole findings table, not just the loaded page.
  // Debounce the text search to avoid a request per keystroke.
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search.trim()), 400);
    return () => clearTimeout(t);
  }, [search]);

  useEffect(() => {
    loadFindingsPage(1, {
      search: debouncedSearch || undefined,
      severity: sev,
      status,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedSearch, sev, status]);

  const handleTestZapConnection = async () => {
    setTestingZap(true);

    try {
      const result = await api.testZapConnection();

      if (result.success) {
        setZapStatus('connected');
        setZapVersion(result.version || '');
      } else {
        setZapStatus('disconnected');
        setZapVersion('');
      }
    } catch {
      setZapStatus('disconnected');
      setZapVersion('');
    } finally {
      setTestingZap(false);
    }
  };

  const handleSyncZap = async () => {
    setSyncingZap(true);
    setSyncMessage('');

    try {
      const result = await api.syncZapFindings(zapAssetId);

      setZapStatus('connected');

      // Sync supersedes the scan step: hide the scan-completion prompt
      // and report the sync result (created/duplicates/total preserved).
      setScanDone(false);
      setScanMessage('');
      setScanProgress(null);
      setSyncDone(true);
      setSyncMessage(
        `Findings synchronized successfully: ${result.created} new, ${result.duplicates} duplicates, ${result.total} total.`
      );
      await refreshFindings();

    } catch {
      setSyncDone(false);
      setSyncMessage('Sync failed. Please check the ZAP connection.');
    } finally {
      setSyncingZap(false);

    }
};

  const pollScan = (id: string) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const st = await api.getZapScanStatus(id);
        const progress = Math.max(0, Math.min(100, Number(st.progress) || 0));
        setScanProgress(progress);
        if (progress >= 100) {
          stopPolling();
          setScanning(false);
          setScanDone(true);
          setScanMessage('Scan completed successfully. You can now sync the findings.');
        }
      } catch (e) {
        stopPolling();
        setScanning(false);
        setScanMessage(e instanceof Error ? e.message : 'Scan status check failed.');
      }
    }, 2500);
  };

  const handleScanWebsite = async () => {
    // Single in-flight scan from this page: the button is disabled while
    // running, and this guard covers repeated clicks before state settles.
    if (scanning || scanStarting || !zapAssetId) return;
    clearScan();
    setScanStarting(true);
    setScanMessage('Starting scan…');
    try {
      const started = await api.startZapScan(zapAssetId);
      setScanId(started.scan_id);
      setScanProgress(0);
      setScanStarting(false);
      setScanning(true);
      setScanMessage('');
      // Immediate first poll so progress appears without waiting ~2.5s.
      try {
        const st = await api.getZapScanStatus(started.scan_id);
        const progress = Math.max(0, Math.min(100, Number(st.progress) || 0));
        setScanProgress(progress);
        if (progress >= 100) {
          setScanning(false);
          setScanDone(true);
          setScanMessage('Scan completed successfully. You can now sync the findings.');
          return;
        }
      } catch (e) {
        setScanning(false);
        setScanMessage(e instanceof Error ? e.message : 'Scan status check failed.');
        return;
      }
      pollScan(started.scan_id);
    } catch (e) {
      setScanStarting(false);
      setScanMessage(e instanceof Error ? e.message : 'Could not start the ZAP scan.');
    }
  };

  const goToPage = (page: number) => {
    loadFindingsPage(page, {
      search: debouncedSearch || undefined,
      severity: sev,
      status,
    });
  };

  const showLoading = findingsLoading && findings.length === 0 && !findingsError;

  return (
    <div>
      <PageHeader title="Findings" subtitle="Raw security issues imported from external scanners. Review each finding, then promote approved items into managed vulnerabilities." />
      <Card className="p-5 mb-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h3 className="text-sm font-medium text-slate-100">
              OWASP ZAP Scanner
            </h3>

            <div className="mt-1 text-sm text-slate-400">
              {zapStatus === 'unknown' && (
                <span>Connection not tested</span>
              )}

              {zapStatus === 'connected' && (
                <span className="text-emerald-400">
                  ● Connected{zapVersion ? ` — v${zapVersion}` : ''}
                </span>
              )}

              {zapStatus === 'disconnected' && (
                <span className="text-red-400">
                  ● Disconnected
                </span>
              )}
            </div>
            <p className="mt-2 text-xs text-slate-500 leading-relaxed">
              OWASP ZAP runs externally and performs the scan through its API — CyberShield only starts it,
              tracks progress, and synchronizes the resulting alerts as findings.
            </p>
          </div>

          {syncMessage && (
          <div className="mt-2 text-sm text-slate-400">
            {syncMessage}
          </div>
        )}

          <div className="flex items-center gap-3 flex-wrap">
            {canManageZap ? (
              <>
            <select
              value={zapAssetId}
              onChange={(e) => handleZapAssetChange(e.target.value)}
              disabled={syncingZap || scanning || scanStarting}
              title="Target asset for ZAP scan and sync"
              className="px-4 py-2 rounded-lg bg-slate-800 text-sm text-slate-100 border border-slate-700 disabled:opacity-50 transition-colors max-w-[220px]"
            >
              {assets.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
            <button
              type="button"
              onClick={handleTestZapConnection}
              disabled={testingZap}
              className="px-4 py-2 rounded-lg bg-slate-800 text-sm text-slate-100 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {testingZap ? 'Testing…' : 'Test Connection'}
            </button>

            <button
              type="button"
              onClick={handleScanWebsite}
              disabled={scanning || scanStarting || syncingZap || !zapAssetId}
              title={assetById(zapAssetId) ? `Ask ZAP to crawl ${assetById(zapAssetId)?.name}` : undefined}
              className="px-4 py-2 rounded-lg bg-slate-800 text-sm text-slate-100 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {scanStarting ? 'Starting…' : scanning ? 'Scanning…' : 'Scan Website'}
            </button>
            <button
              type="button"
              onClick={handleSyncZap}
              disabled={syncingZap || !zapAssetId}
              title={assetById(zapAssetId) ? `Sync ZAP findings for ${assetById(zapAssetId)?.name}` : undefined}
              className={`px-4 py-2 rounded-lg bg-cyan-600 text-sm text-white hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors ${scanDone ? 'ring-2 ring-emerald-400/70' : ''}`}
            >
              {syncingZap ? 'Syncing…' : `Sync Findings · ${assetById(zapAssetId)?.name || `Asset ${zapAssetId}`}`}
            </button>
              </>
            ) : (
              <p className="text-xs text-slate-500 max-w-[280px] leading-relaxed">
                Scanner controls require the Security Analyst or Administrator role. Findings synchronized by analysts appear in the list below.
              </p>
            )}
          </div>
        </div>
        {(scanning || scanProgress !== null || scanMessage) && !syncDone && (
          <div className="mt-4 pt-4 border-t border-slate-800/70">
            {scanStarting && <p className="text-sm text-slate-400">Starting scan…</p>}
            {scanning && scanProgress !== null && (
              <>
                <p className="text-sm text-slate-300">
                  Scanning {assetById(zapAssetId)?.name || `Asset ${zapAssetId}`}… {scanProgress}%
                </p>
                <div className="mt-2 h-2 rounded-full bg-slate-800 overflow-hidden" role="progressbar" aria-valuenow={scanProgress} aria-valuemin={0} aria-valuemax={100}>
                  <div className="h-full rounded-full bg-cyan-500 transition-all" style={{ width: `${scanProgress}%` }} />
                </div>
              </>
            )}
            {scanMessage && (
              <p className={`text-sm mt-2 ${scanDone ? 'text-emerald-300' : scanning || scanStarting ? 'text-slate-400' : 'text-rose-300'}`}>{scanMessage}</p>
            )}
          </div>
        )}
      </Card>
      <Card className="p-5 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search title, ID, or CWE…" className={`${inputClass} md:col-span-2`} />
          <select value={sev} onChange={(e) => setSev(e.target.value)} className={inputClass}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={status} onChange={(e) => setStatus(e.target.value)} className={inputClass}>
            <option value="all">All statuses</option>
            <option value="New">New</option>
            <option value="Reviewed">Reviewed</option>
            <option value="Promoted">Promoted</option>
            <option value="Ignored">Ignored</option>
          </select>
        </div>
      </Card>
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-slate-500 border-b border-slate-800">
                <th className="px-5 py-4 font-medium">Finding ID</th>
                <th className="px-5 py-4 font-medium">Title</th>
                <th className="px-5 py-4 font-medium">Scanner Severity</th>
                <th className="px-5 py-4 font-medium">Asset</th>
                <th className="px-5 py-4 font-medium">Source</th>
                <th className="px-5 py-4 font-medium">Status</th>
                <th className="px-5 py-4 font-medium">Imported</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {findings.map((f) => (
                <tr key={f.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-5 py-4"><Link to={`/findings/${f.id}`} className="font-mono-code text-[13px] text-cyan-300 hover:underline">{f.id}</Link></td>
                  <td className="px-5 py-4 text-slate-100 max-w-xs"><Link to={`/findings/${f.id}`} className="hover:text-cyan-200">{f.title}</Link></td>
                  <td className="px-5 py-4"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-5 py-4 text-slate-300 text-[13px]">{assetById(f.assetId)?.name || f.assetId}</td>
                  <td className="px-5 py-4 text-slate-400 text-[13px]">{f.scannerSource}</td>
                  <td className="px-5 py-4 text-slate-300 text-[13px]">{f.status}</td>
                  <td className="px-5 py-4 text-slate-400 text-[13px]">
                    <Mono>
                      {new Date(f.importedAt).toLocaleString(undefined, {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </Mono>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {findingsError ? (
            <div className="p-12 text-center" role="alert">
              <p className="text-[15.5px] font-semibold text-rose-300">Couldn&apos;t load findings</p>
              <p className="text-sm text-slate-500 mt-1.5">{findingsError} This is a load failure — not zero findings.</p>
              <button
                type="button"
                onClick={() => goToPage(findingsPage)}
                className="mt-4 px-4 py-2 rounded-lg bg-slate-800 text-sm text-slate-100 hover:bg-slate-700 transition-colors"
              >
                Retry
              </button>
            </div>
          ) : showLoading ? (
            <LoadingState title="Loading findings…" />
          ) : findings.length === 0 ? (
            <EmptyState title="No findings match" hint="Adjust your search or filters." />
          ) : null}
          {findingsLoading && findings.length > 0 && (
            <p className="px-5 py-3 text-[12.5px] text-slate-500" role="status">Refreshing…</p>
          )}
        </div>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-5 py-4 border-t border-slate-800">
          <p className="text-[13px] text-slate-500">
            {findingsError
              ? 'Total unavailable — findings failed to load.'
              : `Showing ${findings.length} of ${findingsTotal} findings · Page ${findingsPage} of ${findingsNumPages}`}
          </p>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => goToPage(findingsPage - 1)}
              disabled={!findingsHasPrevious || findingsLoading}
              className="px-4 py-2 rounded-lg bg-slate-800 text-sm text-slate-100 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Previous
            </button>
            <button
              type="button"
              onClick={() => goToPage(findingsPage + 1)}
              disabled={!findingsHasNext || findingsLoading}
              className="px-4 py-2 rounded-lg bg-slate-800 text-sm text-slate-100 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      </Card>
    </div>
  );
};
