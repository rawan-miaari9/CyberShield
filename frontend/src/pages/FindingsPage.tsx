import React, { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, SeverityBadge, EmptyState, LoadingState, Mono, inputClass } from '../components/ui';
import { api } from '../services/api';

export const FindingsPage: React.FC = () => {
  const { findings, assetById, isLoading, refreshFindings } = useApp();

  const [zapStatus, setZapStatus] = useState<'unknown' | 'connected' | 'disconnected'>('unknown');
  const [zapVersion, setZapVersion] = useState('');
  const [testingZap, setTestingZap] = useState(false);
  const [syncingZap, setSyncingZap] = useState(false);
  const [syncMessage, setSyncMessage] = useState('');
  const [search, setSearch] = useState('');
  const [sev, setSev] = useState('all');
  const [status, setStatus] = useState('all');

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
      const result = await api.syncZapFindings('3');

      setZapStatus('connected');

      setSyncMessage(
        `Sync complete: ${result.created} new, ${result.duplicates} duplicates, ${result.total} total.`
      );
      await refreshFindings();

    } catch {
      setSyncMessage('Sync failed. Please check the ZAP connection.');
    } finally {
      setSyncingZap(false);
      
    }
};

  const filtered = useMemo(() => findings.filter((f) => {
    const q = search.toLowerCase();
    const matchQ = !q || f.title.toLowerCase().includes(q) || f.id.toLowerCase().includes(q) || (f.cwe || '').toLowerCase().includes(q);
    return matchQ && (sev === 'all' || f.severity === sev) && (status === 'all' || f.status === status);
  }), [findings, search, sev, status]);

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
          </div>

          {syncMessage && (
          <div className="mt-2 text-sm text-slate-400">
            {syncMessage}
          </div>
        )}

          <div className="flex items-center gap-3">
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
              onClick={handleSyncZap}
              disabled={syncingZap}
              className="px-4 py-2 rounded-lg bg-cyan-600 text-sm text-white hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {syncingZap ? 'Syncing…' : 'Sync Findings'}
            </button>
          </div>
        </div>
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
                <th className="px-5 py-4 font-medium">Severity</th>
                <th className="px-5 py-4 font-medium">Asset</th>
                <th className="px-5 py-4 font-medium">Source</th>
                <th className="px-5 py-4 font-medium">Status</th>
                <th className="px-5 py-4 font-medium">Imported</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filtered.map((f) => (
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
          {isLoading ? <LoadingState title="Loading findings…" /> : filtered.length === 0 && <EmptyState title="No findings match" hint="Adjust your search or filters." />}
        </div>
      </Card>
    </div>
  );
};
