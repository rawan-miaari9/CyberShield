import React, { useState } from 'react';
import { Plug, RefreshCw, FlaskConical } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, Mono, buttonPrimary, buttonGhost } from '../components/ui';
import { api } from '../services/api';

export const IntegrationsPage: React.FC = () => {
  const { integrations, syncScanner } = useApp();
  const [busyId, setBusyId] = useState<string | null>(null);
  const [testMsg, setTestMsg] = useState<string | null>(null);
  const [syncMsg, setSyncMsg] = useState<string | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);

  const handleSync = async (id: string) => {
    setBusyId(id);
    setSyncMsg(null);
    setSyncError(null);
    try {
      const n = await syncScanner(id);
      setSyncMsg(`Sync completed — ${n} findings available for review.`);
    } catch (err) {
      setSyncError(err instanceof Error ? err.message : 'Sync failed.');
    } finally {
      setBusyId(null);
    }
  };

  const handleTest = async () => {
    setTestMsg('Testing connection…');
    try {
      const res = await api.testConnection();
      setTestMsg(res.ok ? 'Connection test passed.' : res.message);
    } catch (err) {
      setTestMsg(err instanceof Error ? err.message : 'Connection test failed.');
    }
  };

  return (
    <div>
      <PageHeader
        title="Scanner Integrations"
        subtitle="CyberShield does not run scans. External scanners run separately; CyberShield synchronizes their findings for analyst review."
        action={<button onClick={handleTest} className={buttonGhost}><FlaskConical className="w-4 h-4" /> Test connection</button>}
      />
      {testMsg && <div className="mb-6 p-4 rounded-xl bg-[#0a0f1d] border border-slate-800 text-sm text-slate-300">{testMsg}</div>}
      {syncMsg && <div className="mb-6 p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-sm text-emerald-300">{syncMsg}</div>}
      {syncError && <div className="mb-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-sm text-rose-300">{syncError}</div>}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {integrations.map((s) => (
          <Card key={s.id} className="p-6">
            <div className="flex items-start justify-between gap-3 mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-300"><Plug className="w-5 h-5" /></div>
                <div>
                  <h3 className="text-lg font-semibold text-white">{s.name}</h3>
                  <p className="text-xs text-slate-500">The only active scanner for the MVP</p>
                </div>
              </div>
              <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/25 capitalize">{s.status}</span>
            </div>
            <p className="text-sm text-slate-400 leading-relaxed mb-4">{s.description}</p>
            <div className="grid grid-cols-2 gap-4 text-sm mb-5">
              <div><div className="text-xs uppercase tracking-wider text-slate-500 mb-1">Last sync</div><Mono className="text-[13px] text-slate-200">{s.lastSync || 'never'}</Mono></div>
              <div><div className="text-xs uppercase tracking-wider text-slate-500 mb-1">Findings</div><span className="text-slate-200">{s.findingsCount}</span></div>
            </div>
            <div className="flex flex-wrap gap-3">
              <button onClick={() => handleSync(s.id)} disabled={busyId === s.id} className={buttonPrimary}>
                <RefreshCw className={`w-4 h-4 ${busyId === s.id ? 'animate-spin' : ''}`} /> {busyId === s.id ? 'Syncing…' : 'Sync findings'}
              </button>
              <button onClick={handleTest} className={buttonGhost}>Configure</button>
            </div>
          </Card>
        ))}
      </div>
      {integrations.length === 0 && (
        <Card className="p-6 mt-6">
          <h3 className="text-base font-semibold text-white mb-2">OWASP ZAP sync</h3>
          <p className="text-sm text-slate-400">Scanner sync is performed per asset from the Findings page (OWASP ZAP Scanner panel). No separate integration records are required for the MVP.</p>
        </Card>
      )}
      <Card className="p-6 mt-6">
        <h3 className="text-base font-semibold text-white mb-2">Other scanners</h3>
        <p className="text-sm text-slate-400">Additional scanner integrations are out of scope for the MVP and are not shown as active.</p>
      </Card>
    </div>
  );
};
