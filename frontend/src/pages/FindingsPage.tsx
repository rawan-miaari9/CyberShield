import React, { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, SeverityBadge, EmptyState, Mono, inputClass } from '../components/ui';

export const FindingsPage: React.FC = () => {
  const { findings, assetById } = useApp();
  const [search, setSearch] = useState('');
  const [sev, setSev] = useState('all');
  const [status, setStatus] = useState('all');

  const filtered = useMemo(() => findings.filter((f) => {
    const q = search.toLowerCase();
    const matchQ = !q || f.title.toLowerCase().includes(q) || f.id.toLowerCase().includes(q) || (f.cwe || '').toLowerCase().includes(q);
    return matchQ && (sev === 'all' || f.severity === sev) && (status === 'all' || f.status === status);
  }), [findings, search, sev, status]);

  return (
    <div>
      <PageHeader title="Findings" subtitle="Raw security issues imported from external scanners. Review each finding, then promote approved items into managed vulnerabilities." />
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
                  <td className="px-5 py-4 text-slate-400 text-[13px]"><Mono>{f.importedAt}</Mono></td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && <EmptyState title="No findings match" hint="Adjust your search or filters." />}
        </div>
      </Card>
    </div>
  );
};
