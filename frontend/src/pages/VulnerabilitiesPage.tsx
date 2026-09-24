import React, { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, SeverityBadge, EmptyState, LoadingState, Mono, inputClass } from '../components/ui';

export const VulnerabilitiesPage: React.FC = () => {
  const { vulnerabilities, findings, assetById, userById, isLoading } = useApp();
  const [search, setSearch] = useState('');
  const [sev, setSev] = useState('all');
  const [status, setStatus] = useState('all');

  const filtered = useMemo(() => vulnerabilities.filter((v) => {
    const q = search.toLowerCase();
    const matchQ = !q || v.title.toLowerCase().includes(q) || v.id.toLowerCase().includes(q);
    return matchQ && (sev === 'all' || v.severity === sev) && (status === 'all' || v.status === status);
  }), [vulnerabilities, search, sev, status]);

  const riskColor = (r: string) =>
    r === 'CRITICAL' ? 'text-rose-300' : r === 'HIGH' ? 'text-orange-300' : r === 'MEDIUM' ? 'text-amber-300' : 'text-emerald-300';
  return (
    <div>
      <PageHeader title="Vulnerabilities" subtitle="Managed vulnerabilities with Risk = Impact × Likelihood (1–5 each). Open an item to assess, assign, and track it." />
      <Card className="p-5 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search ID or title…" className={`${inputClass} md:col-span-2`} />
          <select value={sev} onChange={(e) => setSev(e.target.value)} className={inputClass}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={status} onChange={(e) => setStatus(e.target.value)} className={inputClass}>
            <option value="all">All statuses</option>
            <option value="NEW">New</option>
            <option value="ASSIGNED">Assigned</option>
            <option value="IN_PROGRESS">In Progress</option>
            <option value="REMEDIATED">Remediated</option>
            <option value="VERIFIED">Verified</option>
            <option value="CLOSED">Closed</option>
          </select>
        </div>
      </Card>
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-slate-500 border-b border-slate-800">
                <th className="px-5 py-4 font-medium">ID</th>
                <th className="px-5 py-4 font-medium">Title</th>
                <th className="px-5 py-4 font-medium">Severity</th>
                <th className="px-5 py-4 font-medium">Asset</th>
                <th className="px-5 py-4 font-medium">Risk</th>
                <th className="px-5 py-4 font-medium">Status</th>
                <th className="px-5 py-4 font-medium">Assigned to</th>
                <th className="px-5 py-4 font-medium">Due</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filtered.map((v) => (
                <tr key={v.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-5 py-4"><Link to={`/vulnerabilities/${v.id}`} className="font-mono-code text-[13px] text-cyan-300 hover:underline">{v.id}</Link></td>
                  <td className="px-5 py-4 text-slate-100 max-w-xs truncate"><Link to={`/vulnerabilities/${v.id}`} className="hover:text-cyan-200">{v.title}</Link></td>
                  <td className="px-5 py-4"><SeverityBadge severity={v.severity} /></td>
                  <td className="px-5 py-4 text-slate-300 text-[13px]">
                    {(() => {
                      // Day 9 Task 6: asset id now arrives on the
                      // vulnerability itself; the finding lookup is a
                      // fallback for older payloads.
                      if (v.assetId) return assetById(v.assetId)?.name || v.assetId;
                      const finding = findings.find((f) => f.id === v.findingId);
                      return finding
                        ? assetById(finding.assetId)?.name || finding.assetId
                        : '—';
                    })()}
                  </td>
                  <td className="px-5 py-4 text-[13px]"><Mono className={riskColor(v.riskLevel)}>{v.riskScore} · {v.riskLevel}</Mono></td>
                  <td className="px-5 py-4 text-slate-300 text-[13px]">{v.status.replace('_', ' ')}</td>
                  <td className="px-5 py-4 text-slate-300 text-[13px]">{userById(v.assignedTo)?.name || '—'}</td>
                  <td className="px-5 py-4 text-slate-400 text-[13px]"><Mono>{v.dueDate || '—'}</Mono></td>
                </tr>
              ))}
            </tbody>
          </table>
          {isLoading ? <LoadingState title="Loading vulnerabilities…" /> : filtered.length === 0 && <EmptyState title="No vulnerabilities match" hint="Adjust your search or filters." />}
        </div>
      </Card>
    </div>
  );
};
