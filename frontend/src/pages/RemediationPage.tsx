import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useApp } from '../context/SecurityContext';
import { displayUser } from './VulnerabilityDetailPage';
import { Card, PageHeader, EmptyState, LoadingState, Mono, inputClass } from '../components/ui';

export const RemediationPage: React.FC = () => {
  const { remediation, vulnerabilities, userById, isLoading, getRemediationDisplay } = useApp();
  const [status, setStatus] = useState('all');
  // Filter and render on the live display status (persisted task state +
  // linked vulnerability lifecycle), never on a stale local guess.
  const filtered = remediation.filter((r) => status === 'all' || getRemediationDisplay(r) === status);
  const titleFor = (vid: string) => vulnerabilities.find((v) => v.id === vid)?.title || vid;

  return (
    <div>
      <PageHeader title="Remediation" subtitle="Track fixes from assignment through analyst verification. Only a Security Analyst completes verification." />
      <Card className="p-5 mb-6">
        <div className="flex flex-col sm:flex-row gap-4 sm:items-center">
          <label className="text-sm text-slate-400">Status</label>
          <select value={status} onChange={(e) => setStatus(e.target.value)} className={`${inputClass} sm:max-w-xs`}>
            <option value="all">All</option>
            <option>To Do</option>
            <option>In Progress</option>
            <option>Remediated</option>
            <option>Awaiting Verification</option>
            <option>Completed</option>
          </select>
        </div>
      </Card>
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-slate-500 border-b border-slate-800">
                <th className="px-5 py-4 font-medium">Task</th>
                <th className="px-5 py-4 font-medium">Vulnerability</th>
                <th className="px-5 py-4 font-medium">Assigned to</th>
                <th className="px-5 py-4 font-medium">Status</th>
                <th className="px-5 py-4 font-medium">Due</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filtered.map((r) => (
                <tr key={r.id} className="hover:bg-slate-800/30">
                  <td className="px-5 py-4"><Link to={`/remediation/${r.id}`} className="font-mono-code text-[13px] text-cyan-300 hover:underline">{r.id}</Link></td>
                  <td className="px-5 py-4 text-slate-200 max-w-xs truncate">{r.vulnerabilityId} · {titleFor(r.vulnerabilityId)}</td>
                  {/* Real persisted assignee via the shared user display;
                      '—' only when genuinely unassigned. The API already
                      returns assigned_to — the old `.name` lookup matched
                      nothing on real user objects. */}
                  <td className="px-5 py-4 text-slate-300 text-[13px]">{r.assignedTo ? displayUser(userById(r.assignedTo)) : '—'}</td>
                  <td className="px-5 py-4 text-slate-300 text-[13px]">{getRemediationDisplay(r)}</td>
                  <td className="px-5 py-4 text-slate-400 text-[13px]"><Mono>{r.dueDate || '—'}</Mono></td>
                </tr>
              ))}
            </tbody>
          </table>
          {isLoading ? <LoadingState title="Loading remediation…" /> : filtered.length === 0 && <EmptyState title="No tasks match" hint="Adjust the status filter." />}
        </div>
      </Card>
    </div>
  );
};
