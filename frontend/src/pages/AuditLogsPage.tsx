import React from 'react';
import { Link } from 'react-router-dom';
import { useApp, canViewAuditLogs } from '../context/SecurityContext';
import { Card, PageHeader, EmptyState, LoadingState, Mono } from '../components/ui';

function formatWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export const AuditLogsPage: React.FC = () => {
  const { auditLogs, user, isLoading } = useApp();
  const canView = canViewAuditLogs(user);
  if (!canView) {
    return (
      <div>
        <PageHeader title="Audit Logs" subtitle="Read-only operational trail of who changed what, and when." />
        <Card className="p-10 text-center">
          <p className="text-[15.5px] font-semibold text-slate-200">Access denied</p>
          <p className="text-sm text-slate-500 mt-1.5">Audit Logs require the Security Analyst or Administrator role.</p>
          <Link to="/dashboard" className="text-sm text-cyan-300 hover:underline mt-4 inline-block">← Back to dashboard</Link>
        </Card>
      </div>
    );
  }
  return (
    <div>
      <PageHeader title="Audit Logs" subtitle="Read-only operational trail of who changed what, and when." />
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-slate-500 border-b border-slate-800">
                <th className="px-5 py-4 font-medium">Timestamp</th>
                <th className="px-5 py-4 font-medium">User</th>
                <th className="px-5 py-4 font-medium">Action</th>
                <th className="px-5 py-4 font-medium">Entity</th>
                <th className="px-5 py-4 font-medium">Old → New</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {auditLogs.map((a) => (
                <tr key={a.id} className="hover:bg-slate-800/30">
                  <td className="px-5 py-4 text-slate-400 text-[13px]"><Mono>{formatWhen(a.timestamp)}</Mono></td>
                  <td className="px-5 py-4 text-slate-200 text-[13px]">{a.user}</td>
                  <td className="px-5 py-4 text-slate-200 text-[13px]">{a.action.replace(/_/g, ' ')}</td>
                  <td className="px-5 py-4 text-[13px]"><span className="text-slate-400">{a.entityType} </span><Mono className="text-cyan-300">{a.entityId}</Mono></td>
                  <td className="px-5 py-4 text-[13px] text-slate-400">{a.oldValue || '—'} → {a.newValue || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {isLoading ? <LoadingState title="Loading audit logs…" /> : auditLogs.length === 0 && <EmptyState title="No audit events" hint="Actions will appear here." />}
        </div>
      </Card>
    </div>
  );
};
