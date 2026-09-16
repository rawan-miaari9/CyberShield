import React from 'react';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, EmptyState, Mono } from '../components/ui';

export const AuditLogsPage: React.FC = () => {
  const { auditLogs } = useApp();
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
                  <td className="px-5 py-4 text-slate-400 text-[13px]"><Mono>{a.timestamp}</Mono></td>
                  <td className="px-5 py-4 text-slate-200 text-[13px]">{a.user}</td>
                  <td className="px-5 py-4 text-slate-200 text-[13px]">{a.action.replace(/_/g, ' ')}</td>
                  <td className="px-5 py-4 text-[13px]"><span className="text-slate-400">{a.entityType} </span><Mono className="text-cyan-300">{a.entityId}</Mono></td>
                  <td className="px-5 py-4 text-[13px] text-slate-400">{a.oldValue || '—'} → {a.newValue || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {auditLogs.length === 0 && <EmptyState title="No audit events" hint="Actions will appear here." />}
        </div>
      </Card>
    </div>
  );
};
