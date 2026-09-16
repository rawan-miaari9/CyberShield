import React from 'react';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, EmptyState, Mono } from '../components/ui';

const roleDescriptions: Record<string, string> = {
  Administrator: 'Full access to configuration, users, and all records.',
  'Security Analyst': 'Reviews findings, manages vulnerabilities, verifies remediation.',
  'IT / Developer': 'Owns remediation tasks for assigned vulnerabilities.',
  'Security Manager': 'Oversees progress, assignments, and reporting.',
};

export const UsersPage: React.FC = () => {
  const { users } = useApp();
  return (
    <div>
      <PageHeader title="Users & Roles" subtitle="Who can do what in CyberShield." />
      <Card className="p-6 mb-6">
        <h3 className="text-base font-semibold text-white mb-4">Roles</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {Object.entries(roleDescriptions).map(([role, desc]) => (
            <div key={role} className="p-4 rounded-xl bg-[#0d1322] border border-slate-800">
              <p className="text-sm font-medium text-slate-100">{role}</p>
              <p className="text-sm text-slate-400 mt-1">{desc}</p>
            </div>
          ))}
        </div>
      </Card>
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-slate-500 border-b border-slate-800">
                <th className="px-5 py-4 font-medium">Name</th>
                <th className="px-5 py-4 font-medium">Email</th>
                <th className="px-5 py-4 font-medium">Role</th>
                <th className="px-5 py-4 font-medium">Status</th>
                <th className="px-5 py-4 font-medium">Last login</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-slate-800/30">
                  <td className="px-5 py-4 text-slate-100">{u.name} <Mono className="text-xs text-slate-500 ml-1">{u.id}</Mono></td>
                  <td className="px-5 py-4 text-slate-300 text-[13px]">{u.email}</td>
                  <td className="px-5 py-4 text-slate-300 text-[13px]">{u.role}</td>
                  <td className="px-5 py-4 text-[13px]">{u.active ? <span className="text-emerald-300">Active</span> : <span className="text-slate-500">Inactive</span>}</td>
                  <td className="px-5 py-4 text-slate-400 text-[13px]"><Mono>{u.lastLogin}</Mono></td>
                </tr>
              ))}
            </tbody>
          </table>
          {users.length === 0 && <EmptyState title="No users" hint="Users will load from the backend." />}
        </div>
      </Card>
    </div>
  );
};
