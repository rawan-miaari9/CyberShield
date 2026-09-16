import React from 'react';
import { Link } from 'react-router-dom';
import { Bug, FileSearch, ShieldAlert, CheckCircle2, Plug } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, SeverityBadge, Mono } from '../components/ui';
import { trendData } from '../data/mockData';

function Kpi({ icon, label, value, hint }: { icon: React.ReactNode; label: string; value: string; hint: string }) {
  return (
    <Card className="p-6">
      <div className="flex items-center justify-between mb-4">
        <span className="text-sm font-medium text-slate-400">{label}</span>
        <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-300">{icon}</div>
      </div>
      <div className="text-3xl font-bold text-white">{value}</div>
      <p className="text-sm text-slate-500 mt-2">{hint}</p>
    </Card>
  );
}

export const DashboardPage: React.FC = () => {
  const { vulnerabilities, findings, remediation, integrations, auditLogs, assetById } = useApp();

  const openVulns = vulnerabilities.filter((v) => !['VERIFIED', 'CLOSED'].includes(v.status));
  const criticalVulns = openVulns.filter((v) => v.severity === 'critical');
  const openFindings = findings.filter((f) => f.status === 'New' || f.status === 'Reviewed');
  const doneRem = remediation.filter((r) => r.status === 'Completed').length;
  const progress = remediation.length ? Math.round((doneRem / remediation.length) * 100) : 0;

  const sevCounts = ([
    { key: 'critical', color: '#f43f5e' },
    { key: 'high', color: '#fb923c' },
    { key: 'medium', color: '#facc15' },
    { key: 'low', color: '#34d399' },
  ] as const).map((s) => ({
    name: s.key[0].toUpperCase() + s.key.slice(1),
    count: openVulns.filter((v) => v.severity === s.key).length,
    color: s.color,
  }));

  const recentCritical = [...criticalVulns].slice(0, 4);
  const recentActivity = auditLogs.slice(0, 5);

  return (
    <div>
      <PageHeader title="Dashboard" subtitle="A focused overview of findings, vulnerabilities, and remediation progress." />
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-6 mb-8">
        <Kpi icon={<Bug className="w-5 h-5" />} label="Open Vulnerabilities" value={String(openVulns.length)} hint="Across all managed assets" />
        <Kpi icon={<ShieldAlert className="w-5 h-5" />} label="Critical Vulnerabilities" value={String(criticalVulns.length)} hint="Require analyst attention first" />
        <Kpi icon={<FileSearch className="w-5 h-5" />} label="Open Findings" value={String(openFindings.length)} hint="Imported, awaiting review" />
        <Kpi icon={<CheckCircle2 className="w-5 h-5" />} label="Remediation Progress" value={`${progress}%`} hint={`${doneRem} of ${remediation.length} tasks completed`} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <Card className="p-6">
          <h3 className="text-base font-semibold text-white mb-1">Vulnerability Trend</h3>
          <p className="text-sm text-slate-500 mb-5">Opened vs. closed per week</p>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData} margin={{ top: 5, right: 5, left: -15, bottom: 0 }}>
                <defs>
                  <linearGradient id="openG" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="week" stroke="#64748b" fontSize={12} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0a0f1d', borderColor: '#334155', borderRadius: 10, fontSize: 12 }} />
                <Area type="monotone" dataKey="open" stroke="#22d3ee" strokeWidth={2} fill="url(#openG)" name="Opened" />
                <Area type="monotone" dataKey="closed" stroke="#34d399" strokeWidth={2} fill="transparent" name="Closed" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card className="p-6">
          <h3 className="text-base font-semibold text-white mb-1">Vulnerabilities by Severity</h3>
          <p className="text-sm text-slate-500 mb-5">Open items only</p>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sevCounts} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} allowDecimals={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0a0f1d', borderColor: '#334155', borderRadius: 10, fontSize: 12 }} />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {sevCounts.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold text-white">Recent Critical Vulnerabilities</h3>
            <Link to="/vulnerabilities" className="text-sm text-cyan-300 hover:underline">View all</Link>
          </div>
          <div className="space-y-3">
            {recentCritical.length === 0 && <p className="text-sm text-slate-500">No open critical vulnerabilities. Good work.</p>}
            {recentCritical.map((v) => (
              <Link key={v.id} to={`/vulnerabilities/${v.id}`} className="flex items-center justify-between gap-3 p-3.5 rounded-xl bg-[#0d1322] border border-slate-800 hover:border-slate-700 transition-colors">
                <div className="min-w-0">
                  <Mono className="text-xs text-cyan-300 font-semibold">{v.id}</Mono>
                  <p className="text-sm text-slate-100 truncate mt-0.5">{v.title}</p>
                  <p className="text-xs text-slate-500 mt-0.5">{assetById(v.assetId)?.name}</p>
                </div>
                <SeverityBadge severity={v.severity} />
              </Link>
            ))}
          </div>
        </Card>
        <div className="space-y-6">
          <Card className="p-6">
            <h3 className="text-base font-semibold text-white mb-4">Recent Activity</h3>
            <div className="space-y-3">
              {recentActivity.map((a) => (
                <div key={a.id} className="text-sm">
                  <p className="text-slate-200">{a.action.replace(/_/g, ' ')} · <Mono className="text-cyan-300 text-xs">{a.entityId}</Mono></p>
                  <p className="text-xs text-slate-500 mt-0.5">{a.user} · {a.timestamp}</p>
                </div>
              ))}
            </div>
          </Card>
          <Card className="p-6">
            <h3 className="text-base font-semibold text-white mb-4">Scanner Status</h3>
            <div className="space-y-3">
              {integrations.map((s) => (
                <div key={s.id} className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-300"><Plug className="w-4 h-4" /></div>
                    <div>
                      <p className="text-sm text-slate-100 font-medium">{s.name}</p>
                      <p className="text-xs text-slate-500">Last sync: {s.lastSync || 'never'}</p>
                    </div>
                  </div>
                  <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/25 capitalize">{s.status}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};
