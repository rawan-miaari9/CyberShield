import React from 'react';
import { Link } from 'react-router-dom';
import { Bug, FileSearch, ShieldAlert, CheckCircle2, Plug, ArrowRight, ArrowUpRight } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { useApp } from '../context/SecurityContext';
import { Card, SeverityBadge, Mono, SectionTitle } from '../components/ui';
import { trendData } from '../data/mockData';

function Kpi({ icon, label, value, hint, accent }: { icon: React.ReactNode; label: string; value: string; hint: string; accent: string }) {
  return (
    <Card className="p-6 card-hover animate-rise">
      <div className="flex items-center justify-between mb-4">
        <span className="text-[13px] font-medium uppercase tracking-wider text-slate-500">{label}</span>
        <div className={`p-2.5 rounded-xl border ${accent}`}>{icon}</div>
      </div>
      <div className="font-display text-[32px] font-bold text-white tracking-tight leading-none">{value}</div>
      <p className="text-[13.5px] text-slate-500 mt-2">{hint}</p>
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
      {/* Hero — first-style layout, calmed */}
      <div className="relative rounded-2xl overflow-hidden border border-slate-800 bg-[#0d1321] mb-6 animate-rise">
        <div className="absolute inset-0 cyber-grid-bg-full opacity-70 pointer-events-none" />
        <div className="relative p-7 sm:p-9 flex flex-col lg:flex-row lg:items-end justify-between gap-6">
          <div className="max-w-2xl">
            <div className="inline-flex items-center gap-2 mb-4 px-3.5 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-[12px] font-semibold uppercase tracking-[0.16em] text-cyan-300">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
              Command Center · Live
            </div>
            <h1 className="font-display text-[38px] sm:text-[44px] font-bold leading-[1.05] tracking-tight">
              <span className="text-gradient-faint">Security </span>
              <span className="text-gradient-cyber">Dashboard</span>
            </h1>
            <p className="text-[15.5px] text-slate-400 mt-3 leading-relaxed max-w-xl">
              A focused overview of findings, vulnerabilities, and remediation progress across your entire attack surface.
            </p>
            <div className="mt-5 h-[3px] w-24 rounded-full bg-gradient-to-r from-cyan-500/80 to-cyan-500/0" />
          </div>
          <div className="shrink-0 flex items-center gap-3">
            <Link to="/findings" className="inline-flex items-center gap-1.5 px-5 py-3 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-slate-200 text-[15px] font-medium transition-colors">
              Review findings <ArrowUpRight className="w-4 h-4 text-cyan-400" />
            </Link>
            <Link to="/remediation" className="inline-flex items-center gap-1.5 px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-semibold text-[15px] transition-colors">
              Take action <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
        <div className="relative px-7 sm:px-9 pb-6">
          <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
            <div className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-indigo-500 transition-all" style={{ width: `${progress}%` }} />
          </div>
          <p className="text-[12.5px] text-slate-500 mt-2">{progress}% remediation complete · {openFindings.length} findings awaiting review</p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5 mb-6">
        <Kpi icon={<Bug className="w-5 h-5" />} label="Open Vulns" value={String(openVulns.length)} hint="Across all managed assets" accent="bg-cyan-500/10 text-cyan-300 border-cyan-500/20" />
        <Kpi icon={<ShieldAlert className="w-5 h-5" />} label="Critical" value={String(criticalVulns.length)} hint="Needs attention first" accent="bg-rose-500/10 text-rose-300 border-rose-500/20" />
        <Kpi icon={<FileSearch className="w-5 h-5" />} label="Open Findings" value={String(openFindings.length)} hint="Awaiting review" accent="bg-indigo-500/10 text-indigo-300 border-indigo-500/20" />
        <Kpi icon={<CheckCircle2 className="w-5 h-5" />} label="Remediation" value={`${progress}%`} hint={`${doneRem} of ${remediation.length} completed`} accent="bg-emerald-500/10 text-emerald-300 border-emerald-500/20" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-6">
        <Card className="p-6 animate-rise-1">
          <SectionTitle title="Vulnerability Trend" hint="Opened vs. closed per week" right={<span className="text-[11px] px-2 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-500">LAST 8 WKS</span>} />
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData} margin={{ top: 5, right: 5, left: -15, bottom: 0 }}>
                <defs>
                  <linearGradient id="openG" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.28} />
                    <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="week" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0e1626', borderColor: '#334155', borderRadius: 10, fontSize: 13 }} />
                <Area type="monotone" dataKey="open" stroke="#22d3ee" strokeWidth={2} fill="url(#openG)" name="Opened" />
                <Area type="monotone" dataKey="closed" stroke="#34d399" strokeWidth={2} fill="transparent" name="Closed" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card className="p-6 animate-rise-1">
          <SectionTitle title="By Severity" hint="Open items only" right={<span className="text-[11px] px-2 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-500">{openVulns.length} OPEN</span>} />
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sevCounts} margin={{ top: 5, right: 10, left: 0, bottom: 0 }} barCategoryGap="28%">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0e1626', borderColor: '#334155', borderRadius: 10, fontSize: 13 }} cursor={{ fill: 'rgba(148,163,184,0.06)' }} />
                <Bar dataKey="count" radius={[8, 8, 4, 4]}>
                  {sevCounts.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Card className="p-6 animate-rise-2">
          <SectionTitle
            title="Recent Critical"
            hint="Highest-priority open items"
            right={<Link to="/vulnerabilities" className="text-[14px] font-medium text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1">View all <ArrowUpRight className="w-3.5 h-3.5" /></Link>}
          />
          <div className="space-y-3">
            {recentCritical.length === 0 && <p className="text-sm text-slate-500">No open critical vulnerabilities.</p>}
            {recentCritical.map((v) => (
              <Link key={v.id} to={`/vulnerabilities/${v.id}`} className="flex items-center justify-between gap-3 p-4 rounded-xl bg-white/[0.02] border border-white/[0.07] hover:border-slate-600 transition-colors group">
                <div className="min-w-0">
                  <Mono className="text-[12px] text-cyan-400 font-medium">{v.id}</Mono>
                  <p className="text-[15px] text-slate-100 truncate mt-0.5">{v.title}</p>
                  <p className="text-[13px] text-slate-500 mt-0.5">{assetById(v.assetId)?.name}</p>
                </div>
                <SeverityBadge severity={v.severity} />
              </Link>
            ))}
          </div>
        </Card>
        <div className="space-y-5 animate-rise-2">
          <Card className="p-6">
            <SectionTitle title="Recent Activity" hint="Latest operations" />
            <div className="space-y-1">
              {recentActivity.map((a, i) => (
                <div key={a.id} className="flex gap-3.5 py-2.5 first:pt-0 last:pb-0 relative">
                  {i !== recentActivity.length - 1 && <span className="absolute left-[5px] top-8 bottom-0 w-px bg-white/10" />}
                  <span className="mt-1.5 w-[10px] h-[10px] rounded-full bg-cyan-500/70 shrink-0" />
                  <div className="min-w-0">
                    <p className="text-slate-200 text-[14.5px]">{a.action.replace(/_/g, ' ')} · <Mono className="text-cyan-400 text-[12px]">{a.entityId}</Mono></p>
                    <p className="text-[12.5px] text-slate-500 mt-0.5">{a.user} · {a.timestamp}</p>
                  </div>
                </div>
              ))}
            </div>
          </Card>
          <Card className="p-6">
            <SectionTitle title="Scanner Status" hint="Integration health" />
            <div className="space-y-3">
              {integrations.map((s) => (
                <div key={s.id} className="flex items-center justify-between gap-3 p-3 rounded-xl bg-white/[0.02] border border-white/[0.06]">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-slate-800 text-slate-300"><Plug className="w-4 h-4" /></div>
                    <div>
                      <p className="text-[14.5px] text-slate-100 font-medium">{s.name}</p>
                      <p className="text-[12.5px] text-slate-500">Last sync: {s.lastSync || 'never'}</p>
                    </div>
                  </div>
                  <span className="text-[12px] font-medium px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 capitalize flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />{s.status}
                  </span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};
