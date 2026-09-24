import React from 'react';
import { Link } from 'react-router-dom';
import { Bug, FileSearch, ShieldAlert, CheckCircle2, Plug, ArrowRight, ArrowUpRight } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { useApp, canViewAuditLogs } from '../context/SecurityContext';
import { Card, SeverityBadge, Mono, SectionTitle } from '../components/ui';

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
  const { vulnerabilities, findings, findingsLoading, findingsError, findingsStats, remediation, auditLogs, assetById, user } = useApp();

  // Day 9 Task 2 — KPI verification against the real Django -> frontend
  // mapping (see services/api.ts). Backend sends UPPERCASE lifecycle statuses
  // (NEW..CLOSED) which pass through unchanged, so excluding VERIFIED/CLOSED
  // counts genuinely open work. Backend severities (CRITICAL..) are normalized
  // to lowercase, so `critical` matches. Backend finding DISMISSED maps to
  // frontend 'Ignored', so New + Reviewed is the true pending-review set.
  // Backend remediation COMPLETED maps to 'Completed', so Completed / total
  // is the correct ratio (safe for 0 tasks via the ternary below).
  const openVulns = vulnerabilities.filter((v) => !['VERIFIED', 'CLOSED'].includes(v.status));
  const criticalVulns = openVulns.filter((v) => v.severity === 'critical');
  // Day 9 Task 5 — Open Findings comes from GET /api/findings/stats/
  // (single GROUP BY query), NEVER from filtering the paginated first page.
  // findingsStats === null + loading → "…" (not 0); failed → "unavailable".
  // Only if stats failed but a page loaded do we fall back to the loaded
  // page with the hint marked approximate.
  const statsOpen = findingsStats ? findingsStats.open : null;
  const fallbackOpen = findings.filter((f) => f.status === 'New' || f.status === 'Reviewed').length;
  const openFindingsKnown = statsOpen !== null;
  const openFindingsValue = openFindingsKnown ? String(statsOpen) : findingsLoading ? '…' : findingsError ? 'unavailable' : `~${fallbackOpen}`;
  const openFindingsHint = openFindingsKnown
    ? 'Awaiting review'
    : findingsLoading
      ? 'Loading findings…'
      : findingsError
        ? 'Findings failed to load — count unavailable.'
        : 'Approximate — from the loaded page only.';
  const openFindingsCount = openFindingsKnown ? statsOpen : fallbackOpen;
  const doneRem = remediation.filter((r) => r.status === 'Completed').length;
  const progress = remediation.length ? Math.round((doneRem / remediation.length) * 100) : 0;

  // Day 9 Task 1 — real 8-week "discovered" trend from
  // vulnerabilities[].discoveredAt (mapped from backend created_at). The
  // frontend has no closedAt/resolvedAt field, so no "Closed" series is
  // fabricated — a single `discovered` series only. Buckets are local-midnight
  // 7-day windows ending today; invalid/missing dates are skipped and weeks
  // with zero discoveries render as 0.
  const discoveredTrend = React.useMemo(() => {
    const DAY_MS = 24 * 60 * 60 * 1000;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const buckets: Array<{ label: string; discovered: number }> = [];
    for (let i = 7; i >= 0; i--) {
      const start = new Date(today.getTime() - i * 7 * DAY_MS);
      const end = new Date(start.getTime() + 7 * DAY_MS);
      let count = 0;
      for (const v of vulnerabilities) {
        if (!v.discoveredAt) continue;
        const t = new Date(v.discoveredAt).getTime();
        if (Number.isNaN(t)) continue;
        if (t >= start.getTime() && t < end.getTime()) count += 1;
      }
      buckets.push({
        label: start.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
        discovered: count,
      });
    }
    return buckets;
  }, [vulnerabilities]);
  const discoveredTotal = discoveredTrend.reduce((n, b) => n + b.discovered, 0);

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

  const recentCritical = React.useMemo(() => {
    // "Recent" must actually be newest-first: sort on the real discoveredAt
    // field instead of relying on API ordering. Invalid dates sort last.
    const timeOrZero = (d: string | null | undefined) => {
      if (!d) return 0;
      const t = new Date(d).getTime();
      return Number.isNaN(t) ? 0 : t;
    };
    return [...criticalVulns]
      .sort((a, b) => timeOrZero(b.discoveredAt) - timeOrZero(a.discoveredAt))
      .slice(0, 4);
  }, [vulnerabilities]);
  const recentActivity = auditLogs.slice(0, 5);

  // mapDjangoVulnerability leaves assetId empty (the asset lives on the
  // linked finding), so resolve the display asset through the finding — the
  // same workaround VulnerabilitiesPage uses. Otherwise real-mode asset
  // names on this dashboard would always be blank.
  const findingById = React.useMemo(
    () => new Map(findings.map((f) => [String(f.id), f])),
    [findings],
  );
  const assetNameForVuln = (v: (typeof vulnerabilities)[number]) => {
    // Day 9 Task 6: the backend exposes the asset id directly; the
    // finding lookup remains as a fallback for older payloads.
    if (v.assetId) return assetById(v.assetId)?.name || v.assetId;
    const f = v.findingId ? findingById.get(String(v.findingId)) : undefined;
    if (!f) return '—';
    return assetById(f.assetId)?.name || f.assetId;
  };

  // Day 9 Task 6: backend timestamps are ISO-8601 UTC — render them in a
  // human-readable locale form. Invalid/missing values fall back safely.
  const formatActivityTime = (ts: string | null | undefined) => {
    if (!ts) return 'date unavailable';
    const t = new Date(ts).getTime();
    if (Number.isNaN(t)) return 'date unavailable';
    return new Date(t).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
    });
  };

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
          <p className="text-[12.5px] text-slate-500 mt-2">{progress}% remediation complete · {openFindingsKnown ? `${openFindingsCount} findings awaiting review` : findingsLoading ? 'Loading findings count…' : findingsError ? 'Findings count unavailable.' : `~${openFindingsCount} findings on this page`}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5 mb-6">
        <Kpi icon={<Bug className="w-5 h-5" />} label="Open Vulns" value={String(openVulns.length)} hint="Across all managed assets" accent="bg-cyan-500/10 text-cyan-300 border-cyan-500/20" />
        <Kpi icon={<ShieldAlert className="w-5 h-5" />} label="Critical" value={String(criticalVulns.length)} hint="Needs attention first" accent="bg-rose-500/10 text-rose-300 border-rose-500/20" />
        <Kpi icon={<FileSearch className="w-5 h-5" />} label="Open Findings" value={openFindingsValue} hint={openFindingsHint} accent="bg-indigo-500/10 text-indigo-300 border-indigo-500/20" />
        <Kpi icon={<CheckCircle2 className="w-5 h-5" />} label="Remediation" value={`${progress}%`} hint={`${doneRem} of ${remediation.length} completed`} accent="bg-emerald-500/10 text-emerald-300 border-emerald-500/20" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-6">
        <Card className="p-6 animate-rise-1">
          <SectionTitle title="Vulnerabilities Discovered" hint="New vulnerabilities per week" right={<span className="text-[11px] px-2 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-500">LAST 8 WKS</span>} />
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={discoveredTrend} margin={{ top: 5, right: 5, left: -15, bottom: 0 }}>
                <defs>
                  <linearGradient id="openG" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.28} />
                    <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="label" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0e1626', borderColor: '#334155', borderRadius: 10, fontSize: 13 }} />
                <Area type="monotone" dataKey="discovered" stroke="#22d3ee" strokeWidth={2} fill="url(#openG)" name="Discovered" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          {discoveredTotal === 0 && (
            <p className="text-[12.5px] text-slate-500 mt-2">No vulnerabilities discovered in the last 8 weeks.</p>
          )}
        </Card>
        <Card className="p-6 animate-rise-1">
          <SectionTitle title="By Severity" hint="Open items only" right={<span className="text-[11px] px-2 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-500">{openVulns.length} OPEN</span>} />
          {openVulns.length === 0 ? (
            <div className="h-60 flex items-center justify-center">
              <p className="text-sm text-slate-500">No open vulnerabilities to display.</p>
            </div>
          ) : (
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
          )}
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
                  <p className="text-[13px] text-slate-500 mt-0.5">{assetNameForVuln(v)}</p>
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
                    <p className="text-[12.5px] text-slate-500 mt-0.5">{a.user} · {formatActivityTime(a.timestamp)}</p>
                  </div>
                </div>
              ))}
              {!canViewAuditLogs(user) && (
                <p className="text-[12.5px] text-slate-500 leading-relaxed">
                  Recent activity is available to Security Analysts and Administrators.
                </p>
              )}
            </div>
          </Card>
          <Card className="p-6">
            <SectionTitle title="Scanner Status" hint="Integration health" />
            {/* Day 9 Task 4: the dashboard must not depend on the nonexistent
                GET /api/integrations/ collection (no backend route; the
                context already stopped requesting it) or on mock integration
                rows. There is also no persisted last-sync value exposed to
                the frontend, and health is only known after an explicit
                test-connection call — which the dashboard must NOT fire on
                page load (no repeated network probes) and must never
                auto-sync (POST findings/zap/sync/ stays an explicit action
                on the Findings page). So show the real configured scanner by
                name with a truthful Unknown state instead of fake data. */}
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-3 p-3 rounded-xl bg-white/[0.02] border border-white/[0.06]">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-slate-800 text-slate-300"><Plug className="w-4 h-4" /></div>
                  <div>
                    <p className="text-[14.5px] text-slate-100 font-medium">OWASP ZAP</p>
                    <p className="text-[12.5px] text-slate-500">Last sync: not available</p>
                  </div>
                </div>
                <span className="text-[12px] font-medium px-2.5 py-1 rounded-full bg-slate-500/10 text-slate-300 border border-slate-500/20 capitalize flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />Unknown — not checked
                </span>
              </div>
              <p className="text-[12.5px] text-slate-500 leading-relaxed">
                Connection health is only known after an explicit test. Test the connection and sync findings from the <Link to="/findings" className="text-cyan-400 hover:text-cyan-300">Findings page</Link>.
              </p>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};
