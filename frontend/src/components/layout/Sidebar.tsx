import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  FileSearch,
  Bug,
  Server,
  Wrench,
  Sparkles,
  Plug,
  Bell,
  ScrollText,
  Users,
  Settings,
} from 'lucide-react';
import { useApp } from '../../context/SecurityContext';

const sections: Array<{ heading: string; items: Array<{ to: string; label: string; icon: React.ElementType; accent?: string }> }> = [
  { heading: 'Overview', items: [{ to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard }] },
  {
    heading: 'Security',
    items: [
      { to: '/findings', label: 'Findings', icon: FileSearch },
      { to: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
      { to: '/assets', label: 'Assets', icon: Server },
    ],
  },
  {
    heading: 'Management',
    items: [
      { to: '/remediation', label: 'Remediation', icon: Wrench },
      { to: '/ai-assistant', label: 'AI Assistant', icon: Sparkles, accent: 'ai' },
    ],
  },
  {
    heading: 'System',
    items: [
      { to: '/integrations', label: 'Integrations', icon: Plug },
      { to: '/notifications', label: 'Notifications', icon: Bell },
      { to: '/audit-logs', label: 'Audit Logs', icon: ScrollText },
      { to: '/users', label: 'Users & Roles', icon: Users },
    ],
  },
  { heading: 'Account', items: [{ to: '/settings', label: 'Settings', icon: Settings }] },
];

export const Sidebar: React.FC = () => {
  const { unreadCount, vulnerabilities } = useApp();
  const criticalOpen = vulnerabilities.filter(
    (v) => v.severity === 'critical' && !['VERIFIED', 'CLOSED'].includes(v.status),
  ).length;

  const badgeFor = (to: string): { text: string; danger?: boolean } | null => {
    if (to === '/notifications' && unreadCount > 0) return { text: String(unreadCount) };
    if (to === '/vulnerabilities' && criticalOpen > 0) return { text: String(criticalOpen), danger: true };
    return null;
  };

  return (
    <aside className="w-[264px] h-screen bg-[#0c1220] border-r border-slate-800/80 flex flex-col shrink-0 z-30">
      <div className="h-[76px] px-5 border-b border-slate-800/80 flex items-center shrink-0 bg-white/[0.015]">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-600 to-indigo-600 text-white">
            <Shield className="w-5 h-5" strokeWidth={2} />
          </div>
          <div className="leading-none">
            <span className="font-display font-bold tracking-[0.08em] text-[17px] text-white">
              CYBER<span className="text-cyan-400">SHIELD</span>
            </span>
            <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500 mt-1 font-medium">Vuln Management</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 px-3.5 py-5 space-y-6 overflow-y-auto">
        {sections.map((section) => (
          <div key={section.heading}>
            <div className="px-3 pb-2.5 text-[12px] font-semibold uppercase tracking-[0.16em] text-slate-600">
              {section.heading}
            </div>
            <div className="space-y-1">
              {section.items.map((item) => {
                const badge = badgeFor(item.to);
                const isAI = item.accent === 'ai';
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) =>
                      `group relative flex items-center justify-between px-3.5 py-[10px] rounded-xl text-[15px] font-medium transition-colors ${
                        isActive
                          ? 'bg-cyan-500/[0.08] text-white border border-cyan-500/20'
                          : 'text-slate-400 hover:text-white hover:bg-white/[0.04] border border-transparent'
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && (
                          <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-6 rounded-full bg-cyan-500" />
                        )}
                        <span className="flex items-center gap-3">
                          <span
                            className={`p-1.5 rounded-lg transition-colors ${
                              isActive
                                ? 'bg-cyan-500/10 text-cyan-300'
                                : isAI
                                  ? 'bg-violet-500/10 text-violet-300'
                                  : 'bg-white/[0.04] text-slate-500 group-hover:text-slate-300'
                            }`}
                          >
                            <item.icon className="w-[18px] h-[18px]" />
                          </span>
                          <span>{item.label}</span>
                          {isAI && (
                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-md bg-violet-500/15 text-violet-300 border border-violet-500/20 tracking-wider">
                              AI
                            </span>
                          )}
                        </span>
                        {badge && (
                          <span
                            className={`text-[12px] font-semibold min-w-6 h-6 px-2 rounded-full flex items-center justify-center border ${
                              badge.danger
                                ? 'bg-rose-500/10 text-rose-300 border-rose-500/20'
                                : 'bg-slate-800 text-slate-300 border-slate-700'
                            }`}
                          >
                            {badge.text}
                          </span>
                        )}
                      </>
                    )}
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="px-4 pb-4 shrink-0">
        <div className="p-4 rounded-2xl bg-cyan-500/[0.06] border border-slate-800">
          <div className="flex items-center gap-2 mb-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <p className="text-[13.5px] font-semibold text-white">Shield status: Active</p>
          </div>
          <p className="text-[13px] text-slate-400 leading-relaxed">
            {criticalOpen > 0
              ? `${criticalOpen} critical item${criticalOpen > 1 ? 's need' : ' needs'} triage right now.`
              : 'No critical backlog. Scanners are in sync.'}
          </p>
        </div>
      </div>
    </aside>
  );
};
