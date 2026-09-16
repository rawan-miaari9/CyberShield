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

const sections: Array<{ heading: string; items: Array<{ to: string; label: string; icon: React.ElementType }> }> = [
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
      { to: '/ai-assistant', label: 'AI Security Assistant', icon: Sparkles },
    ],
  },
  {
    heading: 'System',
    items: [
      { to: '/integrations', label: 'Scanner Integrations', icon: Plug },
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

  const badgeFor = (to: string): string | null => {
    if (to === '/notifications' && unreadCount > 0) return String(unreadCount);
    if (to === '/vulnerabilities' && criticalOpen > 0) return String(criticalOpen);
    return null;
  };

  return (
    <aside className="w-64 h-screen bg-[#070a11] border-r border-slate-800/80 flex flex-col shrink-0 z-30">
      <div className="h-16 px-5 border-b border-slate-800/80 flex items-center bg-[#080d16]">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 text-cyan-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <span className="font-display font-bold tracking-wider text-base text-white">
              CYBER<span className="text-cyan-400">SHIELD</span>
            </span>
            <p className="text-xs text-slate-500">Vulnerability Management</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 px-3 py-5 space-y-5 overflow-y-auto">
        {sections.map((section) => (
          <div key={section.heading}>
            <div className="px-3 pb-2 text-xs font-semibold uppercase tracking-widest text-slate-500">
              {section.heading}
            </div>
            <div className="space-y-1">
              {section.items.map((item) => {
                const badge = badgeFor(item.to);
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) =>
                      `group flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
                        isActive
                          ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                          : 'text-slate-300 hover:text-white hover:bg-slate-800/40 border border-transparent'
                      }`
                    }
                  >
                    <span className="flex items-center gap-3">
                      <item.icon className="w-4 h-4" />
                      <span>{item.label}</span>
                    </span>
                    {badge && (
                      <span className="text-xs px-1.5 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/25">
                        {badge}
                      </span>
                    )}
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="px-4 py-4 border-t border-slate-800/80 bg-[#080d16]">
        <p className="text-xs text-slate-500 leading-relaxed">
          Findings from external scanners are reviewed here before becoming managed vulnerabilities.
        </p>
      </div>
    </aside>
  );
};
