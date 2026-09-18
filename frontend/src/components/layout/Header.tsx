import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Bell, LogOut, Menu, X, Search, ChevronRight } from 'lucide-react';
import { useApp } from '../../context/SecurityContext';

const titles: Record<string, { title: string; crumb: string }> = {
  '/dashboard': { title: 'Dashboard', crumb: 'Overview' },
  '/findings': { title: 'Findings', crumb: 'Security' },
  '/vulnerabilities': { title: 'Vulnerabilities', crumb: 'Security' },
  '/assets': { title: 'Assets', crumb: 'Security' },
  '/remediation': { title: 'Remediation', crumb: 'Management' },
  '/ai-assistant': { title: 'AI Assistant', crumb: 'Management' },
  '/integrations': { title: 'Integrations', crumb: 'System' },
  '/notifications': { title: 'Notifications', crumb: 'System' },
  '/audit-logs': { title: 'Audit Logs', crumb: 'System' },
  '/users': { title: 'Users & Roles', crumb: 'System' },
  '/settings': { title: 'Settings', crumb: 'Account' },
};

export const Header: React.FC = () => {
  const { unreadCount, user, logout } = useApp();
  const location = useLocation();
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);
  const displayName = user
  ? `${user.first_name || ''} ${user.last_name || ''}`.trim() || user.username
  : 'CyberShield';

const initials = displayName
  .split(' ')
  .map((part) => part[0])
  .join('')
  .substring(0, 2)
  .toUpperCase();

  const base = '/' + location.pathname.split('/')[1];
  const meta = titles[base] || { title: 'CyberShield', crumb: 'Platform' };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="h-[76px] px-7 bg-[#0c1220]/95 backdrop-blur border-b border-slate-800/80 flex items-center justify-between sticky top-0 z-20 shrink-0">
      <div className="flex items-center gap-3.5 min-w-0">
        <button
          className="lg:hidden p-2.5 rounded-lg text-slate-400 hover:bg-white/5 border border-white/10"
          onClick={() => setMenuOpen(!menuOpen)}
          aria-label="Toggle menu"
        >
          {menuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-[0.14em] text-slate-500">
            <span>{meta.crumb}</span>
            <ChevronRight className="w-3 h-3" />
            <span className="text-cyan-400/80">Live</span>
          </div>
          <h2 className="font-display text-[22px] font-bold text-white tracking-tight leading-tight">
            {meta.title}
          </h2>
        </div>
      </div>

      <div className="flex items-center gap-3.5">
        <div className="hidden md:flex items-center gap-2.5 px-4 py-3 rounded-xl bg-white/[0.03] border border-slate-800 w-[300px] focus-within:border-slate-600 transition-colors">
          <Search className="w-5 h-5 text-slate-600 shrink-0" />
          <input
            placeholder="Search vulns, assets, CVEs…"
            className="bg-transparent flex-1 text-[15px] text-slate-200 placeholder-slate-600 focus:outline-none min-w-0"
          />
          <kbd className="text-[11px] px-1.5 py-0.5 rounded-md bg-white/5 border border-white/10 text-slate-500 shrink-0">⌘K</kbd>
        </div>

        <Link
          to="/notifications"
          className="relative p-3 rounded-xl bg-white/[0.03] hover:bg-white/[0.06] border border-slate-800 text-slate-300 hover:text-white transition-colors"
          aria-label="Notifications"
        >
          <Bell className="w-5 h-5" />
          {unreadCount > 0 && (
            <span className="absolute -top-1.5 -right-1.5 min-w-[22px] h-[22px] px-1.5 rounded-full bg-cyan-600 text-white text-[12.5px] font-bold flex items-center justify-center">
              {unreadCount}
            </span>
          )}
        </Link>

        <div className="hidden sm:flex items-center gap-3 pl-4 border-l border-slate-800">
          <div className="w-11 h-11 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center text-[15px] font-semibold text-slate-200">
            {initials}
          </div>
          <div className="leading-tight hidden xl:block">
            <div className="text-[15px] font-semibold text-slate-100">{displayName}</div>
            <div className="text-[13px] text-slate-500">{user?.role || ''}</div>
          </div>
          <button
            onClick={handleLogout}
            className="p-2.5 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-white/5 transition-colors"
            title="Log out"
          >
            <LogOut className="w-5 h-5" />
          </button>
        </div>
      </div>
    </header>
  );
};
