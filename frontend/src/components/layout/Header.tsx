import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Bell, LogOut, Menu, X } from 'lucide-react';
import { useApp } from '../../context/SecurityContext';

const titles: Record<string, string> = {
  '/dashboard': 'Dashboard',
  '/findings': 'Findings',
  '/vulnerabilities': 'Vulnerabilities',
  '/assets': 'Assets',
  '/remediation': 'Remediation',
  '/ai-assistant': 'AI Security Assistant',
  '/integrations': 'Scanner Integrations',
  '/notifications': 'Notifications',
  '/audit-logs': 'Audit Logs',
  '/users': 'Users & Roles',
  '/settings': 'Settings',
};

export const Header: React.FC = () => {
  const { unreadCount, user, logout } = useApp();
  const location = useLocation();
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);

  const base = '/' + location.pathname.split('/')[1];
  const title = titles[base] || 'CyberShield';

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="h-16 px-6 bg-[#080d16]/95 backdrop-blur-md border-b border-slate-800/80 flex items-center justify-between sticky top-0 z-20">
      <div className="flex items-center gap-3">
        <button
          className="lg:hidden p-2 rounded-lg text-slate-300 hover:bg-slate-800"
          onClick={() => setMenuOpen(!menuOpen)}
          aria-label="Toggle menu"
        >
          {menuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
        <h2 className="text-lg font-semibold text-white">{title}</h2>
      </div>

      <div className="flex items-center gap-3">
        <Link
          to="/notifications"
          className="relative p-2.5 rounded-xl bg-[#0d1322] hover:bg-slate-800 border border-slate-700/80 text-slate-300 transition-colors"
          aria-label="Notifications"
        >
          <Bell className="w-4 h-4" />
          {unreadCount > 0 && (
            <span className="absolute -top-1 -right-1 min-w-5 h-5 px-1 rounded-full bg-cyan-500 text-slate-950 text-xs font-bold flex items-center justify-center">
              {unreadCount}
            </span>
          )}
        </Link>

        <div className="hidden sm:flex items-center gap-3 pl-3 border-l border-slate-800">
          <div className="w-9 h-9 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center text-sm font-bold text-cyan-300">
            {user ? user.name.split(' ').map((p) => p[0]).join('').substring(0, 2).toUpperCase() : 'CS'}
          </div>
          <div className="leading-tight">
            <div className="text-sm font-medium text-slate-100">{user?.name || 'Analyst'}</div>
            <div className="text-xs text-slate-500">{user?.role || ''}</div>
          </div>
          <button
            onClick={handleLogout}
            className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            title="Log out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
