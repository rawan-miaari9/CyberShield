import React, { useEffect, useRef, useState } from 'react';
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
  const { unreadCount, notifications, markNotificationRead, markAllNotificationsRead, user, logout } = useApp();
  const location = useLocation();
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);
  const [bellOpen, setBellOpen] = useState(false);
  const [bellErr, setBellErr] = useState<string | null>(null);
  const [globalSearch, setGlobalSearch] = useState('');
  const bellRef = useRef<HTMLDivElement | null>(null);

  // Mirror the route in the global box (submit-on-Enter only — no live
  // search): show the active ?search= on /findings, clear anywhere else.
  useEffect(() => {
    if (location.pathname === '/findings') {
      setGlobalSearch(new URLSearchParams(location.search).get('search') || '');
    } else {
      setGlobalSearch('');
    }
  }, [location.pathname, location.search]);

  // Close the popover on outside click, Escape, or route change.
  useEffect(() => {
    if (!bellOpen) return;
    const onDown = (e: MouseEvent) => {
      if (bellRef.current && !bellRef.current.contains(e.target as Node)) setBellOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setBellOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [bellOpen]);

  useEffect(() => {
    setBellOpen(false);
  }, [location.pathname]);

  // Personal inbox: never show rows addressed to other users, even though
  // analysts are served everyone's notifications for the overview page.
  const mine = notifications.filter((n) => n.recipientId === undefined || n.recipientId === null || String(n.recipientId) === String(user?.id));
  const latest = mine.slice(0, 5);
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
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const q = globalSearch.trim();
            navigate(q ? `/findings?search=${encodeURIComponent(q)}` : '/findings');
          }}
          className="hidden md:flex items-center gap-2.5 px-4 py-3 rounded-xl bg-white/[0.03] border border-slate-800 w-[300px] focus-within:border-slate-600 transition-colors"
        >
          <Search className="w-5 h-5 text-slate-600 shrink-0" />
          <input
            value={globalSearch}
            onChange={(e) => {
              const next = e.target.value;
              setGlobalSearch(next);
              // Clearing the box fully on /findings?search=… drops the
              // param (replace, no history spam); FindingsPage's existing
              // URL sync then clears its search and restores the list.
              if (next === '' && location.pathname === '/findings' && new URLSearchParams(location.search).has('search')) {
                navigate('/findings', { replace: true });
              }
            }}
            placeholder="Search vulns, assets, CVEs…"
            aria-label="Search findings"
            className="bg-transparent flex-1 text-[15px] text-slate-200 placeholder-slate-600 focus:outline-none min-w-0"
          />
        </form>

        <div className="relative" ref={bellRef}>
          <button
            type="button"
            onClick={() => {
              setBellErr(null);
              setBellOpen((o) => !o);
            }}
            className="relative p-3 rounded-xl bg-white/[0.03] hover:bg-white/[0.06] border border-slate-800 text-slate-300 hover:text-white transition-colors"
            aria-label="Notifications"
            aria-expanded={bellOpen}
          >
            <Bell className="w-5 h-5" />
            {unreadCount > 0 && (
              <span className="absolute -top-1.5 -right-1.5 min-w-[22px] h-[22px] px-1.5 rounded-full bg-cyan-600 text-white text-[12.5px] font-bold flex items-center justify-center">
                {unreadCount}
              </span>
            )}
          </button>

          {bellOpen && (
            <div className="absolute right-0 top-full mt-2 w-[340px] max-w-[calc(100vw-2rem)] rounded-2xl border border-slate-800 bg-[#0e1626] shadow-2xl shadow-black/50 overflow-hidden z-50">
              <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800/80">
                <p className="text-sm font-semibold text-white">
                  Notifications{unreadCount > 0 && <span className="ml-2 text-xs font-medium text-cyan-300">{unreadCount} unread</span>}
                </p>
                {unreadCount > 0 && (
                  <button
                    type="button"
                    onClick={async () => {
                      setBellErr(null);
                      try {
                        await markAllNotificationsRead();
                      } catch (e) {
                        setBellErr(e instanceof Error ? e.message : 'Update failed.');
                      }
                    }}
                    className="text-xs text-cyan-300 hover:text-cyan-200 hover:underline"
                  >
                    Mark all read
                  </button>
                )}
              </div>

              {bellErr && <p className="px-4 py-2 text-xs text-rose-300 bg-rose-500/10 border-b border-rose-500/20">{bellErr}</p>}

              <div className="max-h-[320px] overflow-y-auto divide-y divide-slate-800/70">
                {latest.map((n) => (
                  <div key={n.id} className="px-4 py-3 flex items-start gap-3 hover:bg-white/[0.02]">
                    <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${n.read ? 'bg-slate-700' : 'bg-cyan-400'}`} />
                    <button
                      type="button"
                      onClick={() => {
                        setBellOpen(false);
                        if (n.link) navigate(n.link);
                        else navigate('/notifications');
                      }}
                      className="flex-1 min-w-0 text-left"
                    >
                      <p className="text-[13.5px] font-medium text-slate-100 truncate">{n.title}</p>
                      <p className="text-[13px] text-slate-400 truncate mt-0.5">{n.message}</p>
                    </button>
                    {!n.read && (
                      <button
                        type="button"
                        onClick={async () => {
                          setBellErr(null);
                          try {
                            await markNotificationRead(n.id);
                          } catch (e) {
                            setBellErr(e instanceof Error ? e.message : 'Update failed.');
                          }
                        }}
                        className="text-[11.5px] text-slate-500 hover:text-cyan-300 shrink-0 mt-0.5"
                      >
                        Mark read
                      </button>
                    )}
                  </div>
                ))}
                {latest.length === 0 && <p className="px-4 py-8 text-center text-sm text-slate-500">No notifications.</p>}
              </div>

              <Link
                to="/notifications"
                onClick={() => setBellOpen(false)}
                className="block px-4 py-3 text-center text-[13.5px] font-medium text-cyan-300 hover:text-cyan-200 hover:bg-white/[0.02] border-t border-slate-800/80"
              >
                View all notifications →
              </Link>
            </div>
          )}
        </div>

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
