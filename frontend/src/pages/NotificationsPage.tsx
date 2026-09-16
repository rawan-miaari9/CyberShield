import React from 'react';
import { Link } from 'react-router-dom';
import { Bell } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, Mono, buttonGhost } from '../components/ui';

export const NotificationsPage: React.FC = () => {
  const { notifications, markNotificationRead, markAllNotificationsRead } = useApp();

  return (
    <div>
      <PageHeader
        title="Notifications"
        subtitle="In-app events for assignments, verification, due dates, and scanner syncs."
        action={<button onClick={markAllNotificationsRead} className={buttonGhost}>Mark all read</button>}
      />
      <Card className="divide-y divide-slate-800/70">
        {notifications.map((n) => (
          <div key={n.id} className={`p-5 flex items-start gap-4 ${n.read ? 'opacity-70' : ''}`}>
            <div className={`p-2.5 rounded-xl ${n.read ? 'bg-slate-800 text-slate-400' : 'bg-cyan-500/10 text-cyan-300'}`}>
              <Bell className="w-4 h-4" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <p className="text-sm font-medium text-slate-100">{n.title}</p>
                {!n.read && <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/25">Unread</span>}
              </div>
              <p className="text-sm text-slate-400 mt-1">{n.message}</p>
              <p className="text-xs text-slate-500 mt-1.5"><Mono>{n.createdAt}</Mono></p>
              {n.link && <Link to={n.link} className="text-sm text-cyan-300 hover:underline mt-1 inline-block">Open related item →</Link>}
            </div>
            {!n.read && (
              <button onClick={() => markNotificationRead(n.id)} className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 shrink-0">
                Mark read
              </button>
            )}
          </div>
        ))}
        {notifications.length === 0 && <p className="p-10 text-center text-sm text-slate-500">No notifications.</p>}
      </Card>
    </div>
  );
};
