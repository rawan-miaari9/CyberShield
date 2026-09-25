import React from 'react';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, buttonGhost } from '../components/ui';

export const SettingsPage: React.FC = () => {
  const { user, logout } = useApp();
  const fullName = [user?.first_name, user?.last_name].filter(Boolean).join(' ').trim();
  const identity = user?.name || fullName || user?.username || '—';

  return (
    <div>
      <PageHeader title="Settings" subtitle="Workspace preferences for this account." />
      <Card className="p-6">
        <h3 className="text-base font-semibold text-white mb-4">Profile</h3>
        <p className="text-sm text-slate-200">{identity}</p>
        <p className="text-sm text-slate-500 mt-1.5">Signed in as {user?.email} · {user?.role}</p>
        <p className="text-xs text-slate-500 mt-3">Account details are managed by your administrator.</p>
      </Card>
      <Card className="p-6 mt-6">
        <h3 className="text-base font-semibold text-white mb-2">Session</h3>
        <button onClick={logout} className={buttonGhost}>Log out</button>
      </Card>
    </div>
  );
};
