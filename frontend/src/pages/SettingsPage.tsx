import React, { useState } from 'react';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, buttonGhost, ConfirmDialog } from '../components/ui';

export const SettingsPage: React.FC = () => {
  const { user, logout } = useApp();
  const [confirmLogout, setConfirmLogout] = useState(false);
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
        <button onClick={() => setConfirmLogout(true)} className={buttonGhost}>Log out</button>
      </Card>
      {confirmLogout && (
        <ConfirmDialog
          title="Log out?"
          message="You will be signed out of CyberShield on this device."
          confirmLabel="Log out"
          onConfirm={() => { setConfirmLogout(false); logout(); }}
          onCancel={() => setConfirmLogout(false)}
        />
      )}
    </div>
  );
};
