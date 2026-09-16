import React, { useState } from 'react';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, buttonGhost } from '../components/ui';

export const SettingsPage: React.FC = () => {
  const { user, logout } = useApp();
  const [displayName, setDisplayName] = useState(user?.name || '');
  const [saved, setSaved] = useState(false);

  return (
    <div>
      <PageHeader title="Settings" subtitle="Workspace preferences for this account." />
      <Card className="p-6">
        <h3 className="text-base font-semibold text-white mb-4">Profile</h3>
        <label className="block text-sm text-slate-300 mb-1.5">Display name</label>
        <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} className="w-full px-3.5 py-2.5 bg-[#0d1322] border border-slate-700 rounded-xl text-sm text-slate-200 focus:outline-none focus:border-cyan-500" />
        <p className="text-sm text-slate-500 mt-2">Signed in as {user?.email} · {user?.role}</p>
        <button onClick={() => { setSaved(true); setTimeout(() => setSaved(false), 2000); }} className={`${buttonGhost} mt-4`}>
          {saved ? 'Saved' : 'Save preferences'}
        </button>
      </Card>
      <Card className="p-6 mt-6">
        <h3 className="text-base font-semibold text-white mb-2">Session</h3>
        <button onClick={logout} className={buttonGhost}>Log out</button>
      </Card>
    </div>
  );
};
