import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { useApp } from '../../context/SecurityContext';

export const AppLayout: React.FC = () => {
  const { apiError, isDemoMode } = useApp();

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#070a12] text-slate-100">
      <div className="hidden lg:block">
        <Sidebar />
      </div>
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        <Header />
        {!isDemoMode && apiError && (
          <div className="px-6 lg:px-10 pt-4">
            <div className="max-w-6xl mx-auto p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-sm text-rose-200">
              {apiError}
            </div>
          </div>
        )}
        <main className="flex-1 overflow-y-auto cyber-grid-bg p-6 lg:p-10">
          <div className="max-w-6xl mx-auto">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
};
