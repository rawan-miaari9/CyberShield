import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { useApp } from '../../context/SecurityContext';

export const AppLayout: React.FC = () => {
  const { apiError, isDemoMode } = useApp();

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#0b0f17] text-slate-100">
      <div className="hidden lg:block">
        <Sidebar />
      </div>
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        <Header />
        {!isDemoMode && apiError && (
          <div className="px-6 lg:px-8 pt-4">
            <div className="max-w-6xl mx-auto px-4 py-3 rounded-xl bg-rose-500/10 border border-rose-500/25 text-sm text-rose-300">
              {apiError}
            </div>
          </div>
        )}
        <main className="flex-1 overflow-y-auto relative">
          <div className="absolute inset-0 cyber-grid-bg pointer-events-none" />
          <div className="relative max-w-6xl mx-auto p-6 lg:p-8">
            <Outlet />
            <footer className="mt-10 pb-4 flex items-center justify-between text-[12px] text-slate-600">
              <span className="tracking-wide">CYBERSHIELD · SECURE OPERATIONS</span>
              <span className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                ENCRYPTED SESSION
              </span>
            </footer>
          </div>
        </main>
      </div>
    </div>
  );
};
