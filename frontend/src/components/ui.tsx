import React from 'react';
import { Link } from 'react-router-dom';

export const Card: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className = '' }) => (
  <div className={`rounded-2xl bg-[#0a0f1d] border border-slate-800/90 shadow-xl ${className}`}>{children}</div>
);

export const PageHeader: React.FC<{ title: string; subtitle: string; action?: React.ReactNode }> = ({ title, subtitle, action }) => (
  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 mb-8">
    <div>
      <h1 className="text-2xl font-bold text-white tracking-tight">{title}</h1>
      <p className="text-sm text-slate-400 mt-1.5 max-w-2xl leading-relaxed">{subtitle}</p>
    </div>
    {action && <div className="shrink-0">{action}</div>}
  </div>
);

export function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
    high: 'bg-orange-500/10 text-orange-300 border-orange-500/30',
    medium: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
    low: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
    Critical: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
    High: 'bg-orange-500/10 text-orange-300 border-orange-500/30',
    Medium: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
    Low: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
  };
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border capitalize ${map[severity] || 'bg-slate-700 text-slate-300 border-slate-600'}`}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-200 border border-slate-700">
      {status.replace(/_/g, ' ')}
    </span>
  );
}

export const Mono: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className = '' }) => (
  <span className={`font-mono-code ${className}`}>{children}</span>
);

export const EmptyState: React.FC<{ title: string; hint: string }> = ({ title, hint }) => (
  <div className="p-10 text-center">
    <p className="text-base font-medium text-slate-200">{title}</p>
    <p className="text-sm text-slate-400 mt-1">{hint}</p>
  </div>
);

export const Field: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div>
    <div className="text-xs uppercase tracking-wider text-slate-500 mb-1">{label}</div>
    <div className="text-sm text-slate-200 leading-relaxed">{children}</div>
  </div>
);

export const DetailLink: React.FC<{ to: string; children: React.ReactNode }> = ({ to, children }) => (
  <Link to={to} className="text-cyan-300 hover:text-cyan-200 hover:underline">
    {children}
  </Link>
);

export const inputClass =
  'w-full px-3.5 py-2.5 bg-[#0d1322] border border-slate-700 rounded-xl text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/40 transition-all';

export const buttonPrimary =
  'inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition-all shadow-[0_0_15px_rgba(6,182,212,0.25)] disabled:opacity-50';

export const buttonGhost =
  'inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800/60 hover:bg-slate-800 border border-slate-700 text-slate-200 text-sm transition-colors';
