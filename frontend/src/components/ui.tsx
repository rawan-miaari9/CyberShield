import React from 'react';
import { Link } from 'react-router-dom';

export const Card: React.FC<{ children: React.ReactNode; className?: string; glow?: boolean }> = ({
  children,
  className = '',
}) => (
  <div
    className={`relative rounded-2xl border border-slate-800/90 bg-gradient-to-b from-[#0e1626]/95 to-[#0a0f1c]/95 overflow-hidden ${className}`}
  >
    <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-400/30 to-transparent" />
    {children}
  </div>
);

export const PageHeader: React.FC<{
  title: string;
  subtitle: string;
  action?: React.ReactNode;
  eyebrow?: string;
}> = ({ title, subtitle, action, eyebrow }) => (
  <div className="relative flex flex-col lg:flex-row lg:items-end justify-between gap-5 mb-8 animate-rise">
    <div className="max-w-3xl">
      {eyebrow && (
        <div className="inline-flex items-center gap-2 mb-3 px-3 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/25 text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-300">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
          {eyebrow}
        </div>
      )}
      <h1 className="font-display text-[34px] sm:text-[40px] font-bold leading-[1.05] tracking-tight text-white">
        <span className="text-gradient-faint">{title.split(' ')[0]}</span>{' '}
        <span className="text-gradient-cyber">
          {title.split(' ').slice(1).join(' ') || ''}
        </span>
        {title.split(' ').length === 1 && <span className="text-gradient-cyber">.</span>}
      </h1>
      <p className="text-[15.5px] text-slate-400 mt-3 max-w-2xl leading-relaxed">{subtitle}</p>
      <div className="mt-4 h-[3px] w-24 rounded-full bg-gradient-to-r from-cyan-500/80 to-cyan-500/0" />
    </div>
    {action && <div className="shrink-0 flex items-center gap-3">{action}</div>}
  </div>
);

export function SeverityBadge({ severity }: { severity: string }) {
  const key = severity.toLowerCase();
  const map: Record<string, string> = {
    critical: 'bg-rose-500/10 text-rose-300 border-rose-500/25',
    high: 'bg-orange-500/10 text-orange-300 border-orange-500/25',
    medium: 'bg-amber-500/10 text-amber-300 border-amber-500/25',
    low: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25',
  };
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold uppercase tracking-wider border capitalize ${map[key] || 'bg-slate-800 text-slate-300 border-slate-700'}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-70" />
      {severity}
    </span>
  );
}

export function StatusBadge({ status, tone = 'neutral' }: { status: string; tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'info' }) {
  const tones: Record<string, string> = {
    neutral: 'bg-slate-800/80 text-slate-300 border-slate-700',
    success: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20',
    warning: 'bg-amber-500/10 text-amber-300 border-amber-500/20',
    danger: 'bg-rose-500/10 text-rose-300 border-rose-500/20',
    info: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/20',
  };
  return (
    <span
      className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${tones[tone]}`}
    >
      {status.replace(/_/g, ' ')}
    </span>
  );
}

export const Mono: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className = '' }) => (
  <span className={`font-mono-code tracking-tight ${className}`}>{children}</span>
);

export const LoadingState: React.FC<{ title?: string; hint?: string }> = ({
  title = 'Loading…',
  hint = 'Fetching records from the API.',
}) => (
  <div className="p-12 text-center" role="status" aria-live="polite">
    <div className="mx-auto w-11 h-11 rounded-xl bg-cyan-500/10 border border-cyan-500/25 text-cyan-300 flex items-center justify-center mb-4">
      <svg className="animate-spin" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M21 12a9 9 0 1 1-6.2-8.56" strokeLinecap="round" />
      </svg>
    </div>
    <p className="text-[15.5px] font-semibold text-slate-200">{title}</p>
    <p className="text-sm text-slate-500 mt-1.5">{hint}</p>
  </div>
);

export const EmptyState: React.FC<{ title: string; hint: string }> = ({ title, hint }) => (
  <div className="p-12 text-center">
    <div className="mx-auto w-11 h-11 rounded-xl bg-slate-800/70 border border-slate-700/60 flex items-center justify-center text-slate-500 mb-4">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <circle cx="11" cy="11" r="7" />
        <path d="m20 20-3.5-3.5" />
      </svg>
    </div>
    <p className="text-[15.5px] font-semibold text-slate-200">{title}</p>
    <p className="text-sm text-slate-500 mt-1.5">{hint}</p>
  </div>
);

export const Field: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div className="rounded-xl bg-white/[0.02] border border-white/[0.06] p-3.5">
    <div className="text-[11px] uppercase tracking-[0.12em] font-semibold text-slate-500 mb-1.5">{label}</div>
    <div className="text-[15px] text-slate-200 leading-relaxed">{children}</div>
  </div>
);

export const DetailLink: React.FC<{ to: string; children: React.ReactNode }> = ({ to, children }) => (
  <Link
    to={to}
    className="text-cyan-400 hover:text-cyan-300 hover:underline underline-offset-4 decoration-cyan-500/30 transition-colors font-medium"
  >
    {children}
  </Link>
);

export const inputClass =
  'w-full px-4 py-3 bg-[#0b1220] border border-slate-700/80 rounded-xl text-[15px] text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/15 transition-all';

export const buttonPrimary =
  'inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-semibold text-[15px] transition-all hover:-translate-y-px disabled:opacity-50 disabled:hover:translate-y-0';

export const buttonGhost =
  'inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-white/[0.04] hover:bg-white/[0.07] border border-white/10 text-slate-200 text-[15px] font-medium transition-all';

export const SectionTitle: React.FC<{ title: string; hint?: string; right?: React.ReactNode }> = ({
  title,
  hint,
  right,
}) => (
  <div className="flex items-center justify-between gap-4 mb-4">
    <div>
      <h3 className="text-[16px] font-semibold text-white tracking-tight flex items-center gap-2">
        <span className="w-1 h-4 rounded-full bg-gradient-to-b from-cyan-500 to-indigo-500 inline-block" />
        {title}
      </h3>
      {hint && <p className="text-[13.5px] text-slate-500 mt-1 ml-3">{hint}</p>}
    </div>
    {right}
  </div>
);
