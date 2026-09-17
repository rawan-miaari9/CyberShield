import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Eye, EyeOff, ArrowRight, Check } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { inputClass, buttonPrimary } from '../components/ui';

const points = [
  'Import findings from Nessus, Qualys and OpenVAS',
  'Prioritize risk with AI-assisted triage',
  'Track remediation through to verified fix',
];

export const LoginPage: React.FC = () => {
  const { login } = useApp();
  const navigate = useNavigate();
  const [email, setEmail] = useState('admin@cybershield.local');
  const [password, setPassword] = useState('admin123');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email, password);
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen w-screen flex bg-[#0b0f17] text-slate-100">
      {/* LEFT — calm brand panel */}
      <div className="hidden lg:flex flex-1 flex-col justify-between bg-[#0d1321] border-r border-slate-800 px-14 py-12">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-cyan-600 flex items-center justify-center text-white">
            <Shield className="w-6 h-6" strokeWidth={2} />
          </div>
          <div>
            <div className="font-bold text-[21px] tracking-wide text-white leading-none">
              CYBER<span className="text-cyan-400">SHIELD</span>
            </div>
            <p className="text-[14px] text-slate-500 mt-1.5">Vulnerability Management Platform</p>
          </div>
        </div>

        <div className="max-w-lg">
          <p className="text-[14px] font-semibold uppercase tracking-[0.16em] text-cyan-400/80 mb-5">
            Security operations
          </p>
          <h1 className="text-[58px] font-bold leading-[1.05] tracking-tight text-white">
            Know your risk.
            <br />
            Fix what matters.
          </h1>
          <p className="text-[19px] text-slate-400 leading-relaxed mt-6">
            One place to review scanner findings, manage vulnerabilities, and drive remediation to completion.
          </p>

          <ul className="mt-9 space-y-4">
            {points.map((p) => (
              <li key={p} className="flex items-start gap-3.5 text-[17px] text-slate-300">
                <span className="mt-1 w-6 h-6 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center shrink-0">
                  <Check className="w-3.5 h-3.5" strokeWidth={3} />
                </span>
                {p}
              </li>
            ))}
          </ul>
        </div>

        <p className="text-[14px] text-slate-600">
          © 2026 CyberShield Security · SOC 2 · ISO 27001
        </p>
      </div>

      {/* RIGHT — form */}
      <div className="flex-1 flex items-center justify-center px-6 py-12 sm:px-12">
        <div className="w-full max-w-[460px] animate-rise">
          <div className="lg:hidden flex items-center gap-2.5 mb-8">
            <div className="w-11 h-11 rounded-lg bg-cyan-600 flex items-center justify-center text-white">
              <Shield className="w-6 h-6" />
            </div>
            <span className="font-bold tracking-wide text-white text-[20px]">CYBER<span className="text-cyan-400">SHIELD</span></span>
          </div>

          <h2 className="text-[40px] font-bold tracking-tight text-white leading-tight">Sign in</h2>
          <p className="text-[17px] text-slate-400 mt-2.5 mb-9">
            Welcome back. Enter your credentials to continue.
          </p>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-[15px] font-medium text-slate-200 mb-2">Email</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className={`${inputClass} !px-4 !py-3.5 !text-[16px]`}
                placeholder="you@company.com"
                autoComplete="username"
              />
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-[15px] font-medium text-slate-200">Password</label>
                <button type="button" className="text-[14px] text-slate-500 hover:text-slate-300">
                  Forgot password?
                </button>
              </div>
              <div className="relative">
                <input
                  type={showPw ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={`${inputClass} !px-4 !py-3.5 !text-[16px] pr-12`}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPw(!showPw)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                >
                  {showPw ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {error && (
              <div className="px-4 py-3.5 rounded-lg bg-rose-500/10 border border-rose-500/25 text-[15px] text-rose-300">
                {error}
              </div>
            )}

            <button type="submit" disabled={busy} className={`${buttonPrimary} w-full !py-3.5 !text-[17px]`}>
              {busy ? 'Signing in…' : (
                <>Sign in <ArrowRight className="w-5 h-5" /></>
              )}
            </button>
          </form>

          <div className="mt-9 pt-7 border-t border-slate-800">
            <p className="text-[14px] font-medium text-slate-500 mb-3.5">Demo accounts — click to fill</p>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => { setEmail('admin@cybershield.local'); setPassword('admin123'); }}
                className="px-4 py-3.5 rounded-lg bg-slate-800/50 hover:bg-slate-800 border border-slate-700/80 text-left transition-colors"
              >
                <p className="text-[15px] font-semibold text-slate-200">Admin</p>
                <p className="text-[13px] text-slate-500 truncate font-mono-code">admin@cybershield.local</p>
              </button>
              <button
                type="button"
                onClick={() => { setEmail('analyst@cybershield.local'); setPassword('analyst123'); }}
                className="px-4 py-3.5 rounded-lg bg-slate-800/50 hover:bg-slate-800 border border-slate-700/80 text-left transition-colors"
              >
                <p className="text-[15px] font-semibold text-slate-200">Analyst</p>
                <p className="text-[13px] text-slate-500 truncate font-mono-code">analyst@cybershield.local</p>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
