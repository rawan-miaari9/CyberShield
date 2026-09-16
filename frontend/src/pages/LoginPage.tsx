import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { inputClass, buttonPrimary } from '../components/ui';

export const LoginPage: React.FC = () => {
  const { login } = useApp();
  const navigate = useNavigate();
  const [email, setEmail] = useState('admin@cybershield.local');
  const [password, setPassword] = useState('admin123');
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
    <div className="min-h-screen w-screen flex items-center justify-center bg-[#070a12] cyber-grid-bg p-6">
      <div className="w-full max-w-md rounded-2xl bg-[#0a0f1d] border border-slate-800 p-8 shadow-2xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 text-cyan-400 flex items-center justify-center">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="font-display font-bold text-xl text-white">CYBER<span className="text-cyan-400">SHIELD</span></div>
            <p className="text-sm text-slate-400">Vulnerability Management Platform</p>
          </div>
        </div>
        <h1 className="text-xl font-semibold text-white mb-1">Log in</h1>
        <p className="text-sm text-slate-400 mb-6">Use your CyberShield account to continue.</p>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm text-slate-300 mb-1.5">Email</label>
            <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className={inputClass} autoComplete="username" />
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-1.5">Password</label>
            <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} className={inputClass} autoComplete="current-password" />
          </div>
          {error && <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-sm text-rose-300">{error}</div>}
          <button type="submit" disabled={busy} className={`${buttonPrimary} w-full justify-center`}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        <p className="text-xs text-slate-500 mt-6 leading-relaxed">
          Demo accounts: admin@cybershield.local / admin123 · analyst@cybershield.local / analyst123. Invalid credentials are rejected.
        </p>
      </div>
    </div>
  );
};
