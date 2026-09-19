import React, { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { Card, Field, Mono, buttonPrimary, buttonGhost } from '../components/ui';
import type { RemediationStatus } from '../types';

const flow: RemediationStatus[] = ['To Do', 'In Progress', 'Remediated', 'Awaiting Verification', 'Completed'];

export const RemediationDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { remediation, vulnerabilities, userById, updateRemediationStatus, verifyVulnerability, user } = useApp();
  const [notes, setNotes] = useState('');
  const [verifyErr, setVerifyErr] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const task = remediation.find((r) => r.id === id);

  if (!task) {
    return (
      <div>
        <Link to="/remediation" className="text-sm text-cyan-300 hover:underline">← Back to remediation</Link>
        <Card className="p-10 mt-6 text-center text-slate-400">Task not found.</Card>
      </div>
    );
  }

  const vuln = vulnerabilities.find((v) => v.id === task.vulnerabilityId);
  const isAnalyst = user?.role === 'Security Analyst' || user?.role === 'Administrator' || user?.role === 'Security Manager';

  const verify = async () => {
    setVerifyErr(null);
    if (!vuln) return;
    setVerifying(true);
    try {
      // Persisted Strict lifecycle: only REMEDIATED -> VERIFIED succeeds;
      // backend rejects anything else (no local-only status jump).
      await verifyVulnerability(vuln.id);
      updateRemediationStatus(task.id, 'Completed');
    } catch (e) {
      setVerifyErr(e instanceof Error ? e.message : 'Verification failed.');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div>
      <Link to="/remediation" className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-cyan-300 mb-6">
        <ArrowLeft className="w-4 h-4" /> Back to remediation
      </Link>
      <div className="mb-8">
        <Mono className="text-sm text-cyan-300 font-semibold">{task.id}</Mono>
        <h1 className="text-2xl font-bold text-white mt-1">
          {vuln ? vuln.title : task.vulnerabilityId}
        </h1>
        {vuln && <p className="text-sm text-slate-400 mt-2">Related vulnerability: <Link to={`/vulnerabilities/${vuln.id}`} className="text-cyan-300 hover:underline font-mono-code">{vuln.id}</Link></p>}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="p-6 lg:col-span-2 space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
            <Field label="Status"><p>{task.status}</p></Field>
            <Field label="Assigned to"><p>{userById(task.assignedTo)?.name || '—'}</p></Field>
            <Field label="Due"><Mono>{task.dueDate || '—'}</Mono></Field>
            <Field label="Updated"><Mono>{task.updatedAt}</Mono></Field>
          </div>
          <Field label="Proposed fix"><p>{task.proposedFix}</p></Field>
          <Field label="Remediation notes"><p>{task.notes || '—'}</p></Field>
          <Field label="Verification notes"><p>{task.verificationNotes || '—'}</p></Field>
          <div>
            <label className="block text-xs uppercase tracking-wider text-slate-500 mb-1.5">Add a note</label>
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} placeholder="Progress update, evidence, links…" className="w-full px-3.5 py-2.5 bg-[#0d1322] border border-slate-700 rounded-xl text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500" />
          </div>
        </Card>
        <Card className="p-6">
          <h3 className="text-base font-semibold text-white mb-4">Workflow</h3>
          <div className="space-y-2 mb-5">
            {flow.map((s, i) => (
              <div key={s} className={`flex items-center gap-3 p-2.5 rounded-xl text-sm ${flow.indexOf(task.status) >= i ? 'bg-cyan-500/10 border border-cyan-500/25 text-cyan-200' : 'text-slate-500'}`}>
                <span className="w-6 h-6 rounded-full bg-slate-800 flex items-center justify-center text-xs font-bold">{i + 1}</span>{s}
              </div>
            ))}
          </div>
          <div className="space-y-2">
            {flow.filter((s) => s !== task.status && s !== 'Completed').map((s) => (
              <button key={s} onClick={() => updateRemediationStatus(task.id, s)} className={`${buttonGhost} w-full justify-center !text-xs`}>Move to {s}</button>
            ))}
            {verifyErr && <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-sm text-rose-300">{verifyErr}</div>}
            <button onClick={verify} disabled={!isAnalyst || verifying} title={isAnalyst ? 'Verify as analyst' : 'Only an analyst can verify'} className={`${buttonPrimary} w-full justify-center !text-xs`}>
              {verifying ? 'Verifying…' : 'Verify & complete (analyst)'}
            </button>
            {!isAnalyst && <p className="text-xs text-slate-500">Verification requires the Security Analyst role.</p>}
          </div>
        </Card>
      </div>
    </div>
  );
};
