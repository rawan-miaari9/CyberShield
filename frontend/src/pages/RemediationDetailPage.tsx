import React, { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { Card, Field, Mono, LoadingState, buttonPrimary, buttonGhost } from '../components/ui';
import type { RemediationStatus } from '../types';

const flow: RemediationStatus[] = ['To Do', 'In Progress', 'Remediated', 'Awaiting Verification', 'Completed'];

// Progress highlighting follows the same order as `flow`. 'Awaiting
// Verification' is not a separate persisted state (the backend task enum
// is OPEN/IN_PROGRESS/COMPLETED) — it shares the Remediated step.
function flowIndex(status: RemediationStatus): number {
  if (status === 'Awaiting Verification') return 3;
  const i = flow.indexOf(status);
  return i >= 0 ? i : 0;
}

// Same presentation as Dashboard Recent Activity (Day 9): browser locale,
// local timezone. Invalid/missing values never leak raw text to the UI.
function formatDateTime(ts: string | null | undefined): string {
  if (!ts) return 'Date unavailable';
  const t = new Date(ts).getTime();
  if (Number.isNaN(t)) return 'Date unavailable';
  return new Date(t).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

export const RemediationDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { remediation, vulnerabilities, userById, updateRemediationStatus, verifyVulnerability, saveRemediation, user, isLoading, getRemediationDisplay } = useApp();
  const [notes, setNotes] = useState('');
  const [verifyErr, setVerifyErr] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [remMsg, setRemMsg] = useState<string | null>(null);
  const [remErr, setRemErr] = useState<string | null>(null);
  const [savingRem, setSavingRem] = useState(false);
  const [statusErr, setStatusErr] = useState<string | null>(null);
  const [changingStatus, setChangingStatus] = useState(false);
  const task = remediation.find((r) => r.id === id);

  if (isLoading && !task) {
    return (
      <div>
        <Link to="/remediation" className="text-sm text-cyan-300 hover:underline">← Back to remediation</Link>
        <Card className="p-10 mt-6 text-center text-slate-400"><LoadingState title="Loading task…" /></Card>
      </div>
    );
  }

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
  // Live display status: persisted task state + linked vulnerability
  // lifecycle (survives reloads; never a local-only guess).
  const displayStatus = getRemediationDisplay(task);
  const currentStep = flowIndex(displayStatus);
  // Only the assigned user (or an analyst) may advance the task — the
  // backend enforces the same rule, this just gates the buttons.
  const canWrite =
    isAnalyst ||
    (!!user && !!vuln && !!vuln.assignedTo && String(vuln.assignedTo) === String(user.id));
  // The single valid next action for the current state (forward-only; the
  // backend task endpoint itself is unguarded, so the UI must not invent
  // backward/skip jumps).
  const nextAction: { label: string; target: RemediationStatus; disabled?: boolean; hint?: string } | null = (() => {
    if (!canWrite) return null;
    if (displayStatus === 'To Do') return { label: 'Move to In Progress', target: 'In Progress' };
    if (displayStatus === 'In Progress') {
      if (vuln && vuln.status !== 'IN_PROGRESS' && vuln.status !== 'REMEDIATED') {
        return {
          label: 'Move to Remediated',
          target: 'Remediated',
          disabled: true,
          hint: `Vulnerability ${vuln.id} is ${vuln.status.replace(/_/g, ' ')} — it must be In Progress before work can be marked Remediated.`,
        };
      }
      return { label: 'Move to Remediated', target: 'Remediated' };
    }
    return null;
  })();

  const runStatusChange = async (target: RemediationStatus) => {
    setStatusErr(null);
    setChangingStatus(true);
    try {
      await updateRemediationStatus(task.id, target);
    } catch (e) {
      setStatusErr(e instanceof Error ? e.message : 'Status update failed.');
    } finally {
      setChangingStatus(false);
    }
  };

  const verify = async () => {
    setVerifyErr(null);
    if (!vuln) return;
    setVerifying(true);
    try {
      // Persisted Strict lifecycle: only REMEDIATED -> VERIFIED succeeds;
      // backend rejects anything else (no local-only status jump).
      await verifyVulnerability(vuln.id);
      await updateRemediationStatus(task.id, 'Completed');
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
            <Field label="Status"><p>{displayStatus}</p></Field>
            <Field label="Assigned to"><p>{(() => {
              const u = userById(task.assignedTo);
              if (!u) return '—';
              const full = [u.first_name, u.last_name].filter(Boolean).join(' ').trim();
              return full || u.username || u.email || `User ${u.id}`;
            })()}</p></Field>
            <Field label="Due"><Mono>{task.dueDate || '—'}</Mono></Field>
            <Field label="Updated"><Mono>{formatDateTime(task.updatedAt)}</Mono></Field>
          </div>
          <Field label="Proposed fix"><p>{task.proposedFix}</p></Field>
          <Field label="Remediation notes"><p>{task.notes || '—'}</p></Field>
          <Field label="Verification notes"><p>{task.verificationNotes || '—'}</p></Field>
          <div>
            <label className="block text-xs uppercase tracking-wider text-slate-500 mb-1.5">Add a note</label>
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} placeholder="Progress update, evidence, links…" className="w-full px-3.5 py-2.5 bg-[#0d1322] border border-slate-700 rounded-xl text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500" />
            {remMsg && <div className="mt-2 p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-sm text-emerald-300">{remMsg}</div>}
            {remErr && <div className="mt-2 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-sm text-rose-300">{remErr}</div>}
            <button
              onClick={async () => {
                setRemMsg(null);
                setRemErr(null);
                if (!notes.trim()) {
                  setRemErr('Enter a note first.');
                  return;
                }
                setSavingRem(true);
                try {
                  await saveRemediation(task.vulnerabilityId, {
                    notes: notes.trim(),
                    proposedFix: task.proposedFix,
                  });
                  setRemMsg('Note saved.');
                  setNotes('');
                } catch (e) {
                  setRemErr(e instanceof Error ? e.message : 'Save failed.');
                } finally {
                  setSavingRem(false);
                }
              }}
              disabled={savingRem}
              className={`${buttonPrimary} justify-center mt-2 !text-xs !px-4 !py-2`}
            >
              {savingRem ? 'Saving…' : 'Save note'}
            </button>
          </div>
        </Card>
        <Card className="p-6">
          <h3 className="text-base font-semibold text-white mb-4">Workflow</h3>
          <div className="space-y-2 mb-5">
            {flow.map((s, i) => (
              <div key={s} className={`flex items-center gap-3 p-2.5 rounded-xl text-sm ${currentStep >= i ? 'bg-cyan-500/10 border border-cyan-500/25 text-cyan-200' : 'text-slate-500'}`}>
                <span className="w-6 h-6 rounded-full bg-slate-800 flex items-center justify-center text-xs font-bold">{i + 1}</span>{s}
              </div>
            ))}
          </div>
          <div className="space-y-2">
            {statusErr && <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-sm text-rose-300">{statusErr}</div>}
            {nextAction ? (
              <>
                <button
                  key={nextAction.target}
                  onClick={() => runStatusChange(nextAction.target)}
                  disabled={changingStatus || nextAction.disabled}
                  className={`${buttonGhost} w-full justify-center !text-xs`}
                >
                  {changingStatus ? 'Saving…' : nextAction.label}
                </button>
                {nextAction.hint && <p className="text-xs text-slate-500">{nextAction.hint}</p>}
              </>
            ) : displayStatus === 'Remediated' && !isAnalyst ? (
              <p className="text-xs text-slate-500">Work marked Remediated — awaiting analyst verification.</p>
            ) : null}
            {!canWrite && displayStatus !== 'Completed' && (
              <p className="text-xs text-slate-500">Only the assigned user or a Security Analyst can advance this task.</p>
            )}
            {displayStatus === 'Remediated' && isAnalyst && vuln && vuln.status === 'REMEDIATED' && (
              <>
                {verifyErr && <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-sm text-rose-300">{verifyErr}</div>}
                <button onClick={verify} disabled={verifying} title="Verify as analyst" className={`${buttonPrimary} w-full justify-center !text-xs`}>
                  {verifying ? 'Verifying…' : 'Verify & complete (analyst)'}
                </button>
              </>
            )}
            {displayStatus === 'Completed' && (
              <p className="text-xs text-slate-500">Verified and complete — no further actions.</p>
            )}
            {!isAnalyst && displayStatus !== 'Completed' && <p className="text-xs text-slate-500">Verification requires the Security Analyst role.</p>}
          </div>
        </Card>
      </div>
    </div>
  );
};
