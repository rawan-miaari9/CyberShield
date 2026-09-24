import React, { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, ArrowUpRight } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import type { SecurityFinding } from '../types';
import { Card, PageHeader, SeverityBadge, Field, Mono, LoadingState, SectionTitle } from '../components/ui';
import { api, FINDINGS_PAGE_SIZE } from '../services/api';

export const AssetDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { assets, findings, vulnerabilities, isLoading } = useApp();
  const asset = assets.find((a) => a.id === id);

  // Day 9 Task 6: the global findings context holds one 50-row page, so
  // this page loads its own asset-scoped listing (GET /findings/?asset=<id>)
  // instead of implying the global page covers this asset.
  const [scopedFindings, setScopedFindings] = useState<SecurityFinding[]>([]);
  const [scopedTotal, setScopedTotal] = useState<number | null>(null);
  const [scopedPage, setScopedPage] = useState(1);
  const [scopedNumPages, setScopedNumPages] = useState(1);
  const [scopedHasNext, setScopedHasNext] = useState(false);
  const [scopedHasPrev, setScopedHasPrev] = useState(false);
  const [scopedLoading, setScopedLoading] = useState(false);
  const [scopedError, setScopedError] = useState<string | null>(null);

  const loadScoped = async (page: number) => {
    if (!id) return;
    setScopedLoading(true);
    setScopedError(null);
    try {
      const res = await api.getFindingsPage(page, FINDINGS_PAGE_SIZE, { asset: id });
      setScopedFindings(res.items);
      setScopedTotal(res.count);
      setScopedPage(res.page);
      setScopedNumPages(res.numPages);
      setScopedHasNext(res.hasNext);
      setScopedHasPrev(res.hasPrevious);
    } catch (e) {
      setScopedError(e instanceof Error ? e.message : 'Failed to load findings.');
    } finally {
      setScopedLoading(false);
    }
  };

  useEffect(() => {
    loadScoped(1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  if (isLoading && !asset) {
    return (
      <div>
        <Link to="/assets" className="text-[15px] text-cyan-400 hover:underline">← Back to assets</Link>
        <Card className="p-10 mt-6 text-center text-slate-400"><LoadingState title="Loading asset…" /></Card>
      </div>
    );
  }

  if (!asset) {
    return (
      <div>
        <Link to="/assets" className="text-[15px] text-cyan-400 hover:underline">← Back to assets</Link>
        <Card className="p-10 mt-6 text-center text-slate-400">Asset not found.</Card>
      </div>
    );
  }

  // Summary counts prefer the backend aggregates (TRUE totals); the
  // fallbacks below only apply when aggregates are absent (demo mode).
  const assetOf = (v: (typeof vulnerabilities)[number]) => {
    if (v.assetId) return v.assetId;
    const f = findings.find((x) => x.id === v.findingId);
    return f ? f.assetId : '';
  };
  const assetVulns = vulnerabilities.filter((v) => String(assetOf(v)) === String(asset.id));
  const openVulns = assetVulns.filter((v) => !['VERIFIED', 'CLOSED'].includes(v.status)).length;
  const findingsTotal = typeof asset.findingCount === 'number' ? asset.findingCount : scopedTotal;
  const openTotal = typeof asset.openVulnerabilityCount === 'number' ? asset.openVulnerabilityCount : openVulns;

  return (
    <div className="animate-rise">
      <Link to="/assets" className="inline-flex items-center gap-1.5 text-[15px] text-slate-400 hover:text-cyan-300 mb-6 transition-colors">
        <ArrowLeft className="w-4 h-4" /> Back to assets
      </Link>

      <PageHeader
        eyebrow={asset.id}
        title={asset.name}
        subtitle={asset.description}
        action={<SeverityBadge severity={asset.criticality} />}
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-6">
        <Card className="p-6 lg:col-span-2">
          <SectionTitle title="Details" />
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Field label="Type">{asset.type}</Field>
            <Field label="Address"><Mono className="text-[13px] break-all">{asset.address}</Mono></Field>
            <Field label="Owner">{asset.owner}</Field>
            <Field label="Created"><Mono className="text-[13px]">{asset.createdAt}</Mono></Field>
          </div>
        </Card>
        <Card className="p-6">
          <SectionTitle title="Summary" />
          <div className="space-y-3 text-[15px]">
            <div className="flex justify-between items-center"><span className="text-slate-400">Findings</span><span className="text-white font-bold text-[17px]">{findingsTotal !== null ? findingsTotal : '…'}</span></div>
            <div className="h-px bg-white/5" />
            <div className="flex justify-between items-center"><span className="text-slate-400">Vulnerabilities</span><span className="text-white font-bold text-[17px]">{assetVulns.length}</span></div>
            <div className="h-px bg-white/5" />
            <div className="flex justify-between items-center"><span className="text-slate-400">Open</span><span className="text-white font-bold text-[17px]">{openTotal}</span></div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Card className="p-6">
          <SectionTitle
            title={`Associated findings (${findingsTotal !== null ? findingsTotal : '…'})`}
            right={<Link to="/findings" className="text-[14px] font-medium text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1">View all <ArrowUpRight className="w-3.5 h-3.5" /></Link>}
          />
          <div className="space-y-2.5">
            {scopedFindings.map((f) => (
              <Link key={f.id} to={`/findings/${f.id}`} className="flex items-center justify-between gap-3 p-3.5 rounded-xl bg-white/[0.02] border border-white/[0.07] hover:border-slate-600 transition-colors">
                <span className="min-w-0"><Mono className="text-cyan-400 text-[12px]">{f.id}</Mono> <span className="text-slate-200 ml-1 text-[14.5px]">{f.title}</span></span>
                <SeverityBadge severity={f.severity} />
              </Link>
            ))}
            {scopedError ? (
              <p className="text-[14.5px] text-rose-300" role="alert">Couldn&apos;t load findings: {scopedError}</p>
            ) : scopedLoading && scopedFindings.length === 0 ? (
              <LoadingState title="Loading findings…" />
            ) : scopedFindings.length === 0 ? (
              <p className="text-[14.5px] text-slate-500">No findings for this asset.</p>
            ) : null}
          </div>
          {!scopedError && scopedTotal !== null && scopedTotal > 0 && (
            <div className="flex items-center justify-between gap-3 mt-4 pt-4 border-t border-slate-800/70">
              <p className="text-[12.5px] text-slate-500">Page {scopedPage} of {scopedNumPages}</p>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => loadScoped(scopedPage - 1)}
                  disabled={!scopedHasPrev || scopedLoading}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 text-[13px] text-slate-100 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  Previous
                </button>
                <button
                  type="button"
                  onClick={() => loadScoped(scopedPage + 1)}
                  disabled={!scopedHasNext || scopedLoading}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 text-[13px] text-slate-100 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </Card>
        <Card className="p-6">
          <SectionTitle
            title={`Associated vulnerabilities (${assetVulns.length})`}
            right={<Link to="/vulnerabilities" className="text-[14px] font-medium text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1">View all <ArrowUpRight className="w-3.5 h-3.5" /></Link>}
          />
          <div className="space-y-2.5">
            {assetVulns.map((v) => (
              <Link key={v.id} to={`/vulnerabilities/${v.id}`} className="flex items-center justify-between gap-3 p-3.5 rounded-xl bg-white/[0.02] border border-white/[0.07] hover:border-slate-600 transition-colors">
                <span className="min-w-0"><Mono className="text-cyan-400 text-[12px]">{v.id}</Mono> <span className="text-slate-200 ml-1 text-[14.5px]">{v.title}</span></span>
                <span className="text-[13px] text-slate-400 shrink-0">{v.status.replace(/_/g, ' ')}</span>
              </Link>
            ))}
            {assetVulns.length === 0 && <p className="text-[14.5px] text-slate-500">No vulnerabilities for this asset.</p>}
          </div>
        </Card>
      </div>
    </div>
  );
};
