import React from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { Card, SeverityBadge, Field, Mono } from '../components/ui';

export const AssetDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { assets, findings, vulnerabilities } = useApp();
  const asset = assets.find((a) => a.id === id);

  if (!asset) {
    return (
      <div>
        <Link to="/assets" className="text-sm text-cyan-300 hover:underline">← Back to assets</Link>
        <Card className="p-10 mt-6 text-center text-slate-400">Asset not found.</Card>
      </div>
    );
  }

  const assetFindings = findings.filter((f) => f.assetId === asset.id);
  const assetVulns = vulnerabilities.filter((v) => v.assetId === asset.id);

  return (
    <div>
      <Link to="/assets" className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-cyan-300 mb-6">
        <ArrowLeft className="w-4 h-4" /> Back to assets
      </Link>
      <div className="flex items-center gap-3 mb-8">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Mono className="text-sm text-cyan-300 font-semibold">{asset.id}</Mono>
            <SeverityBadge severity={asset.criticality} />
          </div>
          <h1 className="text-2xl font-bold text-white">{asset.name}</h1>
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <Card className="p-6 lg:col-span-2 space-y-5">
          <Field label="Description"><p>{asset.description}</p></Field>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
            <Field label="Type"><p>{asset.type}</p></Field>
            <Field label="Address"><Mono>{asset.address}</Mono></Field>
            <Field label="Owner"><p>{asset.owner}</p></Field>
            <Field label="Created"><Mono>{asset.createdAt}</Mono></Field>
          </div>
        </Card>
        <Card className="p-6">
          <h3 className="text-base font-semibold text-white mb-4">Summary</h3>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between"><span className="text-slate-400">Findings</span><span className="text-white font-semibold">{assetFindings.length}</span></div>
            <div className="flex justify-between"><span className="text-slate-400">Open vulnerabilities</span><span className="text-white font-semibold">{assetVulns.filter((v) => !['VERIFIED', 'CLOSED'].includes(v.status)).length}</span></div>
          </div>
        </Card>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="p-6">
          <h3 className="text-base font-semibold text-white mb-4">Associated findings ({assetFindings.length})</h3>
          <div className="space-y-2.5">
            {assetFindings.map((f) => (
              <Link key={f.id} to={`/findings/${f.id}`} className="flex items-center justify-between gap-3 p-3 rounded-xl bg-[#0d1322] border border-slate-800 hover:border-slate-700 text-sm">
                <span><Mono className="text-cyan-300 text-xs">{f.id}</Mono> <span className="text-slate-200 ml-1">{f.title}</span></span>
                <SeverityBadge severity={f.severity} />
              </Link>
            ))}
            {assetFindings.length === 0 && <p className="text-sm text-slate-500">No findings for this asset.</p>}
          </div>
        </Card>
        <Card className="p-6">
          <h3 className="text-base font-semibold text-white mb-4">Associated vulnerabilities ({assetVulns.length})</h3>
          <div className="space-y-2.5">
            {assetVulns.map((v) => (
              <Link key={v.id} to={`/vulnerabilities/${v.id}`} className="flex items-center justify-between gap-3 p-3 rounded-xl bg-[#0d1322] border border-slate-800 hover:border-slate-700 text-sm">
                <span><Mono className="text-cyan-300 text-xs">{v.id}</Mono> <span className="text-slate-200 ml-1">{v.title}</span></span>
                <span className="text-xs text-slate-400">{v.status.replace('_', ' ')}</span>
              </Link>
            ))}
            {assetVulns.length === 0 && <p className="text-sm text-slate-500">No vulnerabilities for this asset.</p>}
          </div>
        </Card>
      </div>
    </div>
  );
};
