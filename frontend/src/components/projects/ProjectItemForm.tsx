import { useState, useEffect, type FormEvent } from 'react';
import type { CreateProjectItemPayload } from '../../types/projects.types.ts';

interface ProjectItemFormProps {
    initialData?: Partial<CreateProjectItemPayload>;
    onSubmit: (data: CreateProjectItemPayload) => void;
    submitting: boolean;
    submitLabel?: string;
    isEditing?: boolean;
}

export function ProjectItemForm({
    initialData = {},
    onSubmit,
    submitting,
    submitLabel = 'ADD TRACKED CVE',
    isEditing = false,
}: ProjectItemFormProps) {
    const [assetName, setAssetName] = useState(initialData.asset_name ?? '');
    const [cveId, setCveId] = useState(initialData.cve_id ?? '');
    const [ip, setIp] = useState(initialData.ip ?? '');
    const [hostname, setHostname] = useState(initialData.hostname ?? '');
    const [criticality, setCriticality] = useState(initialData.criticality ?? '');
    const [status, setStatus] = useState(initialData.status ?? 'analysis');
    const [riskScore, setRiskScore] = useState(initialData.risk_score?.toString() ?? '');
    const [aiSummary, setAiSummary] = useState(initialData.ai_summary ?? '');

    useEffect(() => {
        setAssetName(initialData.asset_name ?? '');
        setCveId(initialData.cve_id ?? '');
        setIp(initialData.ip ?? '');
        setHostname(initialData.hostname ?? '');
        setCriticality(initialData.criticality ?? '');
        setStatus(initialData.status ?? 'analysis');
        setRiskScore(initialData.risk_score?.toString() ?? '');
        setAiSummary(initialData.ai_summary ?? '');
    }, [initialData]);

    const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        onSubmit({
            asset_name: assetName.trim(),
            cve_id: cveId.trim(),
            ip: ip.trim() || null,
            hostname: hostname.trim() || null,
            criticality: criticality.trim() || null,
            status: status || 'analysis',
            risk_score: riskScore ? Number(riskScore) : null,
            risk_reasons: null,
            ai_summary: aiSummary.trim() || null,
        });
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-6">
            <div>
                <label className="block font-label-bold text-label-bold text-outline mb-2" htmlFor="assetName">
                    ASSET_NAME
                </label>
                <input
                    id="assetName"
                    value={assetName}
                    onChange={(event) => setAssetName(event.target.value)}
                    className="tactical-input w-full p-2 font-code-sm text-code-sm text-on-surface"
                    placeholder="web-server-01"
                    type="text"
                />
            </div>
            <div>
                <label className="block font-label-bold text-label-bold text-outline mb-2" htmlFor="cveId">
                    CVE_ID
                </label>
                <input
                    id="cveId"
                    value={cveId}
                    onChange={(event) => setCveId(event.target.value)}
                    className="tactical-input w-full p-2 font-code-sm text-code-sm text-on-surface"
                    placeholder="CVE-2024-0001"
                    type="text"
                />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label className="block font-label-bold text-label-bold text-outline mb-2" htmlFor="ip">
                        IP_ADDRESS
                    </label>
                    <input
                        id="ip"
                        value={ip}
                        onChange={(event) => setIp(event.target.value)}
                        className="tactical-input w-full p-2 font-code-sm text-code-sm text-on-surface"
                        placeholder="192.168.1.10"
                        type="text"
                    />
                </div>
                <div>
                    <label className="block font-label-bold text-label-bold text-outline mb-2" htmlFor="hostname">
                        HOSTNAME
                    </label>
                    <input
                        id="hostname"
                        value={hostname}
                        onChange={(event) => setHostname(event.target.value)}
                        className="tactical-input w-full p-2 font-code-sm text-code-sm text-on-surface"
                        placeholder="prod-db-01"
                        type="text"
                    />
                </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                    <label className="block font-label-bold text-label-bold text-outline mb-2" htmlFor="criticality">
                        CRITICALITY
                    </label>
                    <input
                        id="criticality"
                        value={criticality}
                        onChange={(event) => setCriticality(event.target.value)}
                        className="tactical-input w-full p-2 font-code-sm text-code-sm text-on-surface"
                        placeholder="high"
                        type="text"
                    />
                </div>
                <div>
                    <label className="block font-label-bold text-label-bold text-outline mb-2" htmlFor="status">
                        STATUS
                    </label>
                    <select
                        id="status"
                        value={status}
                        onChange={(event) => setStatus(event.target.value)}
                        className="tactical-input w-full p-2 font-code-sm text-code-sm text-on-surface"
                    >
                        <option value="analysis">analysis</option>
                        <option value="mitigation_planned">mitigation_planned</option>
                        <option value="remediating">remediating</option>
                        <option value="risk_accepted">risk_accepted</option>
                    </select>
                </div>
                <div>
                    <label className="block font-label-bold text-label-bold text-outline mb-2" htmlFor="riskScore">
                        RISK_SCORE
                    </label>
                    <input
                        id="riskScore"
                        value={riskScore}
                        onChange={(event) => setRiskScore(event.target.value)}
                        className="tactical-input w-full p-2 font-code-sm text-code-sm text-on-surface"
                        placeholder="7.2"
                        type="number"
                        step="0.1"
                    />
                </div>
            </div>
            <div>
                <label className="block font-label-bold text-label-bold text-outline mb-2" htmlFor="aiSummary">
                    NOTES / SUMMARY
                </label>
                <textarea
                    id="aiSummary"
                    value={aiSummary}
                    onChange={(event) => setAiSummary(event.target.value)}
                    className="tactical-input w-full p-2 font-code-sm text-code-sm text-on-surface resize-none"
                    placeholder="Capture any contextual notes or analysis summary..."
                    rows={4}
                />
            </div>
            <button
                type="submit"
                disabled={submitting}
                className="w-full bg-primary/10 border border-primary text-primary font-label-bold text-label-bold py-4 hover:bg-primary/20 transition-all duration-300 shadow-[0_0_15px_rgba(173,198,255,0.2)] active:scale-95"
            >
                {submitting ? `${submitLabel.toUpperCase()}...` : submitLabel}
            </button>
        </form>
    );
}
