import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getCveList } from '../api/cve';
import type { CveListItem } from '../types/cve.types';

export function CveListPage() {
    const navigate = useNavigate();
    const [cves, setCves] = useState<CveListItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const load = async () => {
            setLoading(true);
            setError(null);

            try {
                const response = await getCveList();
                setCves(response.cves);
            } catch (err: any) {
                setError(err.response?.data?.message || err.response?.data?.error || 'Unable to load CVE registry.');
            } finally {
                setLoading(false);
            }
        };

        load();
    }, []);

    return (
        <div className="w-full">
            <div className="mb-8 border-l-4 border-primary pl-6">
                <span className="font-label-bold text-label-bold text-primary uppercase tracking-[0.3em]">
                    Registry
                </span>
                <h1 className="font-headline-lg text-headline-lg text-on-surface uppercase mt-2">
                    CVE Registry
                </h1>
            </div>

            {loading && <div className="text-on-surface-variant">Loading CVEs...</div>}
            {error && <div className="rounded-none border border-error/20 bg-error-container px-4 py-3 text-error">{error}</div>}

            <div className="glass-panel overflow-x-auto">
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className="border-b border-outline-variant/30 font-label-bold text-label-bold text-outline">
                            <th className="px-4 py-3">CVE</th>
                            <th className="px-4 py-3">Severity</th>
                            <th className="px-4 py-3">Score</th>
                            <th className="px-4 py-3">Published</th>
                            <th className="px-4 py-3">Status</th>
                        </tr>
                    </thead>
                    <tbody className="font-code-sm text-code-sm">
                        {cves.map((cve) => (
                            <tr
                                key={cve.id}
                                className="border-b border-outline-variant/10 hover:bg-primary/5 transition-colors cursor-pointer"
                                onClick={() => navigate(`/cves/${encodeURIComponent(cve.cve_id)}`)}
                            >
                                <td className="px-4 py-4 text-primary">{cve.cve_id}</td>
                                <td className="px-4 py-4">{cve.severity || 'N/A'}</td>
                                <td className="px-4 py-4">{cve.cvss_v3_score ?? 'N/A'}</td>
                                <td className="px-4 py-4">{cve.published_date ? new Date(cve.published_date).toLocaleDateString() : 'N/A'}</td>
                                <td className="px-4 py-4">{cve.vuln_status || 'N/A'}</td>
                            </tr>
                        ))}
                        {!loading && cves.length === 0 && (
                            <tr>
                                <td className="px-4 py-6 text-center text-outline" colSpan={5}>
                                    No CVEs found.
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
