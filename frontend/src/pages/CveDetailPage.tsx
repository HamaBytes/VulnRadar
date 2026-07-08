import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { getCveDetail } from '../api/cve';
import { CVE_REGEX } from '../constants/cve';
import type { CveDetail } from '../types/cve.types';

export function CveDetailPage() {
    const { cve_id } = useParams();
    const navigate = useNavigate();
    const [cve, setCve] = useState<CveDetail | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const load = async () => {
            if (!cve_id || !CVE_REGEX.test(cve_id)) {
                setError('Invalid CVE ID');
                setLoading(false);
                return;
            }

            setLoading(true);
            setError(null);

            try {
                const response = await getCveDetail(cve_id);
                setCve(response.cve);
                if (!response.cve) {
                    setError(response.message || 'CVE not found.');
                }
            } catch (err: any) {
                setError(err.response?.data?.message || err.response?.data?.error || 'Unable to load CVE detail.');
            } finally {
                setLoading(false);
            }
        };

        load();
    }, [cve_id]);

    return (
        <div className="w-full">
            <button
                type="button"
                onClick={() => navigate('/cves')}
                className="mb-6 inline-flex items-center gap-2 text-primary font-label-bold text-label-bold"
            >
                <ArrowLeft size={16} />
                Back to Registry
            </button>

            {loading && <div className="text-on-surface-variant">Loading CVE...</div>}
            {error && <div className="rounded-none border border-error/20 bg-error-container px-4 py-3 text-error">{error}</div>}

            {cve && (
                <div className="glass-panel p-6">
                    <div className="mb-6 border-l-4 border-primary pl-6">
                        <span className="font-label-bold text-label-bold text-primary uppercase tracking-[0.3em]">
                            {cve.severity || 'Unscored'}
                        </span>
                        <h1 className="font-headline-lg text-headline-lg text-on-surface uppercase mt-2">
                            {cve.cve_id}
                        </h1>
                    </div>
                    <p className="font-body-md text-body-md text-on-surface-variant mb-6">
                        {cve.description || 'No description available.'}
                    </p>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-code-sm text-code-sm">
                        <div className="border border-outline-variant p-4">
                            <span className="block text-outline uppercase mb-2">CVSS v3</span>
                            <span className="text-primary">{cve.cvss_v3_score ?? 'N/A'}</span>
                        </div>
                        <div className="border border-outline-variant p-4">
                            <span className="block text-outline uppercase mb-2">Published</span>
                            <span>{cve.published_date ? new Date(cve.published_date).toLocaleDateString() : 'N/A'}</span>
                        </div>
                        <div className="border border-outline-variant p-4">
                            <span className="block text-outline uppercase mb-2">References</span>
                            <span>{cve.references.length}</span>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
