// ── EPSS ──

export interface Epss {
    id: number;
    cve_db_id: number;
    cve_id: string;
    epss_score: number | null;
    percentile: number | null;
}

// ── OSV ──

export interface OsvReference {
    id: number;
    osv_record_id: number;
    url: string;
    source_id: string | null;
    title: string | null;
}

export interface OsvRecord {
    id: number;
    cve_db_id: number;
    cve_id: string;
    osv_id: string | null;
    summary: string | null;
    severities: string[] | null;
    created_at: string;
    references: OsvReference[];
}

// ── GitHub Advisory ──

export type GithubSeverity = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';

export interface GithubAdvisoryReference {
    id: number;
    github_advisory_id: number;
    url: string;
    source: string;
}

export interface GithubAdvisory {
    id: number;
    cve_db_id: number;
    cve_id: string;
    summary: string | null;
    severity: GithubSeverity | null;
    package_name: string | null;
    created_at: string;
    references: GithubAdvisoryReference[];
}

// ── Vendor Advisory ──

export interface VendorAdvisory {
    id: number;
    cve_db_id: number;
    cve_id: string;
    vendor: string | null;
    is_available: boolean;
    sources: string[] | null;
    details: string | null;
    created_at: string;
}
