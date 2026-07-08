import type { CvssMetricV2, CvssMetricV31, CvssMetricV40 } from './cvss.types';
import type { CveWeakness } from './weakness.types';
import type { CveConfiguration } from './config.types';
import type { CveReference, ExploitReference } from './reference.types';
import type { Epss, OsvRecord, GithubAdvisory, VendorAdvisory } from './enrichment.types';

// ── API Response shapes (what backend actually returns) ──

export interface CveDescriptionApi {
    lang: string;
    value: string;
}

export interface CveTagApi {
    value: string;
}

export interface CveReferenceApi {
    url: string;
    source: string | null;
}

// ── Full CVE model (ORM) ──

export interface CveDescription {
    id: number;
    cve_db_id: number;
    lang: string;
    value: string;
}

export interface CveTag {
    id: number;
    cve_db_id: number;
    value: string;
}

export interface Cve {
    id: number;
    cve_id: string;
    source_identifier: string | null;
    title: string | null;
    description: string | null;
    cvss_v3_score: number | null;
    severity: string | null;
    published_date: string | null;
    last_modified_date: string | null;
    vuln_status: string | null;
    created_at: string;

    // Relations (ORM full objects)
    tags: CveTag[];
    descriptions: CveDescription[];
    cvss_v2_metrics: CvssMetricV2[];
    cvss_v31_metrics: CvssMetricV31[];
    cvss_v40_metrics: CvssMetricV40[];
    weaknesses: CveWeakness[];
    configurations: CveConfiguration[];
    references: CveReference[];
    epss: Epss[];
    exploit_references: ExploitReference[];
    osv_records: OsvRecord[];
    github_advisories: GithubAdvisory[];
    vendor_advisories: VendorAdvisory[];
}

/** CVE from API list endpoint (Cve.to_dict()) */
export interface CveListItem {
    id: number;
    cve_id: string;
    source_identifier: string | null;
    title: string | null;
    description: string | null;
    cvss_v3_score: number | null;
    severity: string | null;
    published_date: string | null;
    last_modified_date: string | null;
    vuln_status: string | null;
}

/** CVE from API detail endpoint — relations are simplified by backend */
export interface CveDetail {
    id: number;
    cve_id: string;
    source_identifier: string | null;
    title: string | null;
    description: string | null;
    cvss_v3_score: number | null;
    severity: string | null;
    published_date: string | null;
    last_modified_date: string | null;
    vuln_status: string | null;
    created_at: string;

    // Relations — API-simplified shapes
    tags: string[];                              // backend: [t.value for t in cve.tags]
    descriptions: CveDescriptionApi[];           // backend: {lang, value} only
    cvss_v2_metrics: CvssMetricV2[];
    cvss_v31_metrics: CvssMetricV31[];
    cvss_v40_metrics: CvssMetricV40[];
    weaknesses: CveWeakness[];
    configurations: CveConfiguration[];
    references: CveReferenceApi[];              // backend: {url, source} only
    epss: Epss[];
    exploit_references: ExploitReference[];
    osv_records: OsvRecord[];
    github_advisories: GithubAdvisory[];
    vendor_advisories: VendorAdvisory[];
}
