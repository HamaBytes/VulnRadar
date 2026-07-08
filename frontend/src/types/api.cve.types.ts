/**
 * API Types for CVE endpoints
 * GET /api/v1/cve/list   → { cves: CveListItem[], count: number }
 * GET /api/v1/cve/{id}   → { cve: CveDetail | null, count: number, message?: string }
 */

import type { CveListItem, CveDetail } from './cve.types';

// ── Query Parameters ──

export interface ListCvesQueryParams {
    page?: number;
    per_page?: number;
    cve_id?: string;
    severity?: string;
    min_score?: number;
    max_score?: number;
    published_after?: string;
    published_before?: string;
    has_exploit?: boolean;
    keyword?: string;
    vuln_status?: string;
    weakness_type?: string;
    cpe_keyword?: string;
    has_epss?: boolean;
    min_epss_score?: number;
    has_osv?: boolean;
    has_github_advisory?: boolean;
    has_vendor_advisory?: boolean;
    sort_by?: 'cve_id' | 'published_date' | 'last_modified_date' | 'cvss_v3_score' | 'severity';
    sort_order?: 'asc' | 'desc';
}

// ── Responses ──

export interface CveListResponse {
    cves: CveListItem[];
    count: number;
}

export interface CveDetailResponse {
    cve: CveDetail | null;
    count: number;
    message?: string;
}

// ── Errors ──

export interface CveApiError {
    error: string;
    message: string;
    cve_id?: string;
}

export interface CveNotFoundError extends CveApiError {
    error: 'CVE_NOT_FOUND';
    cve_id: string;
}
