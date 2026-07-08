// ── CVSS v2 ──

export interface CvssDataV2 {
    id: number;
    metric_id: number;
    version: string | null;
    vector_string: string | null;
    base_score: number | null;
    access_vector: string | null;
    access_complexity: string | null;
    authentication: string | null;
    confidentiality_impact: string | null;
    integrity_impact: string | null;
    availability_impact: string | null;
}

export interface CvssMetricV2 {
    id: number;
    cve_db_id: number;
    source: string | null;
    metric_type: string | null;
    base_severity: string | null;
    exploitability_score: number | null;
    impact_score: number | null;
    ac_insuf_info: boolean | null;
    obtain_all_privilege: boolean | null;
    obtain_user_privilege: boolean | null;
    obtain_other_privilege: boolean | null;
    user_interaction_required: boolean | null;
    cvss_data: CvssDataV2 | null;
}

// ── CVSS v3.1 ──

export interface CvssDataV31 {
    id: number;
    metric_id: number;
    version: string | null;
    vector_string: string | null;
    base_score: number | null;
    base_severity: string | null;
    attack_vector: string | null;
    attack_complexity: string | null;
    privileges_required: string | null;
    user_interaction: string | null;
    scope: string | null;
    confidentiality_impact: string | null;
    integrity_impact: string | null;
    availability_impact: string | null;
}

export interface CvssMetricV31 {
    id: number;
    cve_db_id: number;
    source: string | null;
    metric_type: string | null;
    exploitability_score: number | null;
    impact_score: number | null;
    cvss_data: CvssDataV31 | null;
}

// ── CVSS v4.0 ──

export interface CvssDataV40 {
    id: number;
    metric_id: number;
    version: string | null;
    vector_string: string | null;
    base_score: number | null;
    base_severity: string | null;
    attack_vector: string | null;
    attack_complexity: string | null;
    attack_requirements: string | null;
    privileges_required: string | null;
    user_interaction: string | null;
    vuln_confidentiality_impact: string | null;
    vuln_integrity_impact: string | null;
    vuln_availability_impact: string | null;
    sub_confidentiality_impact: string | null;
    sub_integrity_impact: string | null;
    sub_availability_impact: string | null;
}

export interface CvssMetricV40 {
    id: number;
    cve_db_id: number;
    source: string | null;
    metric_type: string | null;
    cvss_data: CvssDataV40 | null;
}