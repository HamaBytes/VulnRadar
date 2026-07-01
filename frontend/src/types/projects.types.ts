export interface Project {
    id: number;
    name: string;
    description: string | null;
    created_at: string;
    item_count: number;
}

export interface ProjectItem {
    id: number;
    project_id: number;
    asset_name: string;
    ip: string | null;
    hostname: string | null;
    cve_id: string;
    cve_db_id: number | null;
    criticality: string | null;
    status: string;
    risk_score: number | null;
    risk_reasons: unknown;
    ai_summary: string | null;
    created_at: string;
}

export interface CreateProjectPayload {
    name: string;
    description?: string | null;
}

export interface UpdateProjectPayload {
    name?: string;
    description?: string | null;
}

export interface CreateProjectItemPayload {
    asset_name: string;
    cve_id: string;
    ip?: string | null;
    hostname?: string | null;
    cve_db_id?: number | null;
    criticality?: string | null;
    status?: string;
    risk_score?: number | null;
    risk_reasons?: unknown;
    ai_summary?: string | null;
}

export interface UpdateProjectItemPayload {
    asset_name?: string;
    ip?: string | null;
    hostname?: string | null;
    criticality?: string | null;
    status?: string;
    risk_score?: number | null;
    risk_reasons?: unknown;
    ai_summary?: string | null;
}
