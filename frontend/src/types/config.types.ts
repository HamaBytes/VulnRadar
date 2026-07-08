export interface CpeMatch {
    id: number;
    node_id: number;
    vulnerable: boolean | null;
    criteria: string | null;
    match_criteria_id: string | null;
}

export interface CveNode {
    id: number;
    configuration_id: number;
    operator: string | null;
    negate: boolean | null;
    cpe_matches: CpeMatch[];
}

export interface CveConfiguration {
    id: number;
    cve_db_id: number;
    nodes: CveNode[];
}