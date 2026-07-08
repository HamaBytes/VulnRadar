export interface CveWeaknessDescription {
    id: number;
    weakness_id: number;
    lang: string;
    value: string;
}

export interface CveWeakness {
    id: number;
    cve_db_id: number;
    source: string | null;
    weakness_type: string | null;
    descriptions: CveWeaknessDescription[];
}