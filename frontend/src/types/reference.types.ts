export type ExploitSource = 'ExploitDB' | 'Metasploit' | 'PoC-in-GitHub';

export interface CveReference {
    id: number;
    cve_db_id: number;
    url: string;
    source: string | null;
}

export interface ExploitReference {
    id: number;
    cve_db_id: number;
    cve_id: string;
    source: ExploitSource;
    url: string;
    exploit_id: string | null;
    title: string | null;
}
