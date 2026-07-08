import type { CveListResponse, CveDetailResponse } from '../types/api.cve.types';
import client from './client';

// Liste
export const getCveList = async (): Promise<CveListResponse> => {
    const res = await client.get('/api/v1/cve/list');
    return res.data;  // { cves: CveListItem[], count: number }
};

// Détail — l'ID passe dans l'URL
export const getCveDetail = async (cveId: string): Promise<CveDetailResponse> => {
    const res = await client.get(`/api/v1/cve/${cveId}`);
    return res.data;  // { cve: CveDetail | null, count: number, message?: string }
};