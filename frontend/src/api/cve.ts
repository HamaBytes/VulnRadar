import type { CveListResponse, CveDetailResponse } from '../types/api.cve.types';
import client from './client';

// Liste
export const getCveList = async (): Promise<CveListResponse> => {
    console.log('[DEBUG] getCveList: initiating request to /api/v1/cve/list');
    try {
        const res = await client.get('/api/v1/cve/list');
        console.log('[DEBUG] getCveList: received response', {
            status: res.status,
            statusText: res.statusText,
            dataKeys: Object.keys(res.data),
        });
        return res.data;  // { cves: CveListItem[], count: number }
    } catch (err: any) {
        console.error('[ERROR] getCveList: request failed', {
            message: err.message,
            responseStatus: err.response?.status,
            responseStatusText: err.response?.statusText,
            url: err.config?.url,
        });
        throw err;
    }
};

// Détail — l'ID passe dans l'URL
export const getCveDetail = async (cveId: string): Promise<CveDetailResponse> => {
    const res = await client.get(`/api/v1/cve/${cveId}`);
    return res.data;  // { cve: CveDetail | null, count: number, message?: string }
};