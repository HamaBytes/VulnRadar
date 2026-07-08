import client from './client';

export const runPipelineSync = async (): Promise<unknown> => {
    const res = await client.get('/api/v1/pipeline/sync');
    return res.data;
};

export const getHealth = async (): Promise<unknown> => {
    const res = await client.get('/api/v1/health');
    return res.data;
};
