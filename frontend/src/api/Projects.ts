import client from './client.ts';
import type {
    Project,
    ProjectItem,
    CreateProjectPayload,
    CreateProjectItemPayload,
    UpdateProjectPayload,
    UpdateProjectItemPayload,
} from '../types/projects.types.ts';

export const getProjects = async (): Promise<Project[]> => {
    const res = await client.get('/api/v1/projects');
    return res.data.projects;
};

export const getProject = async (projectId: number): Promise<Project> => {
    const res = await client.get(`/api/v1/projects/${projectId}`);
    return res.data;
};

export const createProject = async (data: CreateProjectPayload): Promise<Project> => {
    const res = await client.post('/api/v1/projects', data);
    return res.data;
};

export const updateProject = async (
    projectId: number,
    data: UpdateProjectPayload,
): Promise<Project> => {
    const res = await client.patch(`/api/v1/projects/${projectId}`, data);
    return res.data;
};

export const deleteProject = async (projectId: number): Promise<{ status: string }> => {
    const res = await client.delete(`/api/v1/projects/${projectId}`);
    return res.data;
};

export const addProjectItem = async (
    projectId: number,
    data: CreateProjectItemPayload,
): Promise<ProjectItem> => {
    const res = await client.post(`/api/v1/projects/${projectId}/items`, data);
    return res.data;
};

export const listProjectItems = async (projectId: number): Promise<ProjectItem[]> => {
    const res = await client.get(`/api/v1/projects/${projectId}/items`);
    return res.data.items;
};

export const updateProjectItem = async (
    projectId: number,
    cveId: string,
    data: UpdateProjectItemPayload,
): Promise<ProjectItem> => {
    const res = await client.patch(`/api/v1/projects/${projectId}/items/${encodeURIComponent(cveId)}`, data);
    return res.data;
};

export const deleteProjectItem = async (
    projectId: number,
    cveId: string,
): Promise<{ status: string }> => {
    const res = await client.delete(`/api/v1/projects/${projectId}/items/${encodeURIComponent(cveId)}`);
    return res.data;
};

