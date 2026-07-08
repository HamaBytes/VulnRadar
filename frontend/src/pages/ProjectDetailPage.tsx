import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import type { Project, ProjectItem, CreateProjectItemPayload, UpdateProjectItemPayload } from '../types/projects.types.ts';
import { addProjectItem, deleteProjectItem, getProject, listProjectItems, updateProjectItem } from '../api/Projects.ts';
import { ProjectItemTable } from '../components/projects/ProjectItemTable.tsx';
import { ProjectItemForm } from '../components/projects/ProjectItemForm.tsx';

export function ProjectDetailPage() {
    const { id } = useParams();
    const navigate = useNavigate();
    const projectId = Number(id);
    const hasValidProjectId = Boolean(id) && !Number.isNaN(projectId);
    const [project, setProject] = useState<Project | null>(null);
    const [items, setItems] = useState<ProjectItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [submitting, setSubmitting] = useState(false);
    const [editItem, setEditItem] = useState<ProjectItem | null>(null);

    useEffect(() => {
        const load = async () => {
            if (!hasValidProjectId) {
                setError('Invalid project ID');
                setLoading(false);
                return;
            }

            setLoading(true);
            setError(null);

            try {
                const [projectResponse, itemResponse] = await Promise.all([
                    getProject(projectId),
                    listProjectItems(projectId),
                ]);
                setProject(projectResponse);
                setItems(itemResponse);
            } catch (err: any) {
                setError(err.response?.data?.error || 'Unable to load project details.');
            } finally {
                setLoading(false);
            }
        };

        load();
    }, [hasValidProjectId, projectId]);

    if (!hasValidProjectId) {
        return <div className="text-error">Invalid project ID</div>;
    }

    const handleAddItem = async (data: CreateProjectItemPayload) => {
        setSubmitting(true);
        setError(null);

        try {
            const newItem = await addProjectItem(projectId, data);
            setItems((current) => [newItem, ...current]);
            setEditItem(null);
        } catch (err: any) {
            setError(err.response?.data?.error || 'Unable to add item.');
        } finally {
            setSubmitting(false);
        }
    };

    const handleDeleteItem = async (item: ProjectItem) => {
        setSubmitting(true);
        setError(null);

        try {
            await deleteProjectItem(projectId, item.cve_id);
            setItems((current) => current.filter((existing) => existing.id !== item.id));
        } catch (err: any) {
            setError(err.response?.data?.error || 'Unable to delete item.');
        } finally {
            setSubmitting(false);
        }
    };

    const handleEditItem = (item: ProjectItem) => {
        setEditItem(item);
    };

    const handleUpdateItem = async (data: UpdateProjectItemPayload) => {
        if (!editItem) return;
        setSubmitting(true);
        setError(null);

        try {
            const updatedItem = await updateProjectItem(projectId, editItem.cve_id, data);
            setItems((current) => current.map((existing) => (existing.id === updatedItem.id ? updatedItem : existing)));
            setEditItem(null);
        } catch (err: any) {
            setError(err.response?.data?.error || 'Unable to update item.');
        } finally {
            setSubmitting(false);
        }
    };

    return (
        <div className="max-w-max-width mx-auto w-full">
                <button
                    type="button"
                    onClick={() => navigate('/projects')}
                    className="mb-6 inline-flex items-center gap-2 text-primary font-label-bold text-label-bold"
                >
                    <ArrowLeft size={16} />
                    Back to Projects
                </button>

                {loading && <div className="text-on-surface-variant">Loading project...</div>}
                {error && <div className="rounded-none border border-error/20 bg-error-container px-4 py-3 text-error">{error}</div>}

                {project && (
                    <div className="glass-panel p-6 mb-6">
                        <h1 className="font-headline-lg text-headline-lg text-on-surface mb-2">{project.name}</h1>
                        <p className="font-code-sm text-code-sm text-outline mb-4">ID: {project.id}</p>
                        <p className="font-body-md text-body-md text-on-surface-variant">{project.description || 'No description provided.'}</p>
                        <div className="mt-4 flex flex-wrap gap-4 text-sm text-outline">
                            <span>Created: {new Date(project.created_at).toLocaleString()}</span>
                            <span>Tracked Items: {project.item_count}</span>
                        </div>
                    </div>
                )}

                <div className="glass-panel p-6">
                    <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                        <div>
                            <h2 className="font-headline-md text-headline-md">Tracked CVEs</h2>
                            <span className="font-code-sm text-code-sm text-outline">{items.length} items</span>
                        </div>
                        {editItem && (
                            <button
                                type="button"
                                onClick={() => setEditItem(null)}
                                className="rounded-none border border-outline-variant px-4 py-2 text-outline hover:border-primary/50 hover:text-on-surface transition-all"
                            >
                                Cancel edit
                            </button>
                        )}
                    </div>

                    <div className="grid gap-6 lg:grid-cols-[1fr_1.4fr]">
                        <div className="rounded-none border border-outline-variant/30 bg-surface-container-lowest p-5">
                            <h3 className="font-label-bold text-label-bold text-on-surface mb-4">{editItem ? 'Edit tracked CVE' : 'Add tracked CVE'}</h3>
                            <ProjectItemForm
                                initialData={editItem ?? undefined}
                                onSubmit={async (payload) => {
                                    if (editItem) {
                                        const { cve_id: _cveId, ...updatePayload } = payload;
                                        await handleUpdateItem(updatePayload);
                                    } else {
                                        await handleAddItem(payload);
                                    }
                                }}
                                submitting={submitting}
                                submitLabel={editItem ? 'UPDATE TRACKED CVE' : 'ADD TRACKED CVE'}
                            />
                        </div>

                        <div className="rounded-none border border-outline-variant/30 bg-surface-container-lowest p-5">
                            <ProjectItemTable items={items} onEdit={handleEditItem} onDelete={handleDeleteItem} />
                        </div>
                    </div>
                </div>
        </div>
    );
}
