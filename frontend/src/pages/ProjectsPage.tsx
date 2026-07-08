import { useEffect, useState } from 'react';
import { ListFilter, SquarePlus, TriangleAlert } from 'lucide-react';
import type { CreateProjectPayload, Project } from '../types/projects.types.ts';
import { createProject, deleteProject, getProjects } from '../api/Projects.ts';
import { ProjectCard } from '../components/projects/ProjectCard.tsx';
import { ProjectForm } from '../components/projects/ProjectForm.tsx';

export function ProjectsPage() {
    const [projects, setProjects] = useState<Project[]>([]);
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const loadProjects = async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await getProjects();
            setProjects(data);
        } catch (err: any) {
            setError(err.response?.data?.error || 'Unable to load projects.');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadProjects();
    }, []);

    const handleCreateProject = async (payload: CreateProjectPayload) => {
        setError(null);

        if (!payload.name.trim()) {
            setError('Project name is required');
            return;
        }

        setSaving(true);
        try {
            const newProject = await createProject(payload);
            setProjects((current) => [newProject, ...current]);
        } catch (err: any) {
            setError(err.response?.data?.error || 'Unable to create project.');
        } finally {
            setSaving(false);
        }
    };

    const handleDelete = async (projectId: number) => {
        setError(null);
        try {
            await deleteProject(projectId);
            setProjects((current) => current.filter((project) => project.id !== projectId));
        } catch (err: any) {
            setError(err.response?.data?.error || 'Unable to delete project.');
        }
    };

    const activeAssignmentCount = projects.length;
    const criticalRiskCount = projects.filter((project) => project.item_count > 0).length;

    return (
        <div className="w-full grid grid-cols-12 gap-gutter">
                <section className="col-span-12 grid grid-cols-1 md:grid-cols-3 gap-gutter mb-4">
                    <div className="glass-panel p-4 flex flex-col justify-between h-24">
                        <div className="scanline"></div>
                        <span className="font-label-bold text-label-bold text-outline uppercase tracking-widest">Active_Assignments</span>
                        <div className="flex items-baseline gap-2">
                            <span className="font-display-xl text-display-xl text-primary">{loading ? '...' : activeAssignmentCount}</span>
                            <span className="font-code-sm text-code-sm text-outline-variant">/SEC_GRID_A</span>
                        </div>
                    </div>
                    <div className="glass-panel p-4 flex flex-col justify-between h-24 border-error/20">
                        <div className="scanline"></div>
                        <span className="font-label-bold text-label-bold text-error uppercase tracking-widest">Critical_Risk_Items</span>
                        <div className="flex items-baseline gap-2">
                            <span className="font-display-xl text-display-xl text-error pulse-critical">{criticalRiskCount}</span>
                            <TriangleAlert size={20} className="text-error" />
                        </div>
                    </div>
                    <div className="glass-panel p-4 flex flex-col justify-between h-24">
                        <div className="scanline"></div>
                        <span className="font-label-bold text-label-bold text-secondary uppercase tracking-widest">Last_Telemetry_Sync</span>
                        <div className="flex items-baseline gap-2">
                            <span className="font-display-xl text-display-xl text-secondary">0.4</span>
                            <span className="font-code-sm text-code-sm text-outline-variant">MS_AGO</span>
                        </div>
                    </div>
                </section>

                <aside className="col-span-12 lg:col-span-4 flex flex-col gap-gutter">
                    <div className="glass-panel p-6">
                        <h2 className="font-headline-md text-headline-md text-primary mb-6 flex items-center gap-2">
                            <SquarePlus size={22} />
                            INITIALIZE_TASK
                        </h2>
                        {error && (
                            <div className="rounded-none border border-error/20 bg-error-container px-4 py-3 text-error font-code-sm text-code-sm mb-4">
                                {error}
                            </div>
                        )}
                        <ProjectForm onSubmit={handleCreateProject} submitting={saving} />
                    </div>
                    <div className="glass-panel p-6 bg-surface-container-lowest/40">
                        <div className="flex justify-between items-center mb-4">
                            <span className="font-label-bold text-label-bold text-outline">NETWORK_MAP_STATUS</span>
                            <span className="h-2 w-2 rounded-none bg-secondary shadow-[0_0_8px_#5de6ff]"></span>
                        </div>
                        <div className="aspect-video relative rounded-none overflow-hidden border border-outline-variant">
                            <img
                                className="w-full h-full object-cover opacity-60"
                                alt="Tactical digital heatmap overlay"
                                src="https://lh3.googleusercontent.com/aida-public/AB6AXuC-SctO-QRer2J2KW1vELKJLFK73eyhutrd1N7HF7fW8l1cb9rCcCmAnctF3nY1SS8hK5q_3Jf56W8RbvlEobj_Xz5EDLXOYlXB2_T_W0_zWlOUNojO-UPzzwQcJokT7mQDMxy4iH5fxSxbQj6eVeBc1a9S_fANIqYDFeejmZK4eQlLQmvbmiwcl04xfZMlH2YG0ahufSaTzfDMUI5R44xcnnnnf3Y4zcOU68jk7CAN8_x7tEBEGVF96KPWkRsMf-b8c6_5gpdVkg"
                            />
                            <div className="absolute inset-0 bg-gradient-to-t from-background to-transparent"></div>
                            <div className="absolute bottom-2 left-2 font-code-sm text-[10px] text-secondary">
                                LOC: {'{{DATA:LOCATION:DC_VIRGINIA_NORTH}}'}
                            </div>
                        </div>
                    </div>
                </aside>

                <section className="col-span-12 lg:col-span-8">
                    <div className="glass-panel h-full flex flex-col">
                        <div className="p-6 border-b border-outline-variant flex justify-between items-center">
                            <div>
                                <h2 className="font-headline-md text-headline-md text-on-surface">PROJECT_ASSIGNMENT_REGISTRY</h2>
                                <p className="font-code-sm text-code-sm text-outline mt-1">TOTAL_RECORDS: {projects.length} // FILTER: ACTIVE</p>
                            </div>
                            <button
                                type="button"
                                aria-label="Filter projects"
                                className="text-outline hover:text-primary transition-colors"
                            >
                                <ListFilter size={20} />
                            </button>
                        </div>
                        <div className="grid gap-4 p-6">
                            {projects.map((project) => (
                                <ProjectCard key={project.id} project={project} onDelete={handleDelete} />
                            ))}
                            {!loading && projects.length === 0 && (
                                <div className="rounded-none border border-outline-variant/20 bg-surface-container-lowest p-6 text-center text-outline">
                                    No projects found.
                                </div>
                            )}
                        </div>
                    </div>
                </section>
        </div>
    );
}
