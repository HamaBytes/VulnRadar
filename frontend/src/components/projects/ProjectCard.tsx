import type { Project } from '../../types/projects.types.ts';
import { useNavigate } from 'react-router-dom';

interface ProjectCardProps {
    project: Project;
    onDelete: (projectId: number) => void;
}

export function ProjectCard({ project, onDelete }: ProjectCardProps) {
    const navigate = useNavigate();

    return (
        <div className="glass-panel p-6 border border-outline-variant hover:border-primary/50 transition-all">
            <div className="flex items-start justify-between gap-4">
                <div>
                    <h3 className="font-headline-sm text-headline-sm text-on-surface">{project.name}</h3>
                    <p className="font-code-sm text-code-sm text-on-surface-variant mt-2">{project.description || 'No description available.'}</p>
                </div>
                <button
                    onClick={() => onDelete(project.id)}
                    className="text-error font-label-bold text-label-bold uppercase tracking-[0.2em] hover:text-error/80 transition-colors"
                >
                    Delete
                </button>
            </div>
            <div className="mt-6 flex flex-wrap gap-3 text-sm text-outline">
                <span>Items: {project.item_count}</span>
                <span>Created: {new Date(project.created_at).toLocaleDateString()}</span>
            </div>
            <div className="mt-6 flex items-center gap-3">
                <button
                    onClick={() => navigate(`/projects/${project.id}`)}
                    className="rounded-full bg-primary/10 px-4 py-2 text-primary font-label-bold text-label-bold hover:bg-primary/20 transition-all"
                >
                    View details
                </button>
            </div>
        </div>
    );
}
