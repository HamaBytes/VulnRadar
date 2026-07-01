import { useState, type FormEvent } from 'react';
import type { CreateProjectPayload } from '../../types/projects.types.ts';

interface ProjectFormProps {
    initialName?: string;
    initialDescription?: string;
    onSubmit: (data: CreateProjectPayload) => void;
    submitting: boolean;
}

export function ProjectForm({ initialName = '', initialDescription = '', onSubmit, submitting }: ProjectFormProps) {
    const [name, setName] = useState(initialName);
    const [description, setDescription] = useState(initialDescription);

    const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        onSubmit({ name: name.trim(), description: description.trim() || null });
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-6">
            <div>
                <label htmlFor="projectName" className="block font-label-bold text-label-bold text-outline mb-2">
                    ASSIGNMENT_NAME
                </label>
                <input
                    id="projectName"
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                    className="tactical-input w-full p-2 font-code-sm text-code-sm text-on-surface"
                    placeholder="PROJECT_ALPHA_V4"
                    type="text"
                />
            </div>
            <div>
                <label htmlFor="projectDescription" className="block font-label-bold text-label-bold text-outline mb-2">
                    OPERATIONAL_SCOPE
                </label>
                <textarea
                    id="projectDescription"
                    value={description}
                    onChange={(event) => setDescription(event.target.value)}
                    className="tactical-input w-full p-2 font-code-sm text-code-sm text-on-surface resize-none"
                    placeholder="DEFINE_TARGET_SURFACE_AND_VECTOR_PARAMETERS..."
                    rows={4}
                />
            </div>
            <button
                type="submit"
                disabled={submitting}
                className="w-full bg-primary/10 border border-primary text-primary font-label-bold text-label-bold py-4 hover:bg-primary/20 transition-all duration-300 shadow-[0_0_15px_rgba(173,198,255,0.2)] active:scale-95"
            >
                {submitting ? 'SAVING...' : 'COMMIT_TO_DATABASE'}
            </button>
        </form>
    );
}
