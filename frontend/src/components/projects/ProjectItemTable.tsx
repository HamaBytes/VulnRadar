import type { ProjectItem } from '../../types/projects.types.ts';

interface ProjectItemTableProps {
    items: ProjectItem[];
    onEdit: (item: ProjectItem) => void;
    onDelete: (item: ProjectItem) => void;
}

export function ProjectItemTable({ items, onEdit, onDelete }: ProjectItemTableProps) {
    return (
        <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full text-left border-collapse">
                <thead>
                    <tr className="border-b border-outline-variant/30 font-label-bold text-label-bold text-outline">
                        <th className="px-4 py-3">CVE</th>
                        <th className="px-4 py-3">Asset</th>
                        <th className="px-4 py-3">Status</th>
                        <th className="px-4 py-3">Risk</th>
                        <th className="px-4 py-3">Actions</th>
                    </tr>
                </thead>
                <tbody className="font-code-sm text-code-sm">
                    {items.map((item) => (
                        <tr key={item.id} className="border-b border-outline-variant/10 hover:bg-primary/5 transition-colors">
                            <td className="px-4 py-4">{item.cve_id}</td>
                            <td className="px-4 py-4">{item.asset_name}</td>
                            <td className="px-4 py-4">{item.status}</td>
                            <td className="px-4 py-4">{item.criticality || 'N/A'}</td>
                            <td className="px-4 py-4 flex gap-2">
                                <button
                                    type="button"
                                    onClick={() => onEdit(item)}
                                    className="rounded-md border border-outline-variant px-3 py-2 font-label-bold text-label-bold text-on-surface hover:border-primary/50 transition-all"
                                >
                                    Edit
                                </button>
                                <button
                                    type="button"
                                    onClick={() => onDelete(item)}
                                    className="rounded-md border border-error/20 bg-error/10 px-3 py-2 font-label-bold text-label-bold text-error hover:bg-error/20 transition-all"
                                >
                                    Delete
                                </button>
                            </td>
                        </tr>
                    ))}
                    {items.length === 0 && (
                        <tr>
                            <td className="px-4 py-6 text-center text-outline" colSpan={5}>
                                No tracked CVEs in this project.
                            </td>
                        </tr>
                    )}
                </tbody>
            </table>
        </div>
    );
}
