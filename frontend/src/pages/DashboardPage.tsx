import { useNavigate } from 'react-router-dom';
import {
    Shield,
    AlertTriangle,
    Activity,
    Database,
    Terminal,
    ChevronRight,
    RadioTower
} from 'lucide-react';
import { getHealth, runPipelineSync } from '../api/system';

export function DashboardPage() {
    const navigate = useNavigate();
    const now = new Date();
    const timestamp = now.toISOString().replace('T', ' ').slice(0, 19) + 'Z';

    return (
        <div className="w-full relative">
            {/* Ambient scan sweep across the whole workspace */}
            <div className="pointer-events-none fixed inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-terminal-green/60 to-transparent animate-scan-sweep z-50" />

            <div className="max-w-[1440px] mx-auto">
                {/* Status Strip */}
                <div className="flex items-center justify-between mb-6 px-1 font-code-sm text-code-sm text-outline">
                    <div className="flex items-center gap-2">
                        <span className="relative flex h-2 w-2">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-terminal-green opacity-75" />
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-terminal-green" />
                        </span>
                        <span className="uppercase tracking-[0.2em] text-terminal-green">System Nominal</span>
                    </div>
                    <span className="tracking-wider">{timestamp}</span>
                </div>

                {/* Welcome Header */}
                <div className="mb-10 relative border-l-4 border-primary pl-6 py-1">
                    <div className="absolute -left-[2px] top-0 h-3 w-3 border-t-2 border-l-2 border-primary" />
                    <div className="absolute -left-[2px] bottom-0 h-3 w-3 border-b-2 border-l-2 border-primary" />
                    <span className="font-label-bold text-label-bold text-primary uppercase tracking-[0.3em]">
                        Tactical Overview
                    </span>
                    <h1 className="font-headline-lg text-headline-lg text-on-surface uppercase mt-2">
                        Welcome back, Operator
                    </h1>
                    <p className="font-body-md text-body-md text-on-surface-variant mt-2 max-w-xl">
                        Vulnerability intelligence synced and standing by. Review current exposure, then route to the registry for a full breakdown.
                    </p>
                </div>

                {/* Stat Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-10">
                    <StatCard
                        icon={Database}
                        label="Total CVEs"
                        value="0"
                        color="primary"
                        caption="Tracked across all feeds"
                    />
                    <StatCard
                        icon={AlertTriangle}
                        label="Active KEVs"
                        value="0"
                        color="secondary"
                        caption="Confirmed exploited in the wild"
                    />
                    <StatCard
                        icon={Activity}
                        label="Avg EPSS"
                        value="0.00"
                        color="primary"
                        caption="Mean exploit prediction score"
                    />
                </div>

                {/* Registry CTA */}
                <button
                    type="button"
                    onClick={() => navigate('/cves')}
                    className="w-full mb-10 group relative flex items-center justify-between py-4 px-6 border border-cyan-400 text-cyan-400 font-label-bold uppercase tracking-[0.15em] overflow-hidden transition-all duration-300 hover:border-cyan-300 hover:shadow-[0_0_20px_rgba(34,211,238,0.35)]"
                >
                    <span className="absolute inset-0 -translate-x-full bg-cyan-400/15 transition-transform duration-300 ease-out group-hover:translate-x-0" />
                    <span className="relative flex items-center gap-3">
                        <Terminal size={18} />
                        Open CVE Registry
                    </span>
                    <ChevronRight size={18} className="relative transition-transform duration-300 group-hover:translate-x-1" />
                </button>

                {/* Quick Actions */}
                <div className="glass-panel p-8 mb-10 relative">
                    <CornerBrackets />
                    <div className="flex items-center justify-between mb-6">
                        <h2 className="font-headline-md text-headline-md text-on-surface uppercase">
                            Operational Tools
                        </h2>
                        <span className="font-code-sm text-code-sm text-outline uppercase tracking-widest hidden sm:inline">
                            3 available
                        </span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <ActionButton
                            icon={Terminal}
                            label="Run Pipeline"
                            description="Trigger the sync pipeline"
                            onClick={() => {
                                void runPipelineSync();
                            }}
                        />
                        <ActionButton
                            icon={Database}
                            label="Health Check"
                            description="Check API and database status"
                            onClick={() => {
                                void getHealth();
                            }}
                        />
                        <ActionButton
                            icon={Activity}
                            label="Projects"
                            description="Create and manage vulnerability projects"
                            onClick={() => navigate('/projects')}
                        />
                    </div>
                </div>

                {/* Readiness Panel */}
                <div className="glass-panel p-12 text-center relative overflow-hidden">
                    <CornerBrackets />
                    <div className="pointer-events-none absolute inset-x-0 top-0 h-24 bg-gradient-to-b from-primary/5 to-transparent" />
                    <Shield size={48} className="mx-auto mb-4 text-primary/50" />
                    <h3 className="font-headline-md text-headline-md text-on-surface uppercase mb-2">
                        Intelligence Workspace Ready
                    </h3>
                    <p className="text-on-surface-variant font-body-md text-body-md mb-6 max-w-md mx-auto">
                        The dashboard is prepared for vulnerability intelligence workflows and background synchronization.
                    </p>
                    <div className="flex items-center justify-center gap-2 font-code-sm text-code-sm text-outline uppercase tracking-widest">
                        <RadioTower size={14} className="text-terminal-green" />
                        Listening for feed updates
                    </div>
                </div>
            </div>

            <style>{`
                @keyframes scan-sweep {
                    0% { transform: translateX(-100%); }
                    100% { transform: translateX(100%); }
                }
                .animate-scan-sweep {
                    animation: scan-sweep 4s linear infinite;
                }
            `}</style>
        </div>
    );
}

// ─── Sub-components ───────────────────────────────────────────────

function CornerBrackets() {
    return (
        <>
            <span className="absolute top-0 left-0 h-3 w-3 border-t-2 border-l-2 border-primary/40" />
            <span className="absolute top-0 right-0 h-3 w-3 border-t-2 border-r-2 border-primary/40" />
            <span className="absolute bottom-0 left-0 h-3 w-3 border-b-2 border-l-2 border-primary/40" />
            <span className="absolute bottom-0 right-0 h-3 w-3 border-b-2 border-r-2 border-primary/40" />
        </>
    );
}

function StatCard({
                      icon: Icon,
                      label,
                      value,
                      color,
                      caption
                  }: {
    icon: React.ElementType;
    label: string;
    value: string;
    color: 'primary' | 'secondary';
    caption: string;
}) {
    const colorClass = color === 'primary' ? 'text-primary' : 'text-secondary';
    const borderHover = color === 'primary' ? 'hover:border-primary/50' : 'hover:border-secondary/50';

    return (
        <div className={`glass-panel p-6 border-t-2 border-outline-variant/30 ${borderHover} transition-all relative group`}>
            <div className="flex items-center justify-between mb-4">
                <Icon size={24} className={colorClass} />
                <span className="flex items-center gap-1.5 font-label-bold text-[10px] text-outline uppercase tracking-wider">
                    <span className={`h-1.5 w-1.5 rounded-full ${color === 'primary' ? 'bg-terminal-green' : 'bg-secondary'}`} />
                    Live
                </span>
            </div>
            <p className={`font-display-xl text-display-xl ${colorClass} mb-1 tabular-nums`}>{value}</p>
            <p className="font-label-bold text-label-bold text-on-surface uppercase mb-1">{label}</p>
            <p className="font-code-sm text-code-sm text-outline">{caption}</p>
        </div>
    );
}

function ActionButton({
                          icon: Icon,
                          label,
                          description,
                          onClick
                      }: {
    icon: React.ElementType;
    label: string;
    description: string;
    onClick: () => void;
}) {
    return (
        <button
            onClick={onClick}
            className="glass-panel p-6 text-left hover:border-primary/50 transition-all group relative"
        >
            <div className="flex items-start justify-between mb-4">
                <Icon size={28} className="text-primary group-hover:text-secondary transition-colors" />
                <ChevronRight size={16} className="text-outline opacity-0 group-hover:opacity-100 -translate-x-1 group-hover:translate-x-0 transition-all" />
            </div>
            <h4 className="font-label-bold text-label-bold text-on-surface uppercase mb-2">{label}</h4>
            <p className="font-code-sm text-code-sm text-outline">{description}</p>
        </button>
    );
}