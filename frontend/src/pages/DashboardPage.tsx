import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';
import {
    Shield,
    AlertTriangle,
    Activity,
    Database,
    LogOut,
    Terminal,
    Radar
} from 'lucide-react';
import { ThemeToggle } from '../components/layout/ThemeToggle';
export function DashboardPage() {
    const navigate = useNavigate();
    const { user, logout } = useAuthStore();

    const handleLogout = () => {
        logout();
        navigate('/login');
    };

    // Prevent access without auth (double-check)
    useEffect(() => {
        if (!useAuthStore.getState().isAuthenticated) {
            navigate('/login');
        }
    }, [navigate]);

    return (
        <div className="min-h-screen bg-background text-on-background font-body-md">
            {/* Top Navigation */}
            <nav className="fixed top-0 w-full z-50 bg-background/80 backdrop-blur-xl border-b border-outline-variant/30">
                <div className="flex justify-between items-center max-w-[1440px] mx-auto px-8 h-16">
                    <div className="flex items-center gap-4">
                        <Radar size={24} className="text-primary" />
                        <span className="font-headline-md text-headline-md font-bold tracking-tighter text-primary">
              VulnRadar
            </span>
                        <span className="px-2 py-0.5 border border-secondary text-secondary font-label-bold text-[10px] tracking-widest uppercase">
              Command Center
            </span>
                    </div>

                    <div className="flex items-center gap-6">
                        <ThemeToggle />
                        <span className="font-code-sm text-code-sm text-outline">
              {user?.email}
            </span>
                        <button
                            onClick={handleLogout}
                            className="flex items-center gap-2 px-4 py-2 border border-error/50 text-error font-label-bold text-label-bold uppercase hover:bg-error/10 transition-all"
                        >
                            <LogOut size={16} />
                            Terminate Session
                        </button>
                    </div>
                </div>
            </nav>

            {/* Main Content */}
            <main className="pt-24 pb-12 px-8">
                <div className="max-w-[1440px] mx-auto">
                    {/* Welcome Header */}
                    <div className="mb-12 border-l-4 border-primary pl-6">
            <span className="font-label-bold text-label-bold text-primary uppercase tracking-[0.3em]">
              Tactical Overview
            </span>
                        <h1 className="font-headline-lg text-headline-lg text-on-surface uppercase mt-2">
                            Welcome back, Operator
                        </h1>
                    </div>

                    {/* Stats Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-12">
                        <StatCard
                            icon={Database}
                            label="Total CVEs"
                            value="0"
                            color="primary"
                        />
                        <StatCard
                            icon={AlertTriangle}
                            label="Active KEVs"
                            value="0"
                            color="secondary"
                        />
                        <StatCard
                            icon={Activity}
                            label="Avg EPSS"
                            value="0.00"
                            color="primary"
                        />
                    </div>

                    {/* Quick Actions */}
                    <div className="glass-panel p-8 mb-12">
                        <h2 className="font-headline-md text-headline-md text-on-surface uppercase mb-6">
                            Operational Tools
                        </h2>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <ActionButton
                                icon={Terminal}
                                label="Run Pipeline"
                                description="Trigger the sync pipeline"
                                onClick={() => fetch('/api/v1/pipeline/sync', { credentials: 'same-origin' })}
                            />
                            <ActionButton
                                icon={Database}
                                label="Health Check"
                                description="Check API and database status"
                                onClick={() => fetch('/api/v1/health', { credentials: 'same-origin' })}
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
                    <div className="glass-panel p-12 text-center">
                        <Shield size={48} className="mx-auto mb-4 text-primary/50" />
                        <h3 className="font-headline-md text-headline-md text-on-surface uppercase mb-2">
                            Intelligence Workspace Ready
                        </h3>
                        <p className="text-on-surface-variant font-body-md text-body-md mb-6">
                            The dashboard is prepared for vulnerability intelligence workflows and background synchronization.
                        </p>
                    </div>
                </div>
            </main>
        </div>
    );
}

// ─── Sub-components ───────────────────────────────────────────────

function StatCard({
                      icon: Icon,
                      label,
                      value,
                      color
                  }: {
    icon: React.ElementType;
    label: string;
    value: string;
    color: 'primary' | 'secondary';
}) {
    const colorClass = color === 'primary' ? 'text-primary' : 'text-secondary';

    return (
        <div className="glass-panel p-6 border-t-2 border-outline-variant/30 hover:border-primary/50 transition-all">
            <div className="flex items-center justify-between mb-4">
                <Icon size={24} className={colorClass} />
                <span className="font-label-bold text-[10px] text-outline uppercase tracking-wider">
          LIVE
        </span>
            </div>
            <p className={`font-display-xl text-display-xl ${colorClass} mb-1`}>{value}</p>
            <p className="font-label-bold text-label-bold text-outline uppercase">{label}</p>
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
            className="glass-panel p-6 text-left hover:border-primary/50 transition-all group"
        >
            <Icon size={28} className="text-primary mb-4 group-hover:text-secondary transition-colors" />
            <h4 className="font-label-bold text-label-bold text-on-surface uppercase mb-2">{label}</h4>
            <p className="font-code-sm text-code-sm text-outline">{description}</p>
        </button>
    );
}