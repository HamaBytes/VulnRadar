import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
    Bell,
    Database,
    LayoutDashboard,
    ListChecks,
    LockKeyhole,
    LogOut,
    Settings,
    Terminal,
    UserCircle,
} from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import { ThemeToggle } from './ThemeToggle';

const navClass = ({ isActive }: { isActive: boolean }) =>
    [
        'font-body-md text-body-md transition-all flex items-center gap-2 cursor-pointer px-2 py-1 rounded-none',
        isActive
            ? 'text-primary border-b-2 border-primary pb-1'
            : 'text-on-surface-variant hover:text-primary hover:bg-primary/5',
    ].join(' ');

export function Layout() {
    const navigate = useNavigate();
    const { logout, isAuthenticated } = useAuthStore();

    const handleLogout = () => {
        logout();
        navigate('/login');
    };

    return (
        <div className="min-h-screen bg-background text-on-background font-body-md relative">
            <div className="scanline" />

            <nav className="sticky top-0 w-full z-50 bg-background/80 backdrop-blur-xl border-b border-outline-variant/30 shadow-[inset_0_-1px_0_0_rgba(173,198,255,0.1)]">
                <div className="flex justify-between items-center px-margin-desktop py-4 max-w-max-width mx-auto">
                    <div className="flex items-center gap-8">
                        <button
                            type="button"
                            onClick={() => navigate('/dashboard')}
                            className="text-headline-md font-headline-md font-bold tracking-tighter text-primary cursor-pointer"
                            data-text="VULNRADAR"
                        >
                            VulnRadar
                        </button>
                        <div className="hidden md:flex items-center gap-6">
                            <NavLink to="/dashboard" className={navClass}>
                                <LayoutDashboard size={16} /> Dashboard
                            </NavLink>
                            <NavLink to="/cves" className={navClass}>
                                <ListChecks size={16} /> Registry
                            </NavLink>
                            <NavLink to="/projects" className={navClass}>
                                <Database size={16} /> Assets
                            </NavLink>
                        </div>
                    </div>
                    <div className="flex items-center gap-4">
                        <ThemeToggle />
                        <button
                            type="button"
                            aria-label="Open terminal"
                            className="text-outline cursor-pointer hover:text-primary transition-colors"
                        >
                            <Terminal size={20} />
                        </button>
                        <button
                            type="button"
                            aria-label="Notifications"
                            className="relative text-outline cursor-pointer hover:text-primary transition-colors"
                        >
                            <Bell size={20} />
                            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-error rounded-none border border-background" />
                        </button>
                        <button
                            type="button"
                            aria-label="Settings"
                            className="text-outline cursor-pointer hover:text-primary transition-colors"
                        >
                            <Settings size={20} />
                        </button>
                        <div className="w-8 h-8 rounded-none border border-outline/30 overflow-hidden bg-surface-container-lowest flex items-center justify-center text-outline">
                            <UserCircle size={22} />
                        </div>
                        {isAuthenticated && (
                            <button
                                type="button"
                                onClick={handleLogout}
                                aria-label="Disconnect"
                                className="text-error font-code-sm text-[10px] uppercase border border-error/50 px-2 py-1 bg-error/10 cursor-pointer hover:bg-error/20 transition-colors inline-flex items-center gap-2"
                            >
                                <LogOut size={14} /> DISCONNECT
                            </button>
                        )}
                    </div>
                </div>
            </nav>

            <main className="pt-12 pb-12 px-margin-desktop max-w-max-width mx-auto relative z-10">
                <Outlet />
            </main>

            <footer className="mt-12 pt-8 border-t-2 border-outline-variant border-dashed">
                <div className="w-full py-3 flex flex-row justify-between items-center bg-black border-y border-outline-variant/30 px-4 max-w-max-width mx-auto">
                    <div className="text-[10px] font-label-bold text-outline uppercase tracking-widest glitch-text" data-text="VULNRADAR_CMD">
                        VULNRADAR_CMD
                    </div>
                    <div className="hidden md:flex gap-8">
                        <span className="font-code-sm text-[9px] uppercase tracking-widest text-outline-variant flex items-center gap-1">
                            <LockKeyhole size={12} /> AES-256-GCM
                        </span>
                        <span className="font-code-sm text-[9px] uppercase tracking-widest text-outline-variant flex items-center gap-1">
                            <span className="w-1 h-1 bg-terminal-green rounded-none"></span> SYS_OK
                        </span>
                    </div>
                    <div className="text-code-sm text-[9px] uppercase tracking-widest text-terminal-dim">© 2024 SYSTEM</div>
                </div>
            </footer>
        </div>
    );
}
