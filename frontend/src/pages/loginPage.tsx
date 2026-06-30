// src/pages/LoginPage.tsx
import { LoginForm } from '../components/auth/LoginForm';

export function LoginPage() {
    return (
        <div className="min-h-screen bg-background text-on-background flex items-center justify-center p-gutter relative overflow-hidden">
            {/* Grid Background */}
            <div
                className="fixed inset-0 pointer-events-none z-0 opacity-40"
                style={{
                    backgroundSize: '32px 32px',
                    backgroundImage: 'linear-gradient(to right, rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.03) 1px, transparent 1px)'
                }}
            />

            {/* Corner decorations */}
            <div className="fixed top-margin-desktop left-margin-desktop text-outline-variant space-y-1 hidden lg:block">
                <p className="font-code-sm text-code-sm">COORD_X: 42.109</p>
                <p className="font-code-sm text-code-sm">COORD_Y: 71.332</p>
                <p className="font-code-sm text-code-sm">LATENCY: 12ms</p>
            </div>

            <div className="fixed bottom-margin-desktop right-margin-desktop text-outline-variant text-right space-y-1 hidden lg:block">
                <p className="font-code-sm text-code-sm">SYS_UPTIME: 99.98%</p>
                <p className="font-code-sm text-code-sm">VULN_SCAN: ACTIVE</p>
                <p className="font-code-sm text-code-sm text-primary">AUTHORIZED PERSONNEL ONLY</p>
            </div>

            {/* Login Form */}
            <div className="relative z-10">
                <LoginForm onToggle={function(): void {
                    throw new Error("Function not implemented.");
                } } />
            </div>
        </div>
    );
}