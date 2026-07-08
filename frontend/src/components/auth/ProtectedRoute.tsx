// src/components/auth/ProtectedRoute.tsx
import { Navigate } from 'react-router-dom';
import { useAuthStore } from '../../stores/authStore';

interface ProtectedRouteProps {
    children: React.ReactNode;  // The page component to render
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
    const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
    const isLoading = useAuthStore((state) => state.isLoading);

    if (isLoading) {
        return <div className="text-terminal-green">Initializing...</div>;
    }

    // Not logged in → kick to login
    if (!isAuthenticated) {
        return <Navigate to="/auth" replace />;
    }

    // Logged in → show the page
    return <>{children}</>;
}
