import { BrowserRouter, Routes, Route } from 'react-router-dom';
import LandingPage from './components/landing/Landing.tsx';
import { AuthPage } from './pages/AuthPage';
import { DashboardPage } from './pages/DashboardPage';
import { ProjectsPage } from './pages/ProjectsPage';
import { ProjectDetailPage } from './pages/ProjectDetailPage';
import { CveListPage } from './pages/CveListPage';
import { CveDetailPage } from './pages/CveDetailPage';

import { ProtectedRoute } from './components/auth/ProtectedRoute';
import { Layout } from './components/layout/Layout.tsx';
function App() {
    return (
        <BrowserRouter>
            <Routes>
                {/* Public routes — NO layout (Landing has its own nav) */}
                <Route path="/" element={<LandingPage />} />
                <Route path="/auth" element={<AuthPage />} />
                <Route path="/login" element={<AuthPage />} />
                <Route path="/register" element={<AuthPage />} />

                {/* Protected routes — WITH shared layout */}
                <Route element={
                    <ProtectedRoute>
                        <Layout />
                    </ProtectedRoute>
                }>
                    <Route path="/dashboard" element={<DashboardPage />} />
                    <Route path="/projects" element={<ProjectsPage />} />
                    <Route path="/projects/:id" element={<ProjectDetailPage />} />
                    <Route path="/cves" element={<CveListPage />} />
                    <Route path="/cves/:cve_id" element={<CveDetailPage />} />
                </Route>
            </Routes>
        </BrowserRouter>
    );
}

export default App;
