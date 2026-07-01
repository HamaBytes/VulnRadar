import { BrowserRouter, Routes, Route } from 'react-router-dom';
import LandingPage from './components/landing/Landing.tsx';
import { AuthPage } from './pages/AuthPage';
import { DashboardPage } from './pages/DashboardPage';
import { ProjectsPage } from './pages/ProjectsPage';
import { ProjectDetailPage } from './pages/ProjectDetailPage';
import { ProtectedRoute } from './components/auth/ProtectedRoute';

function App() {
    return (
        <BrowserRouter>
            <Routes>
                <Route path="/" element={<LandingPage />} />
                <Route path="/auth" element={<AuthPage />} />
                <Route path="/login" element={<AuthPage />} /> {/* Redirect old bookmark */}
                <Route path="/register" element={<AuthPage />} /> {/* Redirect old bookmark */}
                <Route path="/dashboard" element={
                    <ProtectedRoute>
                        <DashboardPage />
                    </ProtectedRoute>
                } />
                <Route path="/projects" element={
                    <ProtectedRoute>
                        <ProjectsPage />
                    </ProtectedRoute>
                } />
                <Route path="/projects/:id" element={
                    <ProtectedRoute>
                        <ProjectDetailPage />
                    </ProtectedRoute>
                } />
            </Routes>
        </BrowserRouter>
    );
}

export default App;