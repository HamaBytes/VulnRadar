import { useEffect, useState, type ReactNode } from 'react';
import { ThemeContext, type Theme } from './theme';

export function ThemeProvider({ children }: { children: ReactNode }) {
    const [theme, setTheme] = useState<Theme>(() => {
        const stored = localStorage.getItem('vulnradar-theme');
        if (stored === 'dark' || stored === 'light') return stored;
        return 'dark';
    });

    useEffect(() => {
        const root = document.documentElement;
        root.classList.remove('dark', 'light');
        root.classList.add(theme);
        localStorage.setItem('vulnradar-theme', theme);
    }, [theme]);

    const toggleTheme = () => setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));

    return (
        <ThemeContext.Provider value={{ theme, toggleTheme }}>
            {children}
        </ThemeContext.Provider>
    );
}
