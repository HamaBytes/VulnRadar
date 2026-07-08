import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../../contexts/theme';
export function ThemeToggle() {
    const { theme, toggleTheme } = useTheme();

    return (
        <button
            onClick={toggleTheme}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            className="relative w-10 h-10 flex items-center justify-center border border-outline-variant/40 text-on-surface-variant hover:text-primary hover:border-primary/50 transition-all"
        >
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
        </button>
    );
}
