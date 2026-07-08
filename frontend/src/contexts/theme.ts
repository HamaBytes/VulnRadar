import { createContext, useContext } from 'react';

export type Theme = 'dark' | 'light';

export interface ThemeContextValue {
    theme: Theme;
    toggleTheme: () => void;
}

export const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

export function useTheme() {
    const ctx = useContext(ThemeContext);
    if (!ctx) throw new Error('useTheme must be used within ThemeProvider');
    return ctx;
}
