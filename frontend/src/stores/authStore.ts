import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type {user} from '../types/auth.types.ts';
interface AuthState {
    token: string | null;
    user: user | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    setLoading: (isLoading: boolean) => void;
    login: (token: string, user: user) => void;
    logout: () => void;
}

export const useAuthStore = create<AuthState>()(
    persist(
        (set) => ({
            token: null,
            user: null,
            isAuthenticated: false,
            isLoading: true,
            setLoading: (isLoading) => set({ isLoading }),
            login: (token, user) => set({ token, user, isAuthenticated: true, isLoading: false }),
            logout: () => set({ token: null, user: null, isAuthenticated: false, isLoading: false }),
        }),
        {
            name: 'vulnradar-auth',
            partialize: (state) => ({
                token: state.token,
                user: state.user,
                isAuthenticated: state.isAuthenticated,
            }),
            onRehydrateStorage: () => (state) => {
                state?.setLoading(false);
            },
        }
    )
);
