import client from './client.ts'
import type {AuthResponse, LoginCredentials, RegisterCredentials} from '../types/auth.ts';
export const register = async (data: RegisterCredentials): Promise<AuthResponse> => {
    const res = await client.post('/api/v1/auth/register', data);
    return res.data;
};

export const login = async (data: LoginCredentials): Promise<AuthResponse> => {
    const res = await client.post('/api/v1/auth/login', data);
    return res.data;
};

export const me = async () => {
    const res = await client.get('/api/v1/auth/me');
    return res.data.user;
};
