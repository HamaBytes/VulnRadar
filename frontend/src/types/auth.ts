export interface user {
    id: number;
    email: string;
}

export interface AuthResponse {
    token: string;
    user: user;
}

export interface LoginCredentials {
    email: string;
    password: string;
}

export interface RegisterCredentials {
    email: string;
    password: string;
}