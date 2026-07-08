import axios from 'axios';
import { useAuthStore } from '../stores/authStore';
const client = axios.create({
    baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
    headers: { 'Content-Type': 'application/json' },
});
client.interceptors.request.use((config) => {
    const store = useAuthStore.getState();
    console.log("AUTH STORE IN AXIOS:", store);
    const token = store.token;
    console.log("Auth token:", token);
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }

    console.log("Headers:", config.headers);

    return config;
});
client.interceptors.response.use(
    (res) => res,
    (err) => {
        if (err.response?.status === 401) {
            useAuthStore.getState().logout();
            window.location.href = '/login';
        }
        return Promise.reject(err);
    }
);

export default client;
