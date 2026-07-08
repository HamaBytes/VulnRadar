import { z } from 'zod';

export const LoginPageSchema = z.object({
    email: z
        .string()
        .min(1, 'Email is required')
        .email('Please enter a valid email address'),
    password: z
        .string()
        .min(1, 'Password is required')
        .min(8, 'Password must be at least 8 characters long'),
});

export type LoginInput = z.infer<typeof LoginPageSchema>;

export const RegisterSchema = z.object({
    email: z
        .string()
        .min(1, 'Email is required')
        .email('Please enter a valid email address'),
    password: z
        .string()
        .min(1, 'Password is required')
        .min(8, 'Password must be at least 8 characters long'),
    confirmPassword: z
        .string()
        .min(1, 'Confirm password is required'),
}).refine((data) => data.password === data.confirmPassword, {
    message: 'Security ciphers do not match',
    path: ['confirmPassword'],
});

export type RegisterInput = z.infer<typeof RegisterSchema>;
