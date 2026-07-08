import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useNavigate } from 'react-router-dom';
import { register as registerApi } from '../../api/auth';
import { useAuthStore } from '../../stores/authStore';
import { Lock, Mail, Terminal, Shield, KeyRound } from 'lucide-react';
import { motion } from 'framer-motion';
import { RegisterSchema, type RegisterInput } from './authSchemas';

interface RegisterFormProps {
    onToggle: () => void;
}

export function RegisterForm({ onToggle }: RegisterFormProps ) {
    const navigate = useNavigate();
    const authLogin = useAuthStore((state) => state.login);
    const [serverError, setServerError] = useState<string | null>(null);

    const {
        register,
        handleSubmit,
        formState: { errors, isSubmitting }
    } = useForm<RegisterInput>({
        resolver: zodResolver(RegisterSchema),
    });

    const onSubmit = async (data: RegisterInput) => {
        setServerError(null);
        try {
            const { confirmPassword: _confirmPassword, ...apiData } = data;
            const response = await registerApi(apiData);
            authLogin(response.token, response.user);
            navigate('/dashboard');
        } catch (err: any) {
            setServerError(err.response?.data?.error || 'Registration failed. Please try again.');
        }
    };

    return (
        <div className="w-full max-w-md bg-surface-container-lowest/60 backdrop-blur-xl border border-outline-variant/30 relative overflow-hidden group">
            <div className="absolute inset-0 border border-primary/10 pointer-events-none"></div>
            <div className="h-1 bg-secondary w-full shadow-[0_0_10px_rgba(93,230,255,0.6)]"></div>

            <div className="p-8 md:p-10 space-y-8">
                {/* Branding */}
                <div className="space-y-2">
                    <div className="flex items-center gap-2 mb-4">
                        <Terminal size={24} className="text-secondary" />
                        <span className="font-headline-md text-headline-md tracking-tighter text-secondary drop-shadow-[0_0_8px_rgba(93,230,255,0.4)]">
                            VULNRADAR
                        </span>
                    </div>
                    <h1 className="font-headline-lg text-headline-lg text-on-surface leading-none tracking-tight">
                        INITIALIZE OPERATOR CREDENTIALS
                    </h1>
                    <p className="font-code-sm text-code-sm text-outline uppercase tracking-widest">
                        GENERATING SECURE ACCESS PORTAL...
                    </p>
                </div>

                {/* Server Error */}
                {serverError && (
                    <div className="bg-error-container border border-error text-error px-4 py-3 font-code-sm text-code-sm">
                        {serverError}
                    </div>
                )}

                {/* Form */}
                <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
                    {/* Email Field */}
                    <div className="space-y-2 group/input">
                        <label className="flex justify-between items-center px-1" htmlFor="email">
                            <span className="font-label-bold text-label-bold text-outline group-focus-within/input:text-secondary transition-colors uppercase">
                                Operator ID
                            </span>
                            <span className="font-code-sm text-code-sm text-outline-variant group-focus-within/input:text-secondary/50 transition-colors">
                                REQ_EMAIL_TOKEN
                            </span>
                        </label>
                        <div className="relative">
                            <input
                                {...register('email')}
                                id="email"
                                type="email"
                                autoComplete="off"
                                placeholder="NAME@VULNRADAR.INT"
                                className="w-full bg-surface-container-low border border-outline-variant focus:border-secondary focus:ring-0 text-on-surface font-body-md py-4 px-4 pr-12 transition-all placeholder:text-outline-variant/50"
                            />
                            <div className="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-focus-within/input:opacity-100 transition-opacity">
                                <Mail size={20} className="text-secondary" />
                            </div>
                        </div>
                        {errors.email && (
                            <p className="font-code-sm text-code-sm text-error">{errors.email.message}</p>
                        )}
                    </div>

                    {/* Password Field */}
                    <div className="space-y-2 group/input">
                        <label className="flex justify-between items-center px-1" htmlFor="password">
                            <span className="font-label-bold text-label-bold text-outline group-focus-within/input:text-secondary transition-colors uppercase">
                                Security Cipher
                            </span>
                            <span className="font-code-sm text-code-sm text-outline-variant group-focus-within/input:text-secondary/50 transition-colors">
                                AES_CIPHER_X64
                            </span>
                        </label>
                        <div className="relative">
                            <input
                                {...register('password')}
                                id="password"
                                type="password"
                                placeholder="••••••••••••"
                                className="w-full bg-surface-container-low border border-outline-variant focus:border-secondary focus:ring-0 text-on-surface font-body-md py-4 px-4 pr-12 transition-all placeholder:text-outline-variant/50"
                            />
                            <div className="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-focus-within/input:opacity-100 transition-opacity">
                                <Lock size={20} className="text-secondary" />
                            </div>
                        </div>
                        {errors.password && (
                            <p className="font-code-sm text-code-sm text-error">{errors.password.message}</p>
                        )}
                    </div>

                    {/* Confirm Password Field */}
                    <div className="space-y-2 group/input">
                        <label className="flex justify-between items-center px-1" htmlFor="confirmPassword">
                            <span className="font-label-bold text-label-bold text-outline group-focus-within/input:text-secondary transition-colors uppercase">
                                Confirm Cipher
                            </span>
                            <span className="font-code-sm text-code-sm text-outline-variant group-focus-within/input:text-secondary/50 transition-colors">
                                AES_VERIFY_X64
                            </span>
                        </label>
                        <div className="relative">
                            <input
                                {...register('confirmPassword')}
                                id="confirmPassword"
                                type="password"
                                placeholder="••••••••••••"
                                className="w-full bg-surface-container-low border border-outline-variant focus:border-secondary focus:ring-0 text-on-surface font-body-md py-4 px-4 pr-12 transition-all placeholder:text-outline-variant/50"
                            />
                            <div className="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-focus-within/input:opacity-100 transition-opacity">
                                <KeyRound size={20} className="text-secondary" />
                            </div>
                        </div>
                        {errors.confirmPassword && (
                            <p className="font-code-sm text-code-sm text-error">{errors.confirmPassword.message}</p>
                        )}
                    </div>

                    {/* Actions */}
                    <div className="pt-2 flex flex-col gap-4">
                        <button
                            type="submit"
                            disabled={isSubmitting}
                            className="w-full bg-secondary py-4 text-on-secondary font-label-bold text-label-bold tracking-[0.2em] uppercase glow-hover transition-all duration-300 active:scale-95 flex items-center justify-center gap-2 group/btn disabled:opacity-50"
                        >
                            {isSubmitting ? 'GENERATING CREDENTIALS...' : 'CREATE OPERATOR ACCOUNT'}
                            <Shield size={18} className="group-hover/btn:translate-x-1 transition-transform" />
                        </button>

                        {/* Link to Login */}
                        <div className="text-center pt-2">
                            <span className="text-outline font-code-sm text-code-sm">Already have access? </span>
                            <motion.button
                                type="button"
                                onClick={onToggle}
                                className="font-code-sm text-code-sm text-primary transition-colors"
                                whileHover={{ scale: 1.05 }}
                            >
                                Authenticate Existing Credentials
                            </motion.button>
                        </div>
                    </div>
                </form>

                {/* Technical Metadata */}
                <div className="pt-6 border-t border-outline-variant/20 flex flex-wrap gap-x-6 gap-y-2">
                    <div className="flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-none bg-primary animate-pulse"></span>
                        <span className="font-code-sm text-code-sm text-outline">NODE: VR-DELTA-9</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="font-code-sm text-code-sm text-outline">ENCRYPTION: AES-256</span>
                    </div>
                    <div className="flex items-center gap-2 ml-auto">
                        <span className="font-code-sm text-code-sm text-secondary uppercase">Status: Secure</span>
                    </div>
                </div>
            </div>
        </div>
    );
}
