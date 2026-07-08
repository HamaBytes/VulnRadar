import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useNavigate } from 'react-router-dom';
import { login } from '../../api/auth';
import { useAuthStore } from '../../stores/authStore';
import { motion } from 'framer-motion';
import { Lock, Mail, Terminal } from 'lucide-react';
import { LoginPageSchema, type LoginInput } from './authSchemas';

interface LoginFormProps {
    onToggle: () => void;
}

export function LoginForm({ onToggle }: LoginFormProps) {    const navigate = useNavigate();
    const authLogin = useAuthStore((state) => state.login);
    const [serverError, setServerError] = useState<string | null>(null);

    const {
        register,
        handleSubmit,
        formState: { errors, isSubmitting }
    } = useForm<LoginInput>({
        resolver: zodResolver(LoginPageSchema),
    });

    const onSubmit = async (data: LoginInput) => {
        setServerError(null);

        try {
            const response = await login(data);

            console.log("LOGIN RESPONSE:", response);
            console.log("TOKEN:", response.token);
            console.log("USER:", response.user);

            authLogin(response.token, response.user);

            console.log("STORE AFTER LOGIN:", useAuthStore.getState());

            navigate('/dashboard');
        } catch (err: any) {
            setServerError(err.response?.data?.error || 'Login failed. Please try again.');
        }
    };
    return (
        <div className="w-full max-w-md bg-surface-container-lowest/60 backdrop-blur-xl border border-outline-variant/30 relative overflow-hidden group">
            <div className="absolute inset-0 border border-primary/10 pointer-events-none"></div>
            <div className="scanline"></div>
            <div className="h-1 bg-primary w-full shadow-[0_0_10px_rgba(173,198,255,0.6)]"></div>

            <div className="p-8 md:p-10 space-y-8">
                {/* Branding */}
                <div className="space-y-2">
                    <div className="flex items-center gap-2 mb-4">
                        <Terminal size={20} className="text-primary" />
                        <span className="font-headline-md text-headline-md tracking-tighter text-primary drop-shadow-[0_0_8px_rgba(173,198,255,0.4)]">
                            VULNRADAR
                        </span>
                    </div>
                    <h1 className="font-headline-lg text-headline-lg text-on-surface leading-none tracking-tight">
                        SYSTEM ACCESS REQUIRED
                    </h1>
                    <p className="font-code-sm text-code-sm text-outline uppercase tracking-widest">
                        DECRYPTING ACCESS PORTAL...
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
                            <span className="font-label-bold text-label-bold text-outline group-focus-within/input:text-primary transition-colors uppercase">
                                Operator ID
                            </span>
                            <span className="font-code-sm text-code-sm text-outline-variant group-focus-within/input:text-primary/50 transition-colors">
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
                                className="w-full bg-surface-container-low border border-outline-variant focus:border-primary focus:ring-0 text-on-surface font-body-md py-4 px-4 transition-all placeholder:text-outline-variant/50"
                            />
                            <div className="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-focus-within/input:opacity-100 transition-opacity">
                                <Mail size={20} className="text-primary" />
                            </div>
                        </div>
                        {errors.email && (
                            <p className="font-code-sm text-code-sm text-error">{errors.email.message}</p>
                        )}
                    </div>

                    {/* Password Field */}
                    <div className="space-y-2 group/input">
                        <label className="flex justify-between items-center px-1" htmlFor="password">
                            <span className="font-label-bold text-label-bold text-outline group-focus-within/input:text-primary transition-colors uppercase">
                                Security Cipher
                            </span>
                            <span className="font-code-sm text-code-sm text-outline-variant group-focus-within/input:text-primary/50 transition-colors">
                                AES_CIPHER_X64
                            </span>
                        </label>
                        <div className="relative">
                            <input
                                {...register('password')}
                                id="password"
                                type="password"
                                placeholder="••••••••••••"
                                className="w-full bg-surface-container-low border border-outline-variant focus:border-primary focus:ring-0 text-on-surface font-body-md py-4 px-4 transition-all placeholder:text-outline-variant/50"
                            />
                            <div className="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-focus-within/input:opacity-100 transition-opacity">
                                <Lock size={20} className="text-primary" />                            </div>
                        </div>
                        {errors.password && (
                            <p className="font-code-sm text-code-sm text-error">{errors.password.message}</p>
                        )}
                    </div>
                    <button
                        type="submit"
                        disabled={isSubmitting}
                        className="w-full rounded-none bg-primary px-6 py-4 text-on-primary font-label-bold text-label-bold uppercase tracking-[0.2em] transition-all hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {isSubmitting ? 'AUTHENTICATING...' : 'INITIATE SESSION'}
                    </button>
                    {/* Actions */}
                    <div className="text-center pt-2">
                        <span className="text-outline font-code-sm text-code-sm">No access credentials? </span>
                        <motion.button
                            type="button"
                            onClick={onToggle}
                            className="font-code-sm text-code-sm text-secondary transition-colors"
                            whileHover={{ scale: 1.05 }}
                        >
                            Initialize New Operator Account
                        </motion.button>
                    </div>
                </form>

                {/* Technical Metadata */}
                <div className="pt-6 border-t border-outline-variant/20 flex flex-wrap gap-x-6 gap-y-2">
                    <div className="flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-none bg-secondary-fixed animate-pulse"></span>
                        <span className="font-code-sm text-code-sm text-outline">NODE: VR-DELTA-9</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="font-code-sm text-code-sm text-outline">ENCRYPTION: AES-256</span>
                    </div>
                    <div className="flex items-center gap-2 ml-auto">
                        <span className="font-code-sm text-code-sm text-primary uppercase">Status: Ready</span>
                    </div>
                </div>
            </div>
        </div>
    );
}
