import { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { LoginForm } from '../components/auth/LoginForm';
import { RegisterForm } from '../components/auth/RegisterForm';
export function AuthPage() {
    const [isLogin, setIsLogin] = useState(true);
    return (
        <div className="min-h-screen bg-background text-on-background flex items-center justify-center p-gutter relative overflow-hidden">
            <div
                className="fixed inset-0 pointer-events-none z-0 opacity-40"
                style={{
                    backgroundSize: '32px 32px',
                    backgroundImage: 'linear-gradient(to right, rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.03) 1px, transparent 1px)'
                }}
            />
            <div className="fixed top-8 left-8 text-outline-variant space-y-1 hidden lg:block">
                <p className="font-code-sm text-code-sm">COORD_X: 42.109</p>
                <p className="font-code-sm text-code-sm">COORD_Y: 71.332</p>
                <p className="font-code-sm text-code-sm">LATENCY: 12ms</p>
            </div>
            <div className="fixed bottom-8 right-8 text-outline-variant text-right space-y-1 hidden lg:block">
                <p className="font-code-sm text-code-sm">SYS_UPTIME: 99.98%</p>
                <p className="font-code-sm text-code-sm">VULN_SCAN: ACTIVE</p>
                <motion.p
                    className="font-code-sm text-code-sm"
                    animate={{ color: isLogin ? '#adc6ff' : '#5de6ff' }}
                    transition={{ duration: 0.3 }}
                >
                    AUTHORIZED PERSONNEL ONLY
                </motion.p>
            </div>

            <div className="relative z-10 w-full max-w-md">
                <AnimatePresence mode="wait">
                    {isLogin ? (
                        <motion.div
                            key="login"
                            initial={{ opacity: 0, x: 60, scale: 0.98 }}
                            animate={{ opacity: 1, x: 0, scale: 1 }}
                            exit={{ opacity: 0, x: -60, scale: 0.98 }}
                            transition={{ duration: 0.4, ease: "easeInOut" }}
                        >
                            <LoginForm onToggle={() => setIsLogin(false)} />
                        </motion.div>
                    ) : (
                        <motion.div
                            key="register"
                            initial={{ opacity: 0, x: -60, scale: 0.98 }}
                            animate={{ opacity: 1, x: 0, scale: 1 }}
                            exit={{ opacity: 0, x: 60, scale: 0.98 }}
                            transition={{ duration: 0.4, ease: "easeInOut" }}
                        >
                            <RegisterForm onToggle={() => setIsLogin(true)} />
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </div>
    );
}