import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, useInView, AnimatePresence } from 'framer-motion';


import { ThemeToggle } from '../../components/layout/ThemeToggle.tsx';
import {
    Shield,
    Radar,
    Zap,
    Database,
    Lock,
    Server,
    Activity,
    Terminal,
    Globe,
    Crosshair,
    Cpu,
    Network,
    Fingerprint,
    SatelliteDish,
    Bug,
    Target,
    ArrowRight,
    Menu,
    X,
} from 'lucide-react';
import { FaGithub, FaLinkedin, FaTwitter } from 'react-icons/fa';
// ─── Animated Counter ─────────────────────────────────────────────
function AnimatedCounter({ end, suffix = '', duration = 2 }: { end: number; suffix?: string; duration?: number }) {
    const [count, setCount] = useState(0);
    const ref = useRef(null);
    const isInView = useInView(ref, { once: true });

    useEffect(() => {
        if (!isInView) return;
        let start = 0;
        const increment = end / (duration * 60);
        const timer = setInterval(() => {
            start += increment;
            if (start >= end) {
                setCount(end);
                clearInterval(timer);
            } else {
                setCount(Math.floor(start));
            }
        }, 1000 / 60);
        return () => clearInterval(timer);
    }, [isInView, end, duration]);

    return <span ref={ref}>{count.toLocaleString()}{suffix}</span>;
}

// ─── Scanline Effect ──────────────────────────────────────────────
function Scanline() {
    return (
        <motion.div
            className="absolute top-0 left-0 w-full h-[2px] pointer-events-none z-20"
            style={{
                background: 'linear-gradient(90deg, transparent, #5de6ff, transparent)',
                opacity: 0.4,
            }}
            animate={{ top: ['0%', '100%', '0%'] }}
            transition={{ duration: 8, repeat: Infinity, ease: 'linear' }}
        />
    );
}

// ─── Glitch Text ──────────────────────────────────────────────────
function GlitchText({ text, className = '' }: { text: string; className?: string }) {
    return (
        <motion.span
            className={`relative inline-block ${className}`}
            whileHover={{
                x: [0, -2, 2, -2, 0],
                transition: { duration: 0.3, repeat: Infinity }
            }}
        >
            {text}
        </motion.span>
    );
}

// ─── Terminal Mockup ──────────────────────────────────────────────
function TerminalMockup() {
    const [lines, setLines] = useState<string[]>([]);
    const fullLines = [
        '$ vuln-radar --init-sequence',
        '[INFO] System kernel established...',
        '[INFO] Syncing with KEV catalog...',
        '[OK] CISA KEV Sync Complete (1,104 targets)',
        '[ANALYZING] CVE-2026-XXXX (UNASSIGNED)',
        'Heuristic Score: 9.8 CRITICAL',
        'Exploit Telemetry: POC Detected on GitHub',
        '$ monitoring traffic...',
        '_ SYSTEM READY'
    ];

    useEffect(() => {
        let i = 0;
        const interval = setInterval(() => {
            if (i >= fullLines.length) {
                clearInterval(interval);
                return;
            }
            setLines(prev => [...prev, fullLines[i]]);
            i++;
        }, 400);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="glass-panel rounded-lg overflow-hidden border border-outline-variant/40 shadow-2xl relative">
            <div className="bg-surface-container-highest/50 px-4 py-2 border-b border-outline-variant/30 flex items-center justify-between">
                <div className="flex gap-2">
                    <div className="w-2.5 h-2.5 rounded-full bg-error/60" />
                    <div className="w-2.5 h-2.5 rounded-full bg-secondary/60" />
                    <div className="w-2.5 h-2.5 rounded-full bg-primary/60" />
                </div>
                <span className="font-code-sm text-code-sm text-outline opacity-50 uppercase tracking-widest">
          vuln_radar_console_v1.0
        </span>
            </div>
            <div className="p-6 font-code-sm text-code-sm bg-surface-container-lowest min-h-[400px] relative overflow-hidden">
                <Scanline />
                <div className="space-y-2">
                    {lines.filter(Boolean).map((line, idx) => {                        if (line.startsWith('[OK]')) {
                            return (
                                <p key={idx} className="flex items-center gap-2">
                                    <span className="text-secondary font-bold">[OK]</span>
                                    <span className="text-on-surface-variant">{line.replace('[OK] ', '')}</span>
                                </p>
                            );
                        }
                        if (line.includes('CRITICAL')) {
                            return (
                                <p key={idx} className="text-on-surface-variant">
                                    Heuristic Score: <span className="text-error font-bold">9.8 CRITICAL</span>
                                </p>
                            );
                        }
                        if (line.includes('POC')) {
                            return (
                                <p key={idx} className="text-on-surface-variant">
                                    Exploit Telemetry: <span className="text-primary">POC Detected on GitHub</span>
                                </p>
                            );
                        }
                        if (line.includes('SYSTEM READY')) {
                            return (
                                <motion.p
                                    key={idx}
                                    className="text-primary font-bold mt-4"
                                    animate={{ opacity: [0.4, 1, 0.4] }}
                                    transition={{ duration: 2, repeat: Infinity }}
                                >
                                    {line}
                                </motion.p>
                            );
                        }
                        if (line.startsWith('$')) {
                            return <p key={idx} className="text-primary">{line}</p>;
                        }
                        return <p key={idx} className="text-on-surface-variant">{line}</p>;
                    })}
                    {lines.length > 5 && (
                        <div className="mt-4 grid grid-cols-8 gap-1 opacity-40">
                            {Array.from({ length: 32 }).map((_, i) => (
                                <motion.div
                                    key={i}
                                    className="h-4 bg-primary"
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: Math.random() }}
                                    transition={{ duration: 0.5, delay: i * 0.02 }}
                                />
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

// ─── Feature Card ─────────────────────────────────────────────────
function FeatureCard({
                         icon: Icon,
                         title,
                         description,
                         color,
                         delay
                     }: {
    icon: React.ElementType;
    title: string;
    description: string;
    color: 'primary' | 'secondary';
    delay: number;
}) {
    const ref = useRef(null);
    const isInView = useInView(ref, { once: true, margin: '-50px' });

    const colorClasses = {
        primary: 'border-primary/40 text-primary hover:bg-primary hover:text-on-primary',
        secondary: 'border-secondary/40 text-secondary hover:bg-secondary hover:text-on-secondary'
    };

    return (
        <motion.div
            ref={ref}
            initial={{ opacity: 0, y: 30 }}
            animate={isInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6, delay }}
            className="glass-panel p-8 group hover:border-primary/50 transition-all duration-500 relative overflow-hidden"
        >
            <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                <Icon size={64} strokeWidth={1} />
            </div>
            <div className={`w-12 h-12 border ${colorClasses[color]} flex items-center justify-center mb-6 transition-all duration-300`}>
                <Icon size={24} />
            </div>
            <h3 className="font-headline-md text-headline-md text-on-surface mb-4">{title}</h3>
            <p className="text-on-surface-variant font-body-md text-body-md leading-relaxed">
                {description}
            </p>
        </motion.div>
    );
}

// ─── Spec Card ────────────────────────────────────────────────────
function SpecCard({
                      icon: Icon,
                      label,
                      value,
                      subtext,
                      color
                  }: {
    icon: React.ElementType;
    label: string;
    value: string;
    subtext: string;
    color: 'primary' | 'secondary';
}) {
    const colorClass = color === 'primary' ? 'text-primary border-l-primary' : 'text-secondary border-l-secondary';

    return (
        <div className={`glass-panel p-6 border-l-4 ${colorClass} flex flex-col justify-between group hover:bg-white/[0.02] transition-all`}>
            <Icon size={28} className={colorClass} strokeWidth={1.5} />
            <div className="mt-4">
                <h4 className="font-label-bold text-label-bold text-on-surface uppercase mb-2">{label}</h4>
                <p className={`font-headline-md text-headline-md ${colorClass}`}>{value}</p>
                <p className="text-[10px] text-outline font-code-sm uppercase mt-2">{subtext}</p>
            </div>
        </div>
    );
}

// ─── Stat Card ────────────────────────────────────────────────────
function StatCard({ value, label, icon: Icon, color }: { value: React.ReactNode; label: string; icon: React.ElementType; color: string }) {    return (
        <motion.div
            whileHover={{ scale: 1.02 }}
            className="glass-panel p-6 text-center border-t-2"
            style={{ borderColor: color }}
        >
            <Icon size={24} className="mx-auto mb-3" style={{ color }} />
            <p className="font-display-xl text-display-xl mb-2" style={{ color }}>{value}</p>
            <p className="font-label-bold text-label-bold text-outline uppercase">{label}</p>
        </motion.div>
    );
}

// ─── Navigation ─────────────────────────────────────────────────────
function Navigation() {
    const navigate = useNavigate();
    const [mobileOpen, setMobileOpen] = useState(false);

    return (
        <nav className="fixed top-0 w-full z-50 bg-background/80 backdrop-blur-xl border-b border-outline-variant/30">
            <div className="flex justify-between items-center max-w-[1440px] mx-auto px-8 h-16">
                <div className="flex items-center gap-4">

                    <Radar size={28} className="text-primary" />
                    <span className="font-headline-md text-headline-md font-bold tracking-tighter text-primary">
            VulnRadar
          </span>
                    <span className="hidden sm:inline-flex px-2 py-0.5 border border-secondary text-secondary font-label-bold text-[10px] tracking-widest uppercase">
            Tactical Intelligence Unit
          </span>
                </div>

                <div className="hidden md:flex items-center gap-8">
                    <a href="#features" className="text-on-surface-variant hover:text-primary transition-colors font-body-md text-body-md">Capabilities</a>
                    <a href="#specs" className="text-on-surface-variant hover:text-primary transition-colors font-body-md text-body-md">Specifications</a>
                    <a href="#pipeline" className="text-on-surface-variant hover:text-primary transition-colors font-body-md text-body-md">Pipeline</a>
                </div>

                <div className="flex items-center gap-4">
                    <ThemeToggle />
                    <button
                        onClick={() => navigate('/login')}
                        className="hidden lg:flex items-center gap-2 px-5 py-2.5 bg-primary text-on-primary font-label-bold text-label-bold uppercase hover:bg-primary/90 transition-all duration-300 active:scale-95 shadow-[0_0_20px_rgba(173,198,255,0.2)]"
                    >
                        <Terminal size={16} />
                        System Access
                    </button>
                    <button
                        className="md:hidden text-primary"
                        onClick={() => setMobileOpen(!mobileOpen)}
                    >
                        {mobileOpen ? <X size={24} /> : <Menu size={24} />}
                    </button>
                </div>
            </div>

            {/* Mobile Menu */}
            <AnimatePresence>
                {mobileOpen && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="md:hidden bg-surface-container-lowest border-t border-outline-variant/30"
                    >
                        <div className="p-6 space-y-4">
                            <a href="#features" className="block text-on-surface-variant hover:text-primary">Capabilities</a>
                            <a href="#specs" className="block text-on-surface-variant hover:text-primary">Specifications</a>
                            <a href="#pipeline" className="block text-on-surface-variant hover:text-primary">Pipeline</a>
                            <button
                                onClick={() => { navigate('/login'); setMobileOpen(false); }}
                                className="w-full flex items-center justify-center gap-2 px-5 py-3 bg-primary text-on-primary font-label-bold text-label-bold uppercase"
                            >
                                <Terminal size={16} />
                                System Access
                            </button>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </nav>
    );
}

// ─── Hero Section ─────────────────────────────────────────────────
function HeroSection() {
    const navigate = useNavigate();

    return (
        <section className="relative pt-32 pb-24 px-8 overflow-hidden">
            <div className="max-w-[1440px] mx-auto grid lg:grid-cols-2 gap-16 items-center">
                <motion.div
                    initial={{ opacity: 0, x: -50 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.8 }}
                    className="z-10"
                >
                    <motion.div
                        initial={{ opacity: 0, scale: 0.9 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ delay: 0.2 }}
                        className="inline-flex items-center gap-2 mb-6 px-3 py-1.5 bg-primary/10 border border-primary/20 text-primary rounded-full"
                    >
                        <motion.span
                            animate={{ opacity: [1, 0.3, 1] }}
                            transition={{ duration: 2, repeat: Infinity }}
                        >
                            <Activity size={16} />
                        </motion.span>
                        <span className="font-label-bold text-[10px] tracking-[0.2em] uppercase">
              Status: Live Monitoring Active
            </span>
                    </motion.div>

                    <h1 className="font-display-xl text-display-xl-mobile md:text-display-xl text-on-surface mb-6 leading-tight uppercase">
                        Precision <br />
                        <GlitchText text="Vulnerability" className="text-secondary" /> <br />
                        Intelligence
                    </h1>

                    <p className="font-body-lg text-body-lg text-on-surface-variant mb-10 max-w-xl">
                        Eliminate the NVD gap with automated heuristics and real-world exploit telemetry.
                        Deploy the tactical edge in cyber defense and risk mitigation.
                    </p>

                    <div className="flex flex-wrap gap-4">
                        <motion.button
                            whileHover={{ scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                            onClick={() => navigate('/auth')}
                            className="px-8 py-4 bg-primary text-on-primary font-label-bold text-label-bold uppercase tracking-widest shadow-[0_0_30px_rgba(173,198,255,0.2)] hover:shadow-[0_0_40px_rgba(173,198,255,0.4)] transition-all duration-300 flex items-center gap-2"
                        >
                            <Shield size={18} />
                            Initialize Intelligence
                        </motion.button>
                        <motion.button
                            whileHover={{ scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                            className="px-8 py-4 border border-outline-variant text-on-surface font-label-bold text-label-bold uppercase tracking-widest hover:bg-white/5 transition-all duration-300 flex items-center gap-2"
                        >
                            <FaGithub size={18} />                            View Documentation
                        </motion.button>
                    </div>
                </motion.div>

                <motion.div
                    initial={{ opacity: 0, x: 50 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.8, delay: 0.3 }}
                    className="relative z-10"
                >
                    <TerminalMockup />

                    {/* Floating stat chip */}
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 1.5 }}
                        className="absolute -bottom-6 -right-6 glass-panel p-4 rounded-lg border-secondary/30 hidden xl:block"
                    >
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-full border-2 border-secondary/50 flex items-center justify-center">
                                <Zap size={20} className="text-secondary" />
                            </div>
                            <div>
                                <p className="font-label-bold text-[10px] text-outline uppercase tracking-wider">Detection Latency</p>
                                <p className="font-headline-md text-headline-md text-secondary">0.42ms</p>
                            </div>
                        </div>
                    </motion.div>
                </motion.div>
            </div>
        </section>
    );
}

// ─── Features Section ─────────────────────────────────────────────
function FeaturesSection() {
    const features = [
        {
            icon: Crosshair,
            title: 'Automated Heuristics',
            description: 'Analyze unassigned CVEs using advanced risk scoring models to predict impact before official database assignment. Close the NVD gap with rule-based intelligence.',
            color: 'primary' as const,
        },
        {
            icon: SatelliteDish,
            title: 'Exploit Telemetry',
            description: 'Real-time tracking of public exploit evidence and proof-of-concept availability across ExploitDB, Metasploit, and GitHub repositories.',
            color: 'secondary' as const,
        },
        {
            icon: Database,
            title: 'KEV Integration',
            description: 'Direct synchronization with CISA\'s Known Exploited Vulnerabilities catalog for prioritized remediation workflows and government compliance.',
            color: 'primary' as const,
        },
        {
            icon: Activity,
            title: 'EPSS Analysis',
            description: 'Deep integration with FIRST.org\'s Exploit Prediction Scoring System to calculate probability of real-world weaponization within 30 days.',
            color: 'secondary' as const,
        },
    ];

    return (
        <section id="features" className="py-24 px-8 relative bg-surface-container-lowest">
            <div className="max-w-[1440px] mx-auto">
                <motion.div
                    initial={{ opacity: 0, x: -30 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    className="mb-16 border-l-4 border-primary pl-6"
                >
          <span className="font-label-bold text-label-bold text-primary uppercase tracking-[0.3em]">
            Operational Capabilities
          </span>
                    <h2 className="font-headline-lg text-headline-lg text-on-surface uppercase mt-2">
                        Next-Generation Defensive Intelligence
                    </h2>
                </motion.div>

                <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-gutter">
                    {features.map((f, i) => (
                        <FeatureCard key={i} {...f} delay={i * 0.15} />
                    ))}
                </div>
            </div>
        </section>
    );
}

// ─── Pipeline Visualization ───────────────────────────────────────
function PipelineSection() {
    const steps = [
        { icon: Globe, label: 'CISA KEV', desc: 'Known Exploited Vulnerabilities catalog' },
        { icon: Activity, label: 'EPSS', desc: 'Exploit Prediction Scoring System' },
        { icon: Database, label: 'NVD', desc: 'National Vulnerability Database' },
        { icon: Bug, label: 'ExploitDB', desc: 'Verified public exploits' },
        { icon: Cpu, label: 'Metasploit', desc: 'Framework integration modules' },
        { icon: FaGithub, label: 'GitHub PoC', desc: 'Community proof-of-concept repos' },    ];

    return (
        <section id="pipeline" className="py-24 px-8 relative overflow-hidden">
            <div className="max-w-[1440px] mx-auto">
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-16"
                >
          <span className="font-label-bold text-label-bold text-primary uppercase tracking-[0.3em]">
            Data Pipeline
          </span>
                    <h2 className="font-headline-lg text-headline-lg text-on-surface uppercase mt-2 mb-4">
                        Multi-Source Intelligence Fusion
                    </h2>
                    <div className="h-px w-24 bg-primary mx-auto" />
                </motion.div>

                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                    {steps.map((step, i) => (
                        <motion.div
                            key={i}
                            initial={{ opacity: 0, y: 20 }}
                            whileInView={{ opacity: 1, y: 0 }}
                            viewport={{ once: true }}
                            transition={{ delay: i * 0.1 }}
                            className="glass-panel p-6 text-center border-t-2 border-primary/50 hover:border-primary transition-colors group"
                        >
                            <step.icon size={32} className="mx-auto mb-4 text-primary group-hover:text-secondary transition-colors" />
                            <h4 className="font-label-bold text-label-bold text-on-surface uppercase mb-1">{step.label}</h4>
                            <p className="font-code-sm text-code-sm text-outline">{step.desc}</p>
                        </motion.div>
                    ))}
                </div>

                {/* Connection arrows */}
                <div className="hidden lg:flex justify-center items-center mt-8 gap-2">
                    {Array.from({ length: 5 }).map((_, i) => (
                        <motion.div
                            key={i}
                            animate={{ x: [0, 5, 0] }}
                            transition={{ duration: 1.5, repeat: Infinity, delay: i * 0.2 }}
                        >
                            <ArrowRight size={20} className="text-primary/50" />
                        </motion.div>
                    ))}
                </div>
            </div>
        </section>
    );
}

// ─── Stats Section ────────────────────────────────────────────────
function StatsSection() {
    return (
        <section className="py-16 px-8 bg-surface-container-lowest border-y border-outline-variant/20">
            <div className="max-w-[1440px] mx-auto grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatCard value={<AnimatedCounter end={1104} />} label="KEV Catalogued" icon={Target} color="#adc6ff" />
                <StatCard value={<AnimatedCounter end={99} suffix="%" />} label="Uptime Reliability" icon={Server} color="#5de6ff" />
                <StatCard value={<AnimatedCounter end={6} />} label="Intel Sources" icon={Network} color="#adc6ff" />
                <StatCard value="0.42ms" label="Detection Latency" icon={Zap} color="#5de6ff" />
            </div>
        </section>
    );
}

// ─── Specs Section ────────────────────────────────────────────────
function SpecsSection() {
    const specs = [
        { icon: Lock, label: 'Security Protocol', value: 'AES-256', subtext: 'Industrial Grade Encryption', color: 'secondary' as const },
        { icon: Server, label: 'Backend Engine', value: 'FastAPI + AsyncIO', subtext: 'High-Concurrency Python Framework', color: 'primary' as const },
        { icon: Database, label: 'Data Store', value: 'PostgreSQL', subtext: 'Relational Vulnerability Index', color: 'secondary' as const },
        { icon: Cpu, label: 'Scoring Engine', value: 'Rule-Based v1', subtext: 'Transparent Risk Calculation', color: 'primary' as const },
    ];

    return (
        <section id="specs" className="py-24 px-8">
            <div className="max-w-[1440px] mx-auto">
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-16"
                >
                    <h2 className="font-headline-lg text-headline-lg text-on-surface uppercase mb-4 tracking-tight">
                        System Specifications
                    </h2>
                    <div className="h-px w-24 bg-primary mx-auto" />
                </motion.div>

                <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {specs.map((spec, i) => (
                        <SpecCard key={i} {...spec} />
                    ))}
                </div>
            </div>
        </section>
    );
}

// ─── CTA Section ──────────────────────────────────────────────────
function CTASection() {
    const navigate = useNavigate();

    return (
        <section className="py-24 px-8 relative overflow-hidden">
            <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                className="max-w-4xl mx-auto glass-panel p-12 text-center relative z-10 border-primary/30"
            >
                <Scanline />
                <h2 className="font-display-xl text-display-xl-mobile md:text-display-xl text-on-surface mb-6 uppercase">
                    Ready for Deployment?
                </h2>
                <p className="font-body-lg text-body-lg text-on-surface-variant mb-10">
                    Join security teams leveraging VulnRadar for unmatched threat intelligence.
                    Upload your CVE findings and get prioritized remediation in seconds.
                </p>
                <motion.button
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    onClick={() => navigate('/auth')}
                    className="px-12 py-5 bg-primary text-on-primary font-label-bold text-label-bold uppercase tracking-[0.2em] shadow-[0_0_30px_rgba(173,198,255,0.3)] flex items-center gap-3 mx-auto"
                >
                    <Fingerprint size={20} />
                    Establish Secure Link
                </motion.button>
            </motion.div>
        </section>
    );
}

// ─── Footer ───────────────────────────────────────────────────────
function Footer() {
    return (
        <footer className="bg-surface-container-lowest w-full py-12 border-t border-outline-variant/50 relative overflow-hidden">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-gutter max-w-[1440px] mx-auto px-8 relative z-10">
                <div className="space-y-6">
                    <div className="flex items-center gap-3">
                        <Radar size={24} className="text-primary" />
                        <span className="font-headline-md text-headline-md text-on-surface font-bold tracking-tighter">
              VULNRADAR
            </span>
                    </div>
                    <p className="font-label-bold text-label-bold text-outline uppercase leading-loose max-w-sm">
                        © 2026 VULNRADAR TACTICAL SYSTEMS. ALL RIGHTS RESERVED. SECURE ENROLLMENT ACTIVE.
                    </p>
                    <div className="flex gap-4">
                        <a href="#" className="text-outline hover:text-primary transition-colors"><FaGithub size={20} /></a>
                        <a href="#" className="text-outline hover:text-primary transition-colors"><FaTwitter size={20} /></a>
                        <a href="#" className="text-outline hover:text-primary transition-colors"><FaLinkedin size={20} /></a>
                    </div>
                </div>
                <div className="grid grid-cols-2 gap-8">
                    <div className="flex flex-col gap-4">
                        <span className="font-label-bold text-label-bold text-primary uppercase">Governance</span>
                        <a href="#" className="text-outline hover:text-on-surface transition-colors font-label-bold text-label-bold uppercase">Privacy Protocol</a>
                        <a href="#" className="text-outline hover:text-on-surface transition-colors font-label-bold text-label-bold uppercase">Terms of Engagement</a>
                    </div>
                    <div className="flex flex-col gap-4">
                        <span className="font-label-bold text-label-bold text-secondary uppercase">Resources</span>
                        <a href="#" className="text-outline hover:text-on-surface transition-colors font-label-bold text-label-bold uppercase">API Docs</a>
                        <a href="#" className="text-outline hover:text-on-surface transition-colors font-label-bold text-label-bold uppercase">System Status</a>
                    </div>
                </div>
            </div>
            <div className="mt-12 h-1 w-full bg-gradient-to-r from-transparent via-primary/20 to-transparent" />
        </footer>
    );
}

// ─── Main Landing Page ────────────────────────────────────────────
export default function LandingPage() {
    return (
        <div className="bg-background text-on-background min-h-screen font-body-md relative overflow-x-hidden">
            {/* Grid Background */}
            <div className="fixed inset-0 pointer-events-none z-0 opacity-40"
                 style={{
                     backgroundSize: '32px 32px',
                     backgroundImage: 'linear-gradient(to right, rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.03) 1px, transparent 1px)'
                 }}
            />

            <Navigation />
            <HeroSection />
            <StatsSection />
            <FeaturesSection />
            <PipelineSection />
            <SpecsSection />
            <CTASection />
            <Footer />
        </div>
    );
}