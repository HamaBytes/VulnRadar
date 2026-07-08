import { cva, type VariantProps } from "class-variance-authority";
import {
    AlertTriangle,
    Flame,
    Info,
    ShieldAlert,
    ShieldCheck,
} from "lucide-react";
import { cn } from "../../utils/utils";

// ─────────────────────────────────────────────────────────────────────────────
// CVA — no rounded corners, brutalist theme
// ─────────────────────────────────────────────────────────────────────────────

const severityBadge = cva(
    `inline-flex items-center gap-1.5
     px-3 py-1
     border
     font-label-bold
     text-label-bold
     uppercase
     tracking-widest
     transition-all`,
    {
        variants: {
            severity: {
                CRITICAL:
                    "bg-error-container text-on-error-container border-error shadow-[0_0_10px_rgba(255,84,81,0.3)]",

                HIGH:
                    "bg-error/10 text-error border-error/50",

                MEDIUM:
                    "bg-secondary/10 text-secondary border-secondary/50",

                LOW:
                    "bg-terminal-green/10 text-terminal-green border-terminal-green/50",

                INFO:
                    "bg-primary/10 text-primary border-primary/50",
            },
        },
        defaultVariants: {
            severity: "INFO",
        },
    }
);

// ─────────────────────────────────────────────────────────────────────────────
// Icons mapped to severity
// ─────────────────────────────────────────────────────────────────────────────

const severityIcons = {
    CRITICAL: Flame,
    HIGH: ShieldAlert,
    MEDIUM: AlertTriangle,
    LOW: ShieldCheck,
    INFO: Info,
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type Severity = keyof typeof severityIcons;

interface SeverityBadgeProps extends VariantProps<typeof severityBadge> {
    severity: Severity;
    className?: string;
    /** Show animated pulse dot for active threats */
    pulse?: boolean;
    /** Optional count badge */
    count?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────

export function SeverityBadge({
                                  severity,
                                  className,
                                  pulse = false,
                                  count,
                              }: SeverityBadgeProps) {
    const Icon = severityIcons[severity];

    return (
        <span className={cn(severityBadge({ severity }), className)}>
            {pulse && (
                <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-current opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-current" />
                </span>
            )}
            <Icon size={14} strokeWidth={2.5} />
            {severity}
            {count !== undefined && (
                <span className="ml-1 text-[10px] opacity-70">
                    {count}
                </span>
            )}
        </span>
    );
}
