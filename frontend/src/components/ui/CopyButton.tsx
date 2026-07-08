import { Copy, Check } from 'lucide-react';
import { useCopyToClipboard } from '../../hooks/useCopyToClipboard';

interface CopyToClipboardProps {
    /** The text to copy when clicked */
    value: string;
    /** Optional label shown next to the icon. Omit for icon-only usage. */
    label?: string;
    className?: string;
}

export function CopyToClipboard({ value, label, className = '' }: CopyToClipboardProps) {
    const [, copy, isCopied] = useCopyToClipboard();

    return (
        <button
            type="button"
            onClick={() => copy(value)}
            aria-label={isCopied ? 'Copied to clipboard' : 'Copy to clipboard'}
            className={`inline-flex items-center gap-2 font-code-sm text-code-sm uppercase tracking-wider transition-colors duration-200 ${
                isCopied ? 'text-terminal-green' : 'text-outline hover:text-primary'
            } ${className}`}
        >
            <span className="relative h-4 w-4 shrink-0">
                <Copy
                    size={16}
                    className={`absolute inset-0 transition-all duration-200 ${
                        isCopied ? 'opacity-0 scale-75' : 'opacity-100 scale-100'
                    }`}
                />
                <Check
                    size={16}
                    className={`absolute inset-0 transition-all duration-200 ${
                        isCopied ? 'opacity-100 scale-100' : 'opacity-0 scale-75'
                    }`}
                />
            </span>
            {label && <span>{isCopied ? 'Copied' : label}</span>}
        </button>
    );
}