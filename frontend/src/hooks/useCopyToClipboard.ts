import { useState, useCallback } from 'react';

// Manages copy state, including temporary "Copied!" feedback
export function useCopyToClipboard(): [string | null, (text: string) => Promise<boolean>, boolean] {
    const [copiedText, setCopiedText] = useState<string | null>(null);
    const [isCopied, setIsCopied] = useState<boolean>(false);

    const copy = useCallback(async (text: string) => {
        if (!navigator?.clipboard) return false;
        try {
            await navigator.clipboard.writeText(text); // Native Clipboard API
            setCopiedText(text);
            setIsCopied(true);
            setTimeout(() => setIsCopied(false), 2000); // Feedback timer
            return true;
        } catch { return false; }
    }, []);

    return [copiedText, copy, isCopied];
}
