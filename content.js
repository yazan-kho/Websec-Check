// This content script acts like a security detective that examines the actual webpage DOM (HTML elements) looking for common client-side security vulnerabilities. It runs on every webpage and collects findings about potentially risky code patterns.

( function () {
    const findings = {
        inlineEventHandlers: [],
        inlineScriptsWithoutNonce: 0,
        inlineScriptsWithoutEval: 0,
        mixedContent: [],
    };

    // 1) inline event handlers (onclick, onload, etc.)
    const all = document.querySelectorAll("*");     // Select all elements in the document; allows to loop it with forEach
    all.forEach((elmnt) => {
        for (const attr of elmnt.getAttributeNames()) {
            // Returns an array of all attribute names on this element (e.g., for <button onclick="...">, the array will include "onclick").
            if (/^on[a-z]+$/.test(attr)) {
                // Matches attributes that start with "on" followed by one or more lowercase letters (e.g., onclick, onload).
                findings.inlineEventHandlers.push({
                    tag: elmnt.tagName.toLowerCase(),
                    attr
                });
            }
        }
    });
    
    // 2) inline scripts without nonce (<script> tags without a nonce attribute)
    const scripts = document.querySelectorAll("script");    // select all <script> elements on the page
    scripts.forEach((s) => {
        const hasSrc = s.hasAttribute("src"); // Check if the script has a src attribute
        const hasNonce = s.hasAttribute("nonce"); // Check if the script has a nonce attribute
        const code = s.textContent || ''; // Get the script content, defaulting to an empty string if undefined
        const type = s.getAttribute("type") || "text/javascript";
        const isExecutable = ["", "text/javascript", "application/javascript", "module"].includes(type);
        
        if (!hasSrc && isExecutable) {
            // inline script
            if (!hasNonce) findings.inlineScriptsWithoutNonce++;
            if (/\beval\s*\(/.test(code) || /\bnew\s+Function\s*\(/.test(code)) {
                // If the script contains eval() or new Function(), count it
                findings.inlineScriptsWithoutEval++;
            }
        }
    });

    // 3) mixed content (HTTP resources on HTTPS pages)
    const pageIsHttps = location.protocol === "https:";
    if (pageIsHttps) {
        const resources = Array.from(document.querySelectorAll("link, script, img, iframe, audio, video, source")); // Select all elements that can load external resources
        resources.forEach((elmnt) => {
            const src = elmnt.getAttribute("src") || elmnt.getAttribute("href"); // Get the src or href attribute (these are the ones that can load external resources)
            if (src && /^http:\/\//i.test(src)) {
                findings.mixedContent.push({tag: elmnt.tagName.toLowerCase(), src});
            }

            const srcset = elmnt.getAttribute("srcset"); // Check for srcset attribute (used in <img> and <source> elements)
            if (srcset && /\shttp:\/\//i.test(srcset)) {
                findings.mixedContent.push({tag: elmnt.tagName.toLowerCase(), src: srcset});
            }
        });
    }

    // Store results so popup can access them
    window.__WSC_FINDINGS__ = findings;
})();
