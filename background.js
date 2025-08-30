// This background script acts like a network traffic monitor for the security extension. It watches ALL HTTP requests/responses happening in browser tabs and collects security-related information from the response headers.

// In-memory storage for the background script with key by tabId
const headerFindings = new Map();   // Map object to store header details by tabId for each tab. Better for performance and memory usage and quick lookups

// Listen for response headers
chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        const { tabId, responseHeaders, type, url } = details;
        if (tabId < 0) return; // Ignore non-tab requests
        if (type !== "main_frame") return; // keep just the top document's headers

        const wanted = ["content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options", "x-xss-protection", "referrer-policy", "permissions-policy"];
        const found = {};
        for (const header of responseHeaders || []) {
            const name = header.name.toLowerCase();
            if (wanted.includes(name)) {
                found[name] = header.value || '';   // Store the header value, defaulting to empty string if undefined
            }
        }

        if (Object.keys(found).length > 0) {
            const prev = headerFindings.get(tabId) || { headers: {}, urls: [] };    // Look up what we’ve already stored for this tab (if anything). If nothing yet, start with a blank object.
            headerFindings.set(tabId, {
                headers: { ...prev.headers, ...found },  // Merge new findings with previous ones
                urls: [...prev.urls, {type, url}]                // Append the current URL to the list of URLs
            });
        }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders", "extraHeaders"]
);

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg?.type === "GET_HEADERS_FOR_TAB") {
        const tabId = msg.tabId;
        if (tabId < 0) return; // Ignore non-tab requests

        const findings = headerFindings.get(tabId) || { headers: {}, urls: [] }; // Get findings for the tab or an empty object if none found
        sendResponse(findings); // Send the findings back to the content script
    }
});