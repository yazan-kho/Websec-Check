console.log("[popup] loaded");

async function getCurrentTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0];
}

function createStatusItem(title, status, description, details = []) {
    const item = document.createElement("div");
    item.className = "section-item";

    const icon = document.createElement("div");
    icon.className = `status-icon ${status}`;
    icon.textContent = getIcon(status);

    const content = document.createElement("div");
    content.className = "item-content";

    const titleEl = document.createElement("div");
    titleEl.className = "item-title";
    titleEl.innerHTML = title;

    const descEl = document.createElement("div");
    descEl.className = "item-description";
    descEl.textContent = description;

    content.appendChild(titleEl);
    content.appendChild(descEl);
    item.appendChild(icon);
    item.appendChild(content);

    if (details.length > 0) {
        const detailsList = document.createElement("ul");
        detailsList.className = "details-list";
        details.forEach(d => {
            const li = document.createElement("li");
            li.textContent = d;
            detailsList.appendChild(li);
        });
        content.appendChild(detailsList);
    }

    return item;
}

function getIcon(status) {
    switch (status) {
        case 'ok':
            return '✅';
        case 'warn':
            return '⚠️';
        case 'danger':
            return '❌';
        case 'info':
        default:
            return 'ℹ️';
    }
}

async function getHeadersForTab(tabId, ms = 1500) {
  const ask = chrome.runtime.sendMessage({ type: "GET_HEADERS_FOR_TAB", tabId });
  const timeout = new Promise(r => setTimeout(() => r(null), ms));
  try {
    const res = await Promise.race([ask, timeout]);
    return res;
  } catch (e) {
    console.error("[popup] sendMessage error", e);
    return null;
  }
}

(async () => {
    const pageEl = document.getElementById("page");
    const headersEl = document.getElementById("headers-section");
    const risksEl = document.getElementById("risks-section");

    const tab = await getCurrentTab();
    pageEl.textContent = tab?.url || "No active tab found";

    // Header Analysis
    const headerData = await getHeadersForTab(tab.id);
    const headers = (headerData && headerData.headers) || {};
    headersEl.innerHTML = ''; // Clear loading text

    if (headers['content-security-policy']) {
        headersEl.appendChild(createStatusItem(
            'Content-Security-Policy', 'ok', `Value: ${headers['content-security-policy']}`
        ));
    } else {
        headersEl.appendChild(createStatusItem(
            'Content-Security-Policy', 'danger', "Not set. Can lead to XSS and data injection."
        ));
    }
    if (headers['strict-transport-security']) {
        headersEl.appendChild(createStatusItem(
            'Strict-Transport-Security', 'ok', `Value: ${headers['strict-transport-security']}`
        ));
    } else {
        headersEl.appendChild(createStatusItem(
            'Strict-Transport-Security', 'warn', "Not set. Puts the page at risk of SSL stripping."
        ));
    }
    if (headers['x-content-type-options']) {
        headersEl.appendChild(createStatusItem(
            'X-Content-Type-Options', 'ok', `Value: ${headers['x-content-type-options']}`
        ));
    } else {
        headersEl.appendChild(createStatusItem(
            'X-Content-Type-Options', 'warn', "Not set. MIME sniffing can lead to vulnerabilities."
        ));
    }
    if (headers['x-frame-options']) {
        headersEl.appendChild(createStatusItem(
            'X-Frame-Options', 'ok', `Value: ${headers['x-frame-options']}`
        ));
    } else {
        headersEl.appendChild(createStatusItem(
            'X-Frame-Options', 'warn', "Not set. Allows clickjacking via iframes."
        ));
    }
    if (headers['x-xss-protection']) {
        headersEl.appendChild(createStatusItem(
            'X-XSS-Protection', 'ok', `Value: ${headers['x-xss-protection']}`
        ));
    } else {
        headersEl.appendChild(createStatusItem(
            'X-XSS-Protection', 'warn', "Not set. Legacy header for older browser XSS protection."
        ));
    }
    if (headers['referrer-policy']) {
    headersEl.appendChild(createStatusItem(
        'Referrer-Policy', 'ok', `Value: ${headers['referrer-policy']}`
    ));
    } else {
        headersEl.appendChild(createStatusItem(
            'Referrer-Policy', 'warn',  "Not set. Controls how much referrer information (URL path, query) is sent when navigating. Can leak the referring page's URL to other sites."
        ));
    }
    if (headers['permissions-policy']) {
    headersEl.appendChild(createStatusItem(
        'Permissions-Policy', 'ok', `Value: ${headers['permissions-policy']}`
    ));
    } else {
        headersEl.appendChild(createStatusItem(
            'Permissions-Policy', 'warn',  "Not set. Allows third-party access to powerful browser features (camera, geolocation, microphone, etc.)."
        ));
    }
    if (Object.keys(headers).length === 0) {
        headersEl.appendChild(createStatusItem(
            'No Security Headers Found', 'info', "This page may not be using any of the common security headers."
        ));
    }
    

    // DOM Risk Analysis
    const [{ result }] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => window.__WSC_FINDINGS__ || {}
    });

    const findings = {
        inlineEventHandlers: result?.inlineEventHandlers || [],
        inlineScriptsWithoutNonce: result?.inlineScriptsWithoutNonce || 0,
        inlineScriptsWithoutEval: result?.inlineScriptsWithoutEval || 0,
        mixedContent: result?.mixedContent || [],
    };

    risksEl.innerHTML = ''; // Clear loading text

    let foundRisks = false;

    if (findings.inlineEventHandlers.length > 0) {
        foundRisks = true;
        const details = findings.inlineEventHandlers.map(({ tag, attr }) => `Element <${tag}> with attribute "${attr}"`);
        risksEl.appendChild(createStatusItem(
            'Inline Event Handlers',
            'warn',
            `Found ${findings.inlineEventHandlers.length} instance(s). These can be a CSP bypass.`,
            details
        ));
    }

    if (findings.inlineScriptsWithoutNonce > 0) {
        foundRisks = true;
        risksEl.appendChild(createStatusItem(
            'Inline Scripts without Nonce',
            'danger',
            `Found ${findings.inlineScriptsWithoutNonce} instance(s). These are a security risk if no CSP is set.`
        ));
    }

    if (findings.inlineScriptsWithoutEval > 0) {
        foundRisks = true;
        risksEl.appendChild(createStatusItem(
            'Inline Scripts with eval()',
            'danger',
            `Found ${findings.inlineScriptsWithoutEval} instance(s). The use of eval() can be a security risk.`
        ));
    }

    if (findings.mixedContent.length > 0) {
        foundRisks = true;
        const details = findings.mixedContent.map(({ tag, src }) => `Element <${tag}> with source "${src}"`);
        risksEl.appendChild(createStatusItem(
            'Mixed Content',
            'danger',
            `Found ${findings.mixedContent.length} instance(s). These weaken the security of the HTTPS page.`,
            details
        ));
    }

    if (!foundRisks) {
        risksEl.appendChild(createStatusItem(
            'No Security Risks Found', 'ok', 'The page appears to be free of common client-side vulnerabilities.'
        ));
    }
})();