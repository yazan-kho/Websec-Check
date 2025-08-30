# Websec Check: A Web Security Auditing Extension

**Websec Check** is a browser extension that provides a quick, client-side security audit of the current page you are visiting. It checks for common security misconfigurations in both the server-provided security headers and the page's HTML structure (DOM), helping developers and security enthusiasts identify potential vulnerabilities.



## Features

* **Security Header Analysis**: Automatically checks for the presence and configuration of crucial HTTP security headers, including:
    * `Content-Security-Policy`
    * `Strict-Transport-Security`
    * `X-Content-Type-Options`
    * `X-Frame-Options`
    * `X-XSS-Protection`
    * `Referrer-Policy`
    * `Permissions-Policy`

* **DOM Vulnerability Detection**: Scans the page's Document Object Model (DOM) for potential risks that can arise from client-side code:
    * **Inline Event Handlers**: Identifies elements with inline `on*` attributes (`onclick`, `onload`, etc.).
    * **Inline Scripts Without Nonce**: Flags `<script>` tags that lack a `nonce` attribute, which could be a risk if a strong Content Security Policy is not in place.
    * **Inline Scripts with `eval()`**: Detects the use of `eval()` or `new Function()` within inline scripts, which can be a security concern.
    * **Mixed Content**: Finds insecure HTTP resources (images, scripts, stylesheets, etc.) loaded on a secure HTTPS page.

***

## How It Works

The extension operates through a simple, yet powerful, workflow:

1.  A **background service worker** (`background.js`) constantly listens for web requests and collects response headers for the top-level document of each tab.
2.  A **content script** (`content.js`) is injected into every page to analyze the HTML elements and identify client-side security risks.
3.  When you click the extension's icon, a **popup window** (`popup.js`) is launched.
4.  The `popup.js` script requests the collected header data from `background.js` and the DOM findings from `content.js`.
5.  All the data is combined and rendered into a comprehensive, color-coded report that displays the security status of the current page.

***

## Installation

This extension is not currently available on the Chrome Web Store. To install it, you must load it as an unpacked extension.

1.  Download or clone this repository to your local machine.
2.  Open your browser and navigate to the extensions page (e.g., `chrome://extensions` for Chrome).
3.  Enable **Developer mode** in the top-right corner.
4.  Click **"Load unpacked"** and select the folder where you saved the extension's files.

The extension icon should now appear in your browser toolbar.