# LinkShield — Chrome Web Store Listing

## Short Description (132 chars max)

Scans every link before you click. 9-layer threat analysis runs 100% locally. Blocks phishing, malware, and scams. Privacy-first.

(129 characters)


## Category

**Developer Tools** or **Productivity** (primary)

Secondary fit: there is no dedicated "Security" category in Chrome Web Store. Use "Productivity" as the listed category.


## Detailed Description

LinkShield scans every link before it loads. Phishing, malware, scams — blocked before they touch you.

Unlike traditional security extensions that send every URL you visit to a remote server, LinkShield runs entirely on your machine. Your browsing history stays private. No data leaves your computer.

--- HOW IT WORKS ---

When you click any link to an unfamiliar site, LinkShield intercepts the click and runs a full analysis before your browser navigates. If the link is safe, you proceed automatically in 2 seconds. If it's dangerous, you see exactly why — and you decide what to do.

Trusted sites (Google, YouTube, GitHub, Amazon, and 30+ major domains) are never interrupted. You can add any domain to your personal trust list with one click.

--- 9 LAYERS OF ANALYSIS ---

LinkShield doesn't rely on a single check. Every link passes through 9 independent analysis layers:

1. URL Syntax Analysis
Catches @ symbol hijacking, raw IP addresses, data URIs, encoded hostnames, double file extensions, and suspicious path keywords like /login, /verify, /secure.

2. Domain Reputation
Risk-scores the TLD (.tk, .ml, .top are high-risk), measures domain entropy, detects dash-heavy patterns, flags suspicious keywords in the domain name, and identifies free hosting providers.

3. Homograph Detection
Catches Unicode look-alike attacks where attackers use Cyrillic, Greek, or other script characters that visually mimic Latin letters. A Cyrillic "a" looks identical to a Latin "a" but points to a completely different domain.

4. Typosquatting Detection
Compares every domain against 30+ major brands (Google, PayPal, Amazon, Microsoft, Apple, Netflix, and more) using Levenshtein distance. Catches gooogle.com, amaz0n.com, paypai.com, and similar deceptive variations.

5. Redirect Chain Analysis
Follows the full redirect chain to discover where a link actually goes. Flags cross-domain redirects, excessive redirect chains, and links that land on a different domain than expected.

6. SSL Certificate Verification
Validates HTTPS certificates, checks expiration dates, detects domain mismatches between the certificate and the actual domain, and identifies untrusted certificate authorities.

7. DNS Validation
Checks DNS records for the target domain. Flags domains with no DNS records, recently registered domains, and suspicious DNS configurations.

8. Google Safe Browsing (Optional)
If you provide your own API key, LinkShield can cross-reference flagged URLs against Google's Safe Browsing database. Disabled by default — only activates when you enable it.

9. VirusTotal Integration (Optional)
If you provide your own API key, suspicious URLs can be checked against VirusTotal's 70+ antivirus engines. Disabled by default — only activates when you enable it.

--- PRIVACY-FIRST ARCHITECTURE ---

LinkShield is built on a simple principle: a security tool should not itself be a privacy risk.

- 100% local analysis. All URL scanning happens on your machine.
- No URLs are sent to external servers by default.
- No personal data is collected, stored, or transmitted.
- No analytics, no telemetry, no tracking.
- No cookies, no user accounts, no sign-ups.
- The extension communicates only with localhost (127.0.0.1:3847).
- Optional third-party APIs (Safe Browsing, VirusTotal) are off by default and only activate if you explicitly enable them.
- Full source code included. Every file is readable, unminified JavaScript. Audit it yourself.

--- ZERO DEPENDENCIES ---

LinkShield is written in pure JavaScript with zero npm packages. For a security tool, this matters. No supply chain attacks, no hidden code, no packages you can't audit. Every line of code is readable and verifiable.

--- WHAT YOU SEE ---

When a link is flagged, LinkShield shows you a clear analysis page with:
- Each check result (pass, warning, or fail) with a specific explanation
- An overall threat score from 0-100
- A verdict: SAFE, CAUTION, or DANGER
- Action buttons: proceed, go back, or trust the domain permanently

Safe links auto-proceed after 2 seconds. You're never slowed down on legitimate sites.

--- WORKS EVERYWHERE ---

- Chrome extension scans links before you click them
- Content script intercepts clicks, middle-clicks, and window.open calls
- Web navigation handler catches typed URLs, bookmarks, and right-click opens
- Warning banners appear on unverified sites even if the content script didn't catch the navigation

--- BUILT FOR REAL THREATS ---

LinkShield catches the attacks that actually happen:
- Phishing sites impersonating banks, email providers, and social media
- Typosquatting domains one character off from legitimate sites
- Unicode homograph attacks invisible to the human eye
- Shortened URLs that hide the real destination
- Malware distribution through compromised or deceptive links
- Social engineering pages with fake login forms

--- REQUIREMENTS ---

LinkShield requires a local analysis server running on your machine. The server is a lightweight Node.js process that starts with one click and runs in the background. The extension works with basic checks when the server is offline, but full 9-layer analysis requires the server.

--- SUPPORT ---

Questions or issues? Reach out on X: @marcohergi


## Tags

link scanner, phishing protection, malware blocker, URL checker, privacy security, safe browsing, link safety, scam protection, threat detection


## Screenshots Guidance (for Chrome Web Store submission)

Recommended screenshots (1280x800 or 640x400):

1. **Popup** — Show the extension popup with server online, links scanned count, threats caught
2. **Danger verdict** — The check page showing a phishing URL with DANGER score 100/100
3. **Safe verdict** — The check page showing a safe URL with auto-proceed countdown
4. **9 checks** — The analysis page mid-scan, showing all check rows with pass/warn/fail icons
5. **Warning banner** — A website with the LinkShield warning banner at the top
6. **Feature grid** — The landing page's "9 layers of protection" section


## Additional Chrome Web Store Fields

- **Website**: https://linkshield-app.vercel.app
- **Privacy policy URL**: https://linkshield-app.vercel.app/privacy.html
- **Single purpose description**: Scans links for phishing, malware, and scams before navigation using local multi-layer threat analysis.
- **Permission justifications**:
  - activeTab: Read the current tab URL to display site trust status in the popup
  - storage: Persist daily scan and threat count statistics locally
  - webNavigation: Detect navigation to unverified sites and show safety warnings
  - scripting: Inject warning banners on flagged pages
  - Host permissions (all URLs): Content script intercepts link clicks on all pages to redirect untrusted links through the analysis check page before navigation
