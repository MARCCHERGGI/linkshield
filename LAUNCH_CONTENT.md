# LinkShield Launch Content

Ready-to-post content for all platforms. Copy, paste, ship.

---

## X/Twitter Thread

**Tweet 1 (Hook)**
You clicked 47 links today.

At least 3 of them could've been phishing pages, typosquats, or homograph attacks using Cyrillic characters that look identical to English.

You'd never know. Your browser doesn't check. I built something that does.

**Tweet 2**
LinkShield runs 9 layers of analysis on every link before it opens:

- URL syntax traps (@ symbols, encoded chars)
- Domain reputation scoring
- Unicode homograph detection (gооgle.com vs google.com — spot the Cyrillic?)
- Typosquatting (gogle, goggle, gooogle)

**Tweet 3**
More layers:

- Redirect chain following (where does that bit.ly actually go?)
- SSL certificate verification
- DNS record analysis
- Google Safe Browsing check
- VirusTotal lookup

All running locally. Your URLs never leave your machine.

**Tweet 4**
It's a Chrome extension backed by a local Node.js server. Zero external dependencies. No npm install with 847 packages. Just Node.js built-ins.

The DNS server mode protects every device on your network — phones, tablets, everything.

**Tweet 5**
What happens when you click a suspicious link:

1. Extension intercepts the click
2. Routes to a scan page
3. 9 checks run in parallel
4. You see a clear verdict: safe / caution / danger
5. You decide whether to proceed

No black-box blocking. You're always in control.

**Tweet 6**
It catches stuff browsers don't:

- paypаl.com (Cyrillic 'а' — looks identical to paypal.com)
- arnazon.com (rn = m)
- goоgle.com (Cyrillic 'о')
- Short URLs hiding malicious redirects
- IP-address URLs pretending to be real sites

**Tweet 7 (CTA)**
LinkShield is $1 and fully open source.

Landing page: https://linkshield-app.vercel.app
GitHub: https://github.com/MARCCHERGGI/linkshield

I built this because I clicked a bad link once. Never again.

---

## Hacker News — Show HN

**Title:**
Show HN: LinkShield — 9-layer link scanner, zero dependencies, runs locally

**Text:**
I got sick of phishing links that look perfect. Unicode homograph attacks where gооgle.com uses Cyrillic 'о' and your browser shows no warning. Typosquats that differ by one character. Short URLs that redirect through 5 hops to a credential harvester.

So I built LinkShield. It's a Chrome extension backed by a local Node.js analysis server that runs 9 checks on every outbound link:

1. URL syntax analysis (@ tricks, encoded payloads, data URIs)
2. Domain reputation scoring against curated lists
3. Unicode homograph detection with a full confusables table (Cyrillic, Greek, fullwidth Latin, etc.)
4. Typosquatting detection using Levenshtein distance, char swaps, doubled chars, and missing chars against 50+ brand profiles
5. Redirect chain resolution — follows the hops, flags suspicious endpoints
6. SSL certificate verification — checks issuer, expiry, and validity
7. DNS record analysis — catches domains with no records or suspicious configurations
8. Google Safe Browsing API (optional, if you provide a key)
9. VirusTotal API (optional)

Architecture decisions:
- Zero npm dependencies. Everything uses Node.js built-ins (node:http, node:https, node:dns, node:tls, node:dgram)
- All analysis runs locally. URLs never leave your machine unless you enable the optional API checks
- LRU cache with TTL so repeated checks are instant
- Content script intercepts clicks at capture phase, before any page handler can suppress it
- Also ships with a DNS server mode that protects every device on the network by resolving dangerous domains to 0.0.0.0

The homograph detection maps 40+ confusable Unicode characters (Cyrillic а/е/о/р/с, Greek α/ε/ο, Turkish ı, fullwidth Latin, various dashes) and flags mixed-script domains. The typosquatting engine uses character-swap detection, doubled-character detection, and missing-character detection in addition to edit distance.

Everything is MIT licensed. No telemetry, no accounts, no cloud.

GitHub: https://github.com/MARCCHERGGI/linkshield
Landing page: https://linkshield-app.vercel.app

---

## LinkedIn Post

Every company I've talked to has had at least one person click a phishing link in the last year. Usually more.

The links are getting better. Homograph attacks use Cyrillic characters that are pixel-identical to English letters. Typosquats register domains one character off from your bank, your SSO provider, your cloud dashboard. Short URLs hide 5 redirect hops ending at a credential harvesting page.

Your browser catches none of this.

I built LinkShield to fix it. It's a Chrome extension that runs 9 layers of analysis on every outbound link before it opens:

- Homograph detection (catches Cyrillic/Greek lookalike domains)
- Typosquatting detection (edit distance + pattern matching against known brands)
- Redirect chain analysis (follows every hop)
- SSL and DNS verification
- URL syntax traps (encoded characters, @ symbol tricks)
- Optional Safe Browsing and VirusTotal integration

Everything runs locally. No URLs are sent to any external service by default. Zero dependencies beyond Node.js.

For teams: the DNS server mode can protect every device on your network without installing anything on each machine.

It's open source (MIT), and costs $1 for the packaged version with the landing page and setup guide.

If you're responsible for security at your org, or you just don't want to be the person who clicked the wrong link — take a look.

GitHub: https://github.com/MARCCHERGGI/linkshield
Info: https://linkshield-app.vercel.app

#cybersecurity #phishing #opensourcesecurity #chromeextension #infosec

---

## Product Hunt

**Name:** LinkShield

**Tagline:** 9 layers between you and a bad link

**Description:**
LinkShield scans every link before you click it. It's a Chrome extension powered by a local analysis server that runs 9 real-time checks:

URL syntax traps, domain reputation, Unicode homograph detection (catches Cyrillic lookalikes like gооgle.com), typosquatting (Levenshtein + pattern matching), redirect chain following, SSL verification, DNS analysis, and optional Safe Browsing + VirusTotal lookups.

Everything runs locally on your machine. Your browsing data never leaves your computer. Zero npm dependencies — built entirely on Node.js built-ins.

Also includes a DNS server mode that protects every device on your network by blocking dangerous domains at the network level.

Open source. MIT licensed. $1.

**Topics:**
- Chrome Extensions
- Cybersecurity
- Privacy
- Open Source
- Developer Tools

**Links:**
- Website: https://linkshield-app.vercel.app
- GitHub: https://github.com/MARCCHERGGI/linkshield

**Maker comment (first comment):**
I built this after clicking a link that looked exactly like a legitimate site. Turned out the domain used Cyrillic characters — pixel-identical to English but pointing to a completely different server.

No browser warned me. No extension caught it. The URL bar showed what looked like the real domain.

So I built 9 layers of protection that catch what browsers miss: homograph attacks, typosquats, suspicious redirects, bad SSL certs, and more. It runs 100% locally with zero dependencies.

I'm charging $1 because I want people to actually use it, not just star the repo. The full source is on GitHub if you want to self-host or contribute.
