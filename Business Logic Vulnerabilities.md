# Business Logic Vulnerabilities

## What are business logic vulnerabilities

Business logic vulnerabilities are flaws in the assumptions and rules that govern how an application is supposed to work, not in the code itself. The application does exactly what the developer wrote — the problem is that the developer did not think through the flow carefully enough. Scanners cannot find these vulnerabilities because they require understanding what the application is supposed to do and then testing what happens when you do something unexpected.

When testing, the useful questions are: what does the application assume I will do, what happens if I do something different, is validation consistent across the entire flow, and is each parameter validated independently.

## Labs completed

- Excessive trust in client-side controls (Apprentice)
- High-level logic vulnerability (Apprentice)
- Low-level logic flaw (Apprentice)
- Inconsistent security controls (Apprentice)
- Flawed enforcement of business rules (Apprentice)
- Insufficient workflow validation (Practitioner)
- Authentication bypass via flawed state machine (Practitioner)
- Weak isolation on dual-use endpoint (Practitioner)
- Inconsistent handling of exceptional input (Practitioner)
- Infinite money logic flaw (Practitioner)
- Authentication bypass via encryption oracle (Practitioner)
- Bypassing access controls using email address parsing discrepancies (Expert)

## Vulnerabilities covered

**Excessive trust in client-side controls** — the application sent the product price as a POST parameter and trusted it without server-side verification. Changing `price=133700` to `price=1` bought a jacket for $0.01. Prices, discounts, and all financial values must be validated exclusively on the server side.

**High-level logic vulnerability** — the application checked that the cart total was above $0 but did not validate that individual product quantities made sense. Adding a cheap item with a negative quantity brought the total within budget. Every parameter must be validated independently, not just the final computed result.

**Low-level logic flaw / integer overflow** — the cart total was stored as a 32-bit integer. Adding 99 units of an expensive item hundreds of times via Burp Intruder with Null payloads caused the value to wrap around to a large negative number. A cheap item was then added to bring the total into the $0–$100 range. Financial values should always use `decimal` or `BigDecimal`, never a plain integer.

**Inconsistent security controls** — the application granted admin panel access to users with a corporate email domain, but this was only checked at registration. After registering, the email could be changed to any address including the corporate domain without re-verification. Security controls must be enforced consistently across the entire account lifecycle, not only at the point of entry.

**Flawed enforcement of business rules** — the shop had two discount codes. The application blocked using the same code twice in a row but not alternating between them. Cycling through both codes repeatedly reduced a $1337 jacket to around $30. Validation must cover the history of actions within a session, not just the immediately preceding one.

**Insufficient workflow validation** — the checkout flow did not verify that payment had actually succeeded before rendering the order confirmation page. Dropping the insufficient funds error and navigating directly to `/cart/order-confirmation?order-confirmed=true` completed the order without payment. Every step in a multi-stage process must be validated server-side, and the server must never assume prior steps were completed.

**Authentication bypass via flawed state machine** — the login flow had two steps: credentials and role selection. The server assumed the user would always complete both. Dropping the `GET /role-selector` request in Burp and navigating directly to `/admin` caused the application to assign the default role, which was administrator.

**Weak isolation on dual-use endpoint** — the password change endpoint read the target username from the request body instead of from the session. Removing the `current-password` parameter did not block the operation. Submitting `username=administrator` with a new password changed the admin password without knowing the current one. User identity must always come from the server-side session, never from request parameters.

**Inconsistent handling of exceptional input** — the application truncated email addresses to 255 characters. Admin access required the `@dontwannacry.com` domain. Registering with an address crafted so that truncation removed the trailing real domain left only the corporate domain:
aaaa[238 chars]@dontwannacry.com.exploit-server.net

After truncation this became `aaaa...@dontwannacry.com`, granting admin access. Domain validation must happen after normalization and truncation, not before.

**Infinite money logic flaw** — gift cards cost $10 and a 30% discount coupon was available, making each cycle profitable by $3. Automating the full purchase-and-redeem sequence using a Burp Macro with Session Handling Rules and Intruder Null payloads repeated the cycle enough times to accumulate $1337. The macro covered seven steps: fetching CSRF tokens, adding the item, applying the coupon, checking out, and redeeming the gift card code extracted via a custom parameter. Combinations of discount features, gift cards, and loyalty mechanics can interact in ways the developer never anticipated.

**Authentication bypass via encryption oracle** — the application used the same AES-CBC key for two cookies: `stay-logged-in` encrypted `username:timestamp`, and `notification` encrypted error messages containing user input. The comment endpoint acted as an encryption oracle — it encrypted arbitrary text supplied in the email field and returned the result in the notification cookie. Decrypting the `stay-logged-in` cookie via the notification endpoint revealed the plaintext format. Encrypting `xxxxxxxxxadministrator:timestamp` through the comment endpoint and stripping the first 32 bytes (the prefix plus padding) produced a valid `stay-logged-in` cookie for the administrator. The same key must never be used in two different contexts, especially when one of them accepts user input.

**Email parsing discrepancies** — the application required a specific corporate domain at registration. The validator and the mail server parsed RFC 2047 encoded-word addresses differently. Encoding the `@` character as `&AEA-` in UTF-7 made the validator see the corporate domain at the end of the address while the mail server decoded the UTF-7 and delivered the confirmation to the attacker's address. Different system components can parse the same input differently, and rare encoding formats such as RFC 2047, Unicode normalization, and punycode are worth testing wherever email addresses are validated.

## Key takeaway

Business logic vulnerabilities cannot be found by scanners because they require understanding the intended behavior of the application. The most productive testing approach is to ask what the application assumes about user behavior and then deliberately violate those assumptions — submitting steps out of order, using negative numbers, combining features in unintended ways, and probing the boundaries of every numeric field.
