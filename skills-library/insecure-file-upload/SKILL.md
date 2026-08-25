---
name: insecure-file-upload
description: "Insecure file upload covers the range of weaknesses in a feature that accepts a file from a user -- accepting a dangerous file extension, trusting a client-supplied content-type, storing the file somewhere it can later be executed, or failing to check the file's actual content against its claimed type -- any of which can turn an upload feature into a path to code execution or stored content that harms other users. Use this skill when a target has any feature that accepts a file from a user: avatars, attachments, document import, or media upload. Triggers: 'insecure file upload', 'file upload vulnerability', 'webshell upload', 'unrestricted file type', 'upload extension bypass'."
version: 1.0.0
phase: ["enum", "exploit"]
category: ["web-access-control"]
tags: ["file-upload", "insecure-file-upload", "upload-bypass", "web"]
---

# Insecure File Upload

## What it is
Insecure file upload is really a cluster of related weaknesses that share one entry point. The upload feature might accept an extension it should not, such as a server-executable script where only images are intended; trust a client-controlled content-type header instead of checking the file's actual content; store the uploaded file inside a web-servable directory without disabling execution there; or fail to check the file for embedded content that harms another user who later opens it, such as a stored script payload inside an image or document format.

## Where it shows up
Any avatar, attachment, document-import, or media-upload feature is a candidate. Signals worth checking: whether the upload accepts an extension beyond the stated intent, whether the server re-validates content type server-side rather than trusting the client, and whether the resulting file is served from a path that would execute it rather than just deliver it as a static asset.

## How Boundhound approaches it
`/enum` uses ffuf (through `bh-exec`) to locate upload endpoints and, separately, to discover whether previously uploaded files are reachable and executable under a predictable path; nuclei's upload-related templates flag a subset of known misconfiguration patterns where a matching template exists. Confirming an actual bypass -- an unexpected extension accepted, a content-type check that only inspects the client-supplied header, or execution from the storage path -- is manual, through `/burp`: modify the upload request's filename, extension, or content-type and observe how the server responds, then check, without invoking any payload, whether the stored file would be served from an executable path.

## Scope & safety
Upload targets and any resulting stored-file paths must already be covered by `scope.yaml`; the Burp MCP guard refuses a request to anything outside that scope. Boundhound's proof-of-vulnerability is non-destructive: it uploads content that demonstrates the bypass, such as an unexpected extension or content-type being accepted, without uploading or invoking a working executable payload against the target.

## Remediation
Validate uploaded content server-side by its actual bytes, not by client-supplied filename or content-type; store uploads outside any web-executable path, and serve them, if needed, through a handler that sets a safe content-type and disposition rather than letting the storage location be requested directly. Enforce a strict allow-list of accepted file types and strip active content, such as embedded scripts in vector-image or office-document formats, where feasible.
