# MailPal MCP Server -- Comprehensive Test Plan

> **Goal:** Verify every MCP tool works end-to-end, from agent tool call through
> REST API to Stalwart mail server and back. Ship bug-free.
>
> **Test environments:**
> - MCP Inspector: `npx -y @modelcontextprotocol/inspector`
> - Cursor MCP integration (stdio, local dist/index.js)
> - Direct JSON-RPC pipe (PowerShell echo | node dist/index.js)
>
> **Prerequisites:**
> - Valid `MAILPAL_TOKEN` (1id.com JWT for an enrolled agent)
> - MailPal REST API running on vaf (`https://mailpal.com/api/v1/*`)
> - Stalwart mail server running on vaf (SMTP/IMAP/JMAP)
> - A second mailbox to receive test emails (e.g., `aura@geek.net.au`)

---

## Phase 0: MCP Protocol Layer (no backend needed)

These tests verify the MCP server starts, advertises tools correctly, and
handles protocol-level edge cases. They do NOT require a working REST API.

| # | Test | Method | Expected Result | Status |
|---|------|--------|-----------------|--------|
| 0.1 | Server starts on stdio | `echo initialize | node dist/index.js` | Returns `InitializeResult` with name="mailpal", version="1.0.0" | PASS |
| 0.2 | tools/list returns exactly 6 tools | JSON-RPC `tools/list` | Tool names: mailpal_activate_account, mailpal_send_email, mailpal_check_inbox, mailpal_read_message, mailpal_subscribe_to_inbox, mailpal_jmap | PASS |
| 0.3 | Each tool has correct required params | Inspect `tools/list` schemas | send_email requires `to`, `subject`; read_message requires `message_id`; jmap requires `method_calls`; others have no required params | PASS |
| 0.4 | attestation_mode defaults to 2 | Inspect send_email schema | `"default": 2` in inputSchema | PASS |
| 0.5 | Server instructions present | Check initialize response | Instructions mention hardware attestation, 6 tools | PASS |
| 0.6 | Every tool has `token` parameter | Inspect all 6 tool schemas | Each has optional `token` in inputSchema.properties | PASS |
| 0.7 | No token (no env var, no param) | Call any tool | Tool sends unauthenticated request; API returns auth error; MCP returns error content | |
| 0.8 | Invalid JSON-RPC request | Send malformed JSON | Server returns JSON-RPC error, does not crash | |
| 0.9 | Unknown tool name | `tools/call` with name "nonexistent" | JSON-RPC error -32601 (method not found) | |
| 0.10 | Missing required params | `tools/call mailpal_send_email {}` | JSON-RPC error (validation failure for missing `to`, `subject`) | |
| 0.11 | Extra unknown params | `tools/call mailpal_check_inbox {"foo": "bar"}` | Rejected (additionalProperties: false) or ignored gracefully | |

---

## Phase 1: Backend Connectivity (REST API must be running)

These tests verify the MCP server can reach the MailPal REST API and get
meaningful responses. They require `MAILPAL_TOKEN` and a running backend.

### 1A: Verify REST API endpoints exist

Before testing MCP tools, confirm each REST endpoint responds (even if with
an error). Use curl or the MCP terminal tool to probe.

**Status as of 2026-04-11:** Swagger at `/api/docs` confirms endpoints exist.

| # | Endpoint | Method | Expected | Status |
|---|----------|--------|----------|--------|
| 1A.1 | `GET /api/v1/inbox` | GET | 200 with messages array, or 401 if no auth | LIVE (401) |
| 1A.2 | `GET /api/v1/inbox/{id}` | GET | 200 with message, or 404 | LIVE |
| 1A.3 | `POST /api/v1/activate` | POST | 200 with challenge or account info | LIVE |
| 1A.4 | `POST /api/v1/send` | POST | 200 or 400 (validation) | LIVE |
| 1A.5 | `POST /api/v1/send/prepare` | POST | 200 with prepare_token | LIVE |
| 1A.6 | `POST /api/v1/send/commit` | POST | 200 with message_id | LIVE |
| 1A.7 | `POST /api/v1/jmap` | POST | 200 with JMAP response | NOT YET |
| 1A.8 | `GET /api/v1/inbox/events` | GET (SSE) | 200 with text/event-stream | NOT YET |

### 1B: Auth verification (per-call token + env var fallback)

| # | Test | Expected | Status |
|---|------|----------|--------|
| 1B.1 | Valid JWT via `token` param (no env var) | API accepts, returns data | |
| 1B.2 | Valid JWT via MAILPAL_TOKEN env var (no `token` param) | API accepts, falls back to env var | |
| 1B.3 | `token` param overrides MAILPAL_TOKEN env var | Per-call token is used, not env var | |
| 1B.4 | Two calls with different tokens | Each call authenticates as the correct agent | |
| 1B.5 | Expired JWT | API returns 401, MCP tool returns error text | |
| 1B.6 | Malformed JWT (not a JWT at all) | API returns 401 | |
| 1B.7 | No token at all (no param, no env var) | API returns 401 | |

---

## Phase 2: Tool-by-Tool Functional Tests

### 2.1 mailpal_activate_account

| # | Test | Input | Expected | Status |
|---|------|-------|----------|--------|
| 2.1.1 | Phase 1: get challenge | `{}` | Returns `phase: "challenge"`, `prompt`, `challenge_token`, `expires_in_seconds` | |
| 2.1.2 | Phase 2: solve challenge | `{challenge_token: "...", challenge_answer: "..."}` | Returns `primary_email`, `trust_tier`, `smtp`, `imap`, `jmap` | |
| 2.1.3 | Wrong answer | `{challenge_token: "...", challenge_answer: "wrong"}` | Returns error (not a crash) | |
| 2.1.4 | Expired token | Use a token after expiry | Returns error about expiration | |
| 2.1.5 | Idempotent re-activation | Call again after account exists | Returns existing account info (no duplicate) | |
| 2.1.6 | With display_name | `{display_name: "Test Agent"}` | display_name reflected in account | |

### 2.2 mailpal_send_email

| # | Test | Input | Expected | Status |
|---|------|-------|----------|--------|
| 2.2.1 | Basic text email, mode 0 | `{to: ["aura@geek.net.au"], subject: "MCP test", text: "Hello", attestation_mode: 0}` | Returns message_id, status "sent" or "queued" | |
| 2.2.2 | Verify delivery (mode 0) | Check recipient inbox via IMAP | Email arrived, no attestation headers | |
| 2.2.3 | Attested email, mode 2 (default) | `{to: ["aura@geek.net.au"], subject: "Attested test", text: "Hello"}` | Returns message_id, attestation_header present, trust_tier shown | |
| 2.2.4 | Verify attestation headers | Check recipient IMAP raw headers | `Hardware-Trust-Proof` or `Hardware-Attestation` header present, `hw-attest=pass` or `hw-trust=pass` | |
| 2.2.5 | Mode 1 (direct TPM CMS) | `{..., attestation_mode: 1}` | Returns message_id with CMS attestation (sovereign tier only) | |
| 2.2.6 | Mode 2 on declared tier | Agent with declared tier sends mode 2 | Either succeeds (if API supports) or returns clear error | |
| 2.2.7 | HTML email | `{to: [...], subject: "...", html: "<h1>Hello</h1>"}` | HTML body delivered correctly | |
| 2.2.8 | CC and BCC | Include cc and bcc arrays | CC visible in headers, BCC not visible | |
| 2.2.9 | Reply threading | Include `in_reply_to` with a Message-ID | Email threaded correctly in recipient client | |
| 2.2.10 | Missing body (no text, no html) | `{to: [...], subject: "..."}` | API returns validation error | |
| 2.2.11 | Empty to array | `{to: [], subject: "..."}` | Validation error | |
| 2.2.12 | Invalid email address | `{to: ["not-an-email"], ...}` | API returns validation error | |
| 2.2.13 | Very long subject (>998 chars) | Long subject string | API handles gracefully (truncate or error) | |
| 2.2.14 | Unicode subject and body | Japanese/emoji in subject and text | Delivered correctly with proper encoding | |
| 2.2.15 | from_address override | Use a valid alternate address | Sent from that address | |
| 2.2.16 | from_address not owned | Use someone else's address | API rejects | |

### 2.3 mailpal_check_inbox

| # | Test | Input | Expected | Status |
|---|------|-------|----------|--------|
| 2.3.1 | Default params | `{}` | Returns messages array (up to 20), total, unread counts | |
| 2.3.2 | With limit | `{limit: 5}` | At most 5 messages returned | |
| 2.3.3 | With offset | `{limit: 5, offset: 5}` | Second page of results | |
| 2.3.4 | unread_only=true | `{unread_only: true}` | Only unread messages | |
| 2.3.5 | Empty inbox | New agent with no mail | Returns empty messages array, total: 0 | |
| 2.3.6 | Message fields present | Check returned message objects | Each has: id, from, subject, date, is_read, preview, size_bytes | |
| 2.3.7 | limit=0 | `{limit: 0}` | Validation error (min 1) | |
| 2.3.8 | limit=101 | `{limit: 101}` | Validation error (max 100) | |

### 2.4 mailpal_read_message

| # | Test | Input | Expected | Status |
|---|------|-------|----------|--------|
| 2.4.1 | Valid message ID | ID from check_inbox results | Returns full message: id, from, to, cc, subject, date, text_body, html_body, etc. | |
| 2.4.2 | Non-existent ID | `{message_id: "fake-id-12345"}` | API returns 404 or error | |
| 2.4.3 | Message with attachments | Read a message that has attachments | Attachment metadata present (names, sizes, types) | |
| 2.4.4 | HTML-only message | Read a message with only HTML body | html_body present, text_body may be empty or auto-generated | |
| 2.4.5 | Message with attestation headers | Read an attested email | Attestation headers visible in response | |

### 2.5 mailpal_subscribe_to_inbox

| # | Test | Input | Expected | Status |
|---|------|-------|----------|--------|
| 2.5.1 | Subscribe with valid token | `{}` | Returns subscribed: true, uri: "mailpal://inbox/{agent_id}", transport: "stdio" | |
| 2.5.2 | Subscribe without token | (no MAILPAL_TOKEN) | Returns error about missing token | |
| 2.5.3 | Notification on new mail | Subscribe, then send email to agent | MCP client receives `notifications/resources/updated` with inbox URI | |
| 2.5.4 | SSE reconnect on drop | Kill SSE connection | Background task reconnects after 5s | |
| 2.5.5 | Multiple subscribes | Call subscribe twice | Second call replaces first (no duplicate listeners) | |

### 2.6 mailpal_jmap

| # | Test | Input | Expected | Status |
|---|------|-------|----------|--------|
| 2.6.1 | List folders | `{method_calls: [["Mailbox/query", {}, "mq"], ["Mailbox/get", {"#ids": {"resultOf": "mq", "name": "Mailbox/query", "path": "/ids"}, "properties": ["id","name","role","totalEmails","unreadEmails"]}, "mg"]]}` | Returns mailbox list with INBOX, Sent, etc. | |
| 2.6.2 | Search messages | `{method_calls: [["Email/query", {"filter": {"text": "test"}, "limit": 10}, "s1"]]}` | Returns matching message IDs | |
| 2.6.3 | Mark message read | `{method_calls: [["Email/set", {"update": {"MSG_ID": {"keywords/$seen": true}}}, "r1"]]}` | Message marked as read | |
| 2.6.4 | Flag message | `{method_calls: [["Email/set", {"update": {"MSG_ID": {"keywords/$flagged": true}}}, "f1"]]}` | Message flagged | |
| 2.6.5 | Delete message | `{method_calls: [["Email/set", {"destroy": ["MSG_ID"]}, "d1"]]}` | Message destroyed | |
| 2.6.6 | Create folder | `{method_calls: [["Mailbox/set", {"create": {"new1": {"name": "TestFolder"}}}, "cf"]]}` | Folder created | |
| 2.6.7 | Move message to folder | `{method_calls: [["Email/set", {"update": {"MSG_ID": {"mailboxIds": {"FOLDER_ID": true}}}}, "mv"]]}` | Message moved | |
| 2.6.8 | Custom using URIs | `{using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"], method_calls: [...]}` | Submission capabilities available | |
| 2.6.9 | Invalid JMAP method | `{method_calls: [["Fake/method", {}, "x1"]]}` | JMAP error response (not a crash) | |
| 2.6.10 | Empty method_calls | `{method_calls: []}` | Empty response or validation error | |

---

## Phase 3: End-to-End Scenarios

These are multi-step workflows that exercise the full stack.

### 3.1 "Hello World" -- Agent sends its first email

1. Call `mailpal_activate_account` (phase 1) -> get challenge
2. Call `mailpal_activate_account` (phase 2) -> account created
3. Call `mailpal_send_email` with `attestation_mode: 0` -> email sent
4. Verify email arrived at recipient via IMAP
5. Call `mailpal_send_email` with default mode (2) -> attested email sent
6. Verify attestation headers present at recipient via IMAP raw headers

### 3.2 "Inbox workflow" -- Agent reads and manages email

1. Send a test email TO the agent's mailpal address (from another account)
2. Call `mailpal_check_inbox` -> see the new message
3. Call `mailpal_read_message` with the message ID -> see full content
4. Call `mailpal_jmap` to mark it read
5. Call `mailpal_jmap` to flag it
6. Call `mailpal_jmap` to move it to a new folder
7. Call `mailpal_jmap` to delete it
8. Call `mailpal_check_inbox` -> message gone

### 3.3 "Reply chain" -- Agent participates in a thread

1. Receive an email from external sender
2. Read it with `mailpal_read_message`
3. Reply using `mailpal_send_email` with `in_reply_to` set to the Message-ID
4. Verify threading works in recipient's mail client

### 3.4 "Real-time notification" -- You've Got Mail!

1. Call `mailpal_subscribe_to_inbox`
2. From a separate account, send an email to the agent
3. Verify the MCP client receives `notifications/resources/updated`
4. Call `mailpal_check_inbox` to see the new message

### 3.5 "Attestation verification" -- The crown jewel

1. Send an attested email (mode 2) from a sovereign-tier agent
2. Retrieve raw email headers at recipient via IMAP
3. Verify `Hardware-Trust-Proof` header is present
4. Verify `hw-trust=pass` in Authentication-Results
5. Send an attested email (mode 1) from the same agent
6. Verify `Hardware-Attestation` header with CMS signature
7. Verify `hw-attest=pass` in Authentication-Results

### 3.6 "JMAP power user" -- Full Stalwart capabilities

1. Upload an attachment via `mailpal_jmap` (Blob/upload)
2. Compose an email with attachment via `mailpal_jmap` (Email/set)
3. Submit the email via `mailpal_jmap` (EmailSubmission/set)
4. Verify the email with attachment arrived at recipient
5. List contacts via `mailpal_jmap` (if CardDAV enabled)
6. Create a Sieve filter via `mailpal_jmap` (if Sieve enabled)

---

## Phase 4: Error Handling & Edge Cases

| # | Test | Expected | Status |
|---|------|----------|--------|
| 4.1 | API server down (unreachable) | MCP tool returns error text, does not crash | |
| 4.2 | API returns 500 | MCP tool returns error with server message | |
| 4.3 | API returns HTML instead of JSON | MCP tool returns parse error, does not crash | |
| 4.4 | Network timeout (slow API) | MCP tool eventually returns timeout error | |
| 4.5 | Very large inbox (1000+ messages) | check_inbox with pagination works | |
| 4.6 | Very large message (>1MB body) | read_message returns content without truncation | |
| 4.7 | Concurrent tool calls | Two tools called simultaneously | Both complete correctly | |
| 4.8 | MAILPAL_API_URL override | Set to localhost:9999 | Tools call the override URL | |
| 4.9 | Special chars in message_id | URL-encoded correctly in path | |

---

## Phase 5: Python MCP Server Parity

Repeat all Phase 0 and Phase 2 tests against the Python server
(`mailpal-mcp` / `src/mailpal_mcp/server.py`). The Python server must
produce identical results for identical inputs.

| # | Test | Status |
|---|------|--------|
| 5.1 | Phase 0 protocol tests pass | |
| 5.2 | All 6 tools present with correct schemas | PASS |
| 5.3 | Phase 2 functional tests produce same results as TypeScript | |
| 5.4 | `uvx mailpal-mcp` entry point works | |
| 5.5 | `python -m mailpal_mcp` works | |

---

## Test Execution Checklist

- [ ] Phase 0 complete (MCP protocol -- no backend needed)
- [ ] Phase 1A: All REST endpoints confirmed reachable
- [ ] Phase 1B: Auth flow verified
- [ ] Phase 2.1: activate_account all cases
- [ ] Phase 2.2: send_email all cases (including attestation verification)
- [ ] Phase 2.3: check_inbox all cases
- [ ] Phase 2.4: read_message all cases
- [ ] Phase 2.5: subscribe_to_inbox all cases
- [ ] Phase 2.6: jmap passthrough all cases
- [ ] Phase 3: All end-to-end scenarios
- [ ] Phase 4: Error handling verified
- [ ] Phase 5: Python parity confirmed
