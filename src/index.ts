#!/usr/bin/env node
/**
 * MailPal MCP server v2 -- Progressive disclosure gateway.
 *
 * Two gateway tools: `mailpal` (email) and `oneid` (identity).
 * Each accepts `operation` and `params`; call with operation="readme" for docs.
 *
 * Replaces the 24 individual tool registrations from v1 with 2 gateway tools,
 * reducing idle context cost from ~4,000 tokens to ~120 tokens per server.
 *
 * Delegates to the `1id` Node.js SDK for all cryptographic operations.
 * The SDK handles TPM authentication, MIME assembly, attestation computation,
 * header injection, and direct SMTP submission.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as fs from "node:fs";
import * as path from "node:path";
import oneid, {
  type MailpalSendOptions,
  type MailpalActivateOptions,
  type IdentityProofBundle,
} from "1id";

const MAILPAL_REST_API_BASE_URL = process.env.MAILPAL_API_URL ?? "https://mailpal.com/api/v1";
const MAILPAL_BEARER_AUTH_TOKEN = process.env.MAILPAL_TOKEN ?? "";

let inbox_sse_abort_controller: AbortController | null = null;
let subscribed_inbox_resource_uri: string | null = null;
let bearer_token_for_active_sse_inbox_connection: string = "";
let registered_email_arrival_callbacks: Array<Record<string, unknown>> = [];

const _ATTESTATION_MODE_MCP_INTEGER_TO_SDK_STRING: Record<number, MailpalSendOptions["attestation_mode"]> = {
  0: "none",
  1: "direct",
  2: "sd-jwt",
  3: "both",
};


// ========================================================================
// Known operations and their accepted parameter names
// ========================================================================

const _MAILPAL_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES: Record<string, Set<string>> = {
  "readme": new Set(),
  "activate_account": new Set(["challenge_token", "challenge_answer", "display_name"]),
  "send": new Set([
    "to", "subject", "text", "html", "cc", "bcc", "from_address",
    "from_display_name", "reply_to", "in_reply_to", "references",
    "attachments", "attestation_mode", "output",
    "smtp_host", "smtp_port", "smtp_username", "smtp_password",
    "smtp_domain", "smtp_security", "smtp_envelope_from",
  ]),
  "check_inbox": new Set(["limit", "offset", "unread_only"]),
  "read_message": new Set(["message_id"]),
  "subscribe": new Set(),
  "wait_for_email": new Set(["timeout_seconds"]),
  "register_callback": new Set(["webhook_url", "webhook_method", "webhook_headers"]),
  "unregister_callback": new Set(["callback_id"]),
  "send_raw": new Set([
    "rfc5322_base64", "to",
    "smtp_host", "smtp_port", "smtp_domain", "smtp_security",
    "smtp_username", "smtp_password", "smtp_envelope_from",
  ]),
  "search": new Set([
    "query", "from_address", "to_address", "subject",
    "since", "before", "has_attachment", "limit",
  ]),
  "delete": new Set(["message_id", "message_ids", "permanent"]),
  "move": new Set(["message_id", "message_ids", "to_folder"]),
  "jmap": new Set(["method_calls", "using"]),
};

const _MAILPAL_REQUIRED_PARAMS_PER_OPERATION: Record<string, Set<string>> = {
  "send": new Set(["to", "subject"]),
  "read_message": new Set(["message_id"]),
  "register_callback": new Set(["webhook_url"]),
  "unregister_callback": new Set(["callback_id"]),
  "send_raw": new Set(["rfc5322_base64", "to"]),
  "search": new Set(),
  "delete": new Set(),
  "move": new Set(["to_folder"]),
  "jmap": new Set(["method_calls"]),
};

const _ONEID_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES: Record<string, Set<string>> = {
  "readme": new Set(),
  "get_or_create_identity": new Set(["display_name", "operator_email", "requested_handle", "get_only"]),
  "status": new Set(),
  "detect_hardware": new Set(),
  "get_bearer_token": new Set(),
  "sign_challenge": new Set(["nonce_hex"]),
  "verify_peer": new Set(["nonce_hex", "proof_bundle_json"]),
  "list_credential_pointers": new Set(["agent_id"]),
  "generate_consent_token": new Set(["issuer_id", "credential_type", "valid_for_seconds"]),
  "set_pointer_visibility": new Set(["pointer_id", "publicly_visible"]),
  "remove_pointer": new Set(["pointer_id"]),
  "list_devices": new Set(),
  "add_device": new Set(["device_type", "existing_device_fingerprint", "existing_device_type"]),
  "lock_hardware": new Set(),
  "burn_device": new Set(["device_fingerprint", "device_type", "co_device_fingerprint", "co_device_type", "reason"]),
  "request_burn": new Set(["device_fingerprint", "device_type", "reason"]),
  "confirm_burn": new Set(["token_id", "co_device_signature_b64", "co_device_fingerprint", "co_device_type"]),
};

const _ONEID_REQUIRED_PARAMS_PER_OPERATION: Record<string, Set<string>> = {
  "sign_challenge": new Set(["nonce_hex"]),
  "verify_peer": new Set(["nonce_hex", "proof_bundle_json"]),
  "generate_consent_token": new Set(["issuer_id", "credential_type"]),
  "set_pointer_visibility": new Set(["pointer_id", "publicly_visible"]),
  "remove_pointer": new Set(["pointer_id"]),
  "burn_device": new Set(["device_fingerprint", "device_type", "co_device_fingerprint", "co_device_type"]),
  "request_burn": new Set(["device_fingerprint", "device_type"]),
  "confirm_burn": new Set(["token_id", "co_device_signature_b64", "co_device_fingerprint", "co_device_type"]),
};


// ========================================================================
// MCP server instance
// ========================================================================

const mailpal_mcp_server_instance = new McpServer({
  name: "mailpal",
  version: "1.1.1",
}, {
  capabilities: {
    logging: {},
    resources: { subscribe: true },
  },
  instructions:
    "MailPal: email + identity for AI agents with hardware attestation. " +
    "Two tools: mailpal (email) and oneid (identity). " +
    "Call either with operation=\"readme\" for full documentation.",
});


// ========================================================================
// Utility functions
// ========================================================================

function _format_as_mcp_text_content(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

function _format_as_mcp_json_content(data: unknown) {
  return _format_as_mcp_text_content(JSON.stringify(data, null, 2));
}


// ========================================================================
// REST API helper (for tools not yet backed by SDK)
// ========================================================================

async function send_authenticated_request_to_mailpal_rest_api(
  api_endpoint_path: string,
  http_method: "GET" | "POST" = "GET",
  json_request_body?: Record<string, unknown>,
  url_query_parameters?: Record<string, string>,
  bearer_token_for_this_request?: string,
): Promise<Record<string, unknown>> {
  const full_request_url = new URL(`${MAILPAL_REST_API_BASE_URL}${api_endpoint_path}`);
  if (url_query_parameters) {
    for (const [param_name, param_value] of Object.entries(url_query_parameters)) {
      full_request_url.searchParams.set(param_name, param_value);
    }
  }

  const effective_bearer_token = bearer_token_for_this_request || MAILPAL_BEARER_AUTH_TOKEN;
  const http_request_headers: Record<string, string> = {
    "Accept": "application/json",
    "User-Agent": "mailpal-mcp-node/1.1.1",
  };
  if (effective_bearer_token) {
    http_request_headers["Authorization"] = `Bearer ${effective_bearer_token}`;
  }
  if (json_request_body) {
    http_request_headers["Content-Type"] = "application/json";
  }

  const http_response = await fetch(full_request_url.toString(), {
    method: http_method,
    headers: http_request_headers,
    body: json_request_body ? JSON.stringify(json_request_body) : undefined,
  });

  const parsed_response_json = await http_response.json() as Record<string, unknown>;

  if (!http_response.ok) {
    const error_field = (parsed_response_json as { error?: string | { message?: string } }).error;
    const human_readable_error_description =
      typeof error_field === "string"
        ? error_field
        : (error_field as { message?: string })?.message ?? `HTTP ${http_response.status}`;
    throw new Error(`MailPal API error: ${human_readable_error_description}`);
  }

  return parsed_response_json;
}


// ========================================================================
// Readme documentation generators
// ========================================================================

function _generate_mailpal_readme_documentation_text(): string {
  return `# MailPal -- Email for AI Agents

## Quick Start
1. mailpal(operation="activate_account") -- get your @mailpal.com address
2. mailpal(operation="send", params={"to": ["user@example.com"], "subject": "Hello", "text": "Hi!"})
3. mailpal(operation="check_inbox") -- check for received mail

## About Attestation (IMPORTANT)

Every email you send through MailPal automatically includes cryptographic
attestation headers (Hardware-Attestation and Hardware-Trust-Proof) that prove
YOUR agent identity composed the message. This is the core purpose of MailPal.

Recipients (and their mail servers) can verify these headers to confirm the
email was machine-generated and by which specific agent. This works regardless
of what the From address says.

**Never set attestation_mode=0 unless the human operator explicitly requests it.**
Disabling attestation defeats the purpose of the system and makes your emails
indistinguishable from forgeries.

## Sending on behalf of a human operator

Agents often need to send email that appears to come from their human operator
(e.g. From: "Chris Drake" <cnd@1id.com>) while the attestation proves the
agent composed it. This is the intended use case.

To send on behalf of another account:
  - Set from_address to the operator's email (appears in From header)
  - Set from_display_name to the operator's name
  - Set smtp_username + smtp_password to the account authorized to relay
  - Set reply_to to the operator's email (so replies go to them)
  - Attestation is automatic: headers prove your agent identity composed it

The From header shows who the email is "from" to recipients.
The SMTP credentials determine who is authorized to relay.
The attestation headers prove which agent actually composed it.
These three can all be different, and that is by design.

## Operations

### activate_account
Create a @mailpal.com email account (2-phase Proof-of-Intelligence challenge).
Phase 1 (no params): returns a challenge prompt the agent must solve.
Phase 2 (submit answer): provide challenge_token + challenge_answer.
Idempotent: returns existing account if already activated.

Optional params:
  challenge_token: str    -- Token from Phase 1 (Phase 2 only)
  challenge_answer: str   -- Your answer to the challenge (Phase 2 only)
  display_name: str       -- Friendly name for the account

### send
Send email with hardware attestation (ON by default).

Required params:
  to: list[str]           -- Recipient addresses
  subject: str            -- Subject line

Optional params:
  text: str               -- Plain text body (at least one of text/html needed)
  html: str               -- HTML body
  cc: list[str]           -- CC recipients
  bcc: list[str]          -- BCC recipients
  from_address: str       -- Sender address (default: your @mailpal.com)
  from_display_name: str  -- Display name for From header
  reply_to: str           -- Reply-To address
  in_reply_to: str        -- Message-ID for threading
  references: str         -- Thread Message-ID chain (space-separated)
  attachments: list       -- File attachments (see below)
  attestation_mode: int   -- 3=both (default), 2=SD-JWT, 1=direct, 0=none
  output: str             -- "send" (default), "rfc5322", or "rfc5322_base64"
  smtp_host: str          -- SMTP host or IP (default: smtp.mailpal.com)
                             Accepts hostname, IPv4, or IPv6 in [brackets]
  smtp_port: int          -- SMTP port (default: based on smtp_security)
  smtp_username: str      -- SMTP auth username (also used as envelope sender)
  smtp_password: str      -- SMTP auth password
  smtp_domain: str        -- Domain for MX auto-discovery (alternative to smtp_host)
  smtp_security: str      -- "starttls" (default/587), "tls" (SMTPS/465), "none" (25)
  smtp_envelope_from: str -- Explicit SMTP MAIL FROM override

When output="rfc5322" or "rfc5322_base64":
  The message is assembled and signed but NOT delivered via SMTP.
  The complete RFC 5322 message is returned so you can deliver it
  through your own SMTP server, save to a file, or process further.
  Attestation headers prove your hardware identity regardless of
  which SMTP server actually delivers the message.

Attachment format:
  {"file_path": "/path/to/file"}              -- read from disk
  {"content_base64": "...", "filename": "x"}  -- provide content directly
  Optional keys: content_type, inline, content_id

### send_raw
Deliver a pre-assembled RFC 5322 message via SMTP.
Use this after output="rfc5322_base64" when you need to deliver
through a different SMTP server than the one used for attestation signing.

Required params:
  rfc5322_base64: str     -- Complete RFC 5322 message, base64-encoded
  to: list[str]           -- Envelope recipient addresses

Optional params:
  smtp_host: str          -- SMTP host or IP (default: smtp.mailpal.com)
                             Accepts hostname, IPv4, or IPv6 in [brackets]
  smtp_port: int          -- SMTP port (default: based on smtp_security)
  smtp_domain: str        -- Domain for MX auto-discovery
  smtp_security: str      -- "starttls" (default/587), "tls" (SMTPS/465), "none" (25)
  smtp_username: str      -- SMTP auth username
  smtp_password: str      -- SMTP auth password
  smtp_envelope_from: str -- Explicit SMTP MAIL FROM address

### search
Search for emails by text, sender, recipient, subject, date range, or attachments.

Optional params:
  query: str              -- Full-text search
  from_address: str       -- Filter by sender
  to_address: str         -- Filter by recipient
  subject: str            -- Filter by subject substring
  since: str              -- ISO 8601 date (messages after this)
  before: str             -- ISO 8601 date (messages before this)
  has_attachment: bool    -- Filter for messages with attachments
  limit: int              -- Max results (default: 20, max: 100)

### delete
Delete or trash emails.

Params (provide message_id or message_ids):
  message_id: str         -- Single message ID to delete
  message_ids: list[str]  -- Multiple message IDs to delete
  permanent: bool         -- True = permanent delete, False = move to Trash (default)

### move
Move emails to a folder.

Required params:
  to_folder: str          -- Target folder name (e.g. "Archive", "Trash", "INBOX")

Params (provide message_id or message_ids):
  message_id: str         -- Single message ID to move
  message_ids: list[str]  -- Multiple message IDs to move

### check_inbox
List inbox messages (sender, subject, date).

Optional params:
  limit: int              -- Max messages (default: 20)
  offset: int             -- Pagination offset (default: 0)
  unread_only: bool       -- Only unread messages (default: false)

### read_message
Read the full content of a specific email message.

Required params:
  message_id: str         -- Message ID from check_inbox

### subscribe
Subscribe to real-time new-mail SSE notifications.
No params. Enables wait_for_email and webhook callbacks.

### wait_for_email
Block until new email arrives or timeout. Requires subscribe first.

Optional params:
  timeout_seconds: int    -- Max wait (1-3600, default: 300)

### register_callback
Register a webhook URL for new-email notifications. Requires subscribe first.

Required params:
  webhook_url: str        -- HTTPS URL to receive POST payloads

Optional params:
  webhook_method: str     -- HTTP method (default: "POST")
  webhook_headers: dict   -- Extra HTTP headers for the webhook

### unregister_callback
Remove a registered webhook.

Required params:
  callback_id: str        -- ID from register_callback, or "all" to remove all

### jmap
Raw JMAP method calls (full RFC 8620/8621).

Required params:
  method_calls: list      -- JMAP method call triples

Optional params:
  using: list[str]        -- JMAP capabilities (default: core + mail)

Common JMAP patterns:
  Delete: [["Email/set", {"destroy": ["id1"]}, "d1"]]
  Move:   [["Email/set", {"update": {"id1": {"mailboxIds": {"folder": true}}}}, "m1"]]
  Read:   [["Email/set", {"update": {"id1": {"keywords/$seen": true}}}, "r1"]]
  Search: [["Email/query", {"filter": {"text": "invoice"}, "limit": 20}, "s1"]]`;
}


function _generate_oneid_readme_documentation_text(): string {
  return `# 1ID -- Hardware-Anchored Identity for AI Agents

## Quick Start
1. oneid(operation="get_or_create_identity") -- enroll or recover your identity
2. oneid(operation="status") -- full identity + services picture
3. oneid(operation="detect_hardware") -- discover locally-present hardware

## Operations

### get_or_create_identity
Enroll a new identity or retrieve your existing one.
Auto-detects hardware (TPM, YubiKey, Secure Enclave) and enrolls at highest tier.
If already enrolled, returns existing identity instantly (no network call).

Optional params:
  display_name: str          -- Friendly name (e.g. "Clawdia", "Sparky")
  operator_email: str        -- Human contact for handle purchases / recovery
  requested_handle: str      -- Vanity handle (random handles are free)
  get_only: bool             -- If true, never create new identity

Trust tiers (highest to lowest):
  sovereign (TPM) > portable (YubiKey) > enclave (SE) > virtual (vTPM) > declared (software)

### status
Full identity + connected services + operator guidance.
Cached for 5 minutes. Recommended for context recovery after restarts.
No params.

### detect_hardware
Discover physically-present hardware security modules (TPM, YubiKey, Secure Enclave).
Different from list_devices (which shows already-enrolled server-side devices).
Use this to see what hardware is available for enrollment or upgrade.
No params.

### get_bearer_token
Get an OAuth2 Bearer token (signed JWT with identity claims).
Cached and auto-refreshed. Use for authenticating with external APIs.
No params.

### sign_challenge
Prove your hardware identity by signing a verifier-provided nonce.
Step 2 of 3 in peer-to-peer identity verification.

Required params:
  nonce_hex: str             -- Verifier's nonce as hex string (64+ hex chars)

### verify_peer
Verify another agent's identity proof bundle. Offline after first trust root fetch.
Step 3 of 3 in peer-to-peer identity verification.

Required params:
  nonce_hex: str             -- The original nonce you sent to the prover (hex)
  proof_bundle_json: str     -- JSON proof bundle from the prover's sign_challenge

### list_credential_pointers
List credential pointers for an identity.

Optional params:
  agent_id: str              -- Another agent's ID (omit for your own pointers)

### generate_consent_token
Authorize a credential authority to register a credential pointer.

Required params:
  issuer_id: str             -- DID/URI of the authority
  credential_type: str       -- e.g. "ceh-certification", "degree"

Optional params:
  valid_for_seconds: int     -- Token validity (60-604800, default: 86400)

### set_pointer_visibility
Toggle a credential pointer between public and private.

Required params:
  pointer_id: str            -- The pointer to update (prefix: cp-)
  publicly_visible: bool     -- true=public, false=private

### remove_pointer
Soft-delete a credential pointer (preserves audit trail).

Required params:
  pointer_id: str            -- The pointer to remove (prefix: cp-)

### list_devices
List all hardware devices (active and burned) bound to this identity.
No params.

### add_device
Add a new hardware device to this identity.
Path 1: Declared -> hardware upgrade (auto-detects, no co-location needed).
Path 2: Hardware -> hardware binding (requires existing device info).

Optional params:
  device_type: str                    -- "tpm" or "piv" (auto-detected if omitted)
  existing_device_fingerprint: str    -- For hardware-to-hardware binding
  existing_device_type: str           -- "tpm" or "piv" (for binding)

### lock_hardware
IRREVERSIBLE: Permanently lock identity to its single active device.
No new devices can be added, existing device cannot be burned.
Preconditions: hardware-tier, exactly 1 active device.
No params.

### burn_device
IRREVERSIBLE: Permanently retire a device. Requires co-device co-signature.

Required params:
  device_fingerprint: str    -- Device to burn
  device_type: str           -- "tpm" or "piv"
  co_device_fingerprint: str -- Co-signing device fingerprint
  co_device_type: str        -- "tpm" or "piv"

Optional params:
  reason: str                -- e.g. "migrated to new hardware"

### request_burn
Async burn step 1/2: get a confirmation token (valid 5 minutes).

Required params:
  device_fingerprint: str    -- Device to burn
  device_type: str           -- "tpm" or "piv"

Optional params:
  reason: str                -- Burn reason

### confirm_burn
Async burn step 2/2: confirm with co-device signature.

Required params:
  token_id: str              -- Token from request_burn
  co_device_signature_b64: str -- Base64-encoded co-device signature
  co_device_fingerprint: str -- Co-signing device fingerprint
  co_device_type: str        -- "tpm" or "piv"`;
}


// ========================================================================
// Error formatting and validation
// ========================================================================

function _format_gateway_error_response_as_json(
  error_code: string,
  error_message: string,
  fix_instruction: string,
  readme_documentation_text: string,
  example?: Record<string, unknown>,
): string {
  const response: Record<string, unknown> = {
    error: true,
    error_code,
    error_message,
    fix: fix_instruction,
    full_documentation: readme_documentation_text,
  };
  if (example !== undefined) {
    response["example"] = example;
  }
  return JSON.stringify(response, null, 2);
}


function _find_closest_matching_operation_names_by_similarity(
  unknown_operation_name: string,
  known_operation_names: string[],
  max_suggestions: number = 3,
): string[] {
  const matches: string[] = [];
  for (const known_name of known_operation_names) {
    if (known_name.startsWith(unknown_operation_name)
        || unknown_operation_name.startsWith(known_name)
        || unknown_operation_name.includes(known_name)
        || known_name.includes(unknown_operation_name)) {
      matches.push(known_name);
    }
  }
  if (matches.length === 0) {
    for (const known_name of known_operation_names) {
      let common_chars = 0;
      for (let i = 0; i < Math.min(unknown_operation_name.length, known_name.length); i++) {
        if (unknown_operation_name[i] === known_name[i]) { common_chars++; }
      }
      if (common_chars >= unknown_operation_name.length * 0.4) {
        matches.push(known_name);
      }
    }
  }
  return matches.slice(0, max_suggestions);
}


function _validate_params_and_return_error_json_if_invalid(
  params: Record<string, unknown>,
  operation_name: string,
  known_param_names: Set<string>,
  required_param_names: Set<string>,
  readme_documentation_text: string,
  gateway_name: string,
): string | null {
  const unknown_param_names = Object.keys(params).filter(k => !known_param_names.has(k));
  if (unknown_param_names.length > 0) {
    return _format_gateway_error_response_as_json(
      "unknown_param",
      `Unknown parameter(s) for '${operation_name}': ${JSON.stringify(unknown_param_names.sort())}`,
      `Accepted parameters for '${operation_name}': ` +
        `${known_param_names.size > 0 ? JSON.stringify([...known_param_names].sort()) : "(none)"}. ` +
        `Call ${gateway_name}(operation="readme") for full documentation.`,
      readme_documentation_text,
    );
  }

  const missing_required: string[] = [];
  for (const param_name of required_param_names) {
    if (!(param_name in params) || params[param_name] === null || params[param_name] === undefined) {
      missing_required.push(param_name);
    }
  }
  if (missing_required.length > 0) {
    return _format_gateway_error_response_as_json(
      "missing_required_param",
      `Missing required parameter(s) for '${operation_name}': ${JSON.stringify(missing_required.sort())}`,
      `Include all required parameters. Call ${gateway_name}(operation="readme") for details.`,
      readme_documentation_text,
    );
  }

  return null;
}


// ========================================================================
// MIME type guessing for attachments
// ========================================================================

const _COMMON_FILE_EXTENSION_TO_MIME_TYPE: Record<string, string> = {
  ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
  ".gif": "image/gif", ".webp": "image/webp", ".svg": "image/svg+xml",
  ".pdf": "application/pdf", ".doc": "application/msword",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xls": "application/vnd.ms-excel",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".ppt": "application/vnd.ms-powerpoint",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  ".zip": "application/zip", ".gz": "application/gzip",
  ".tar": "application/x-tar", ".7z": "application/x-7z-compressed",
  ".mp3": "audio/mpeg", ".wav": "audio/wav", ".mp4": "video/mp4",
  ".txt": "text/plain", ".csv": "text/csv", ".html": "text/html",
  ".json": "application/json", ".xml": "application/xml",
};

function _guess_mime_type_from_filename(filename: string): string {
  const ext = path.extname(filename).toLowerCase();
  return _COMMON_FILE_EXTENSION_TO_MIME_TYPE[ext] ?? "application/octet-stream";
}


// ========================================================================
// SSE / background notification machinery
// ========================================================================

async function _execute_registered_email_arrival_callbacks_on_new_mail(event_data: string): Promise<void> {
  for (const callback of registered_email_arrival_callbacks) {
    try {
      if (callback["callback_type"] === "webhook" && callback["webhook_url"]) {
        const webhook_payload = {
          event: "new_email",
          callback_id: callback["callback_id"],
          uri: subscribed_inbox_resource_uri ?? "mailpal://inbox",
          timestamp: Date.now(),
          raw_event: event_data,
        };
        await fetch(callback["webhook_url"] as string, {
          method: (callback["webhook_method"] as string) ?? "POST",
          headers: {
            "Content-Type": "application/json",
            ...((callback["webhook_headers"] as Record<string, string>) ?? {}),
          },
          body: JSON.stringify(webhook_payload),
          signal: AbortSignal.timeout(10_000),
        });
      }
    } catch {
      /* best effort */
    }
  }
}


let pending_inbox_wait_resolvers: Array<{ resolve: (value: string) => void }> = [];

async function _start_background_sse_listener_for_inbox_event_notifications(): Promise<void> {
  if (inbox_sse_abort_controller) {
    inbox_sse_abort_controller.abort();
  }
  inbox_sse_abort_controller = new AbortController();

  const effective_sse_token = bearer_token_for_active_sse_inbox_connection || MAILPAL_BEARER_AUTH_TOKEN;

  (async () => {
    let reconnect_delay_ms = 1000;
    while (!inbox_sse_abort_controller!.signal.aborted) {
      try {
        const sse_response = await fetch(`${MAILPAL_REST_API_BASE_URL}/inbox/events`, {
          headers: {
            "Authorization": `Bearer ${effective_sse_token}`,
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
          },
          signal: inbox_sse_abort_controller!.signal,
        });

        if (!sse_response.ok || !sse_response.body) { break; }

        reconnect_delay_ms = 1000;
        const reader = sse_response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let current_event_type = "";
        let current_data_lines: string[] = [];

        while (true) {
          const { done, value } = await reader.read();
          if (done) { break; }
          buffer += decoder.decode(value, { stream: true });

          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";

          for (const raw_line of lines) {
            if (raw_line.startsWith("event:")) {
              current_event_type = raw_line.substring(6).trim();
            } else if (raw_line.startsWith("data:")) {
              current_data_lines.push(raw_line.substring(5).trim());
            } else if (raw_line.startsWith(":")) {
              /* comment, ignore */
            } else if (raw_line.trim() === "") {
              if (current_data_lines.length > 0) {
                const event_type = current_event_type || "state_change";
                const event_data = current_data_lines.join("\n");

                if (["state_change", "StateChange", "state"].includes(event_type)) {
                  _execute_registered_email_arrival_callbacks_on_new_mail(event_data);

                  for (const waiter of pending_inbox_wait_resolvers) {
                    waiter.resolve(event_data);
                  }
                  pending_inbox_wait_resolvers = [];
                }
              }
              current_event_type = "";
              current_data_lines = [];
            }
          }
        }
      } catch (err: unknown) {
        if (inbox_sse_abort_controller!.signal.aborted) { return; }
        await new Promise(r => setTimeout(r, reconnect_delay_ms));
        reconnect_delay_ms = Math.min(reconnect_delay_ms * 2, 30_000);
      }
    }
  })();
}


// ========================================================================
// Mailpal operation handlers
// ========================================================================

async function _handle_mailpal_send_email_operation_with_output_mode_support(
  params: Record<string, unknown>,
  readme_text: string,
): Promise<string> {
  const output_mode = (params["output"] as string) ?? "send";
  if (!["send", "rfc5322", "rfc5322_base64"].includes(output_mode)) {
    return _format_gateway_error_response_as_json(
      "invalid_param_value",
      `Invalid output value: '${output_mode}'. Must be 'send', 'rfc5322', or 'rfc5322_base64'.`,
      "Use output='send' (default, delivers via SMTP), " +
        "'rfc5322' (returns message text), or " +
        "'rfc5322_base64' (returns base64-encoded message).",
      readme_text,
    );
  }

  const attestation_mode_integer = (params["attestation_mode"] as number) ?? 3;
  if (typeof attestation_mode_integer !== "number" || ![0, 1, 2, 3].includes(attestation_mode_integer)) {
    return _format_gateway_error_response_as_json(
      "invalid_param_value",
      `Invalid attestation_mode: ${JSON.stringify(attestation_mode_integer)}. Must be 0, 1, 2, or 3.`,
      "3=both (default), 2=SD-JWT only, 1=direct CMS only, 0=none.",
      readme_text,
    );
  }

  const sdk_attestation_mode_string = _ATTESTATION_MODE_MCP_INTEGER_TO_SDK_STRING[attestation_mode_integer] ?? "both";
  const deliver_via_smtp = (output_mode === "send");

  let sdk_attachments: Array<{
    filename: string;
    content_base64: string;
    content_type: string;
    inline?: boolean;
    content_id?: string;
  }> | undefined;

  const raw_attachments = params["attachments"] as Array<Record<string, unknown>> | undefined;
  if (raw_attachments && raw_attachments.length > 0) {
    sdk_attachments = [];
    for (const attachment_spec of raw_attachments) {
      let encoded_content: string;
      let resolved_filename: string;

      if (attachment_spec["file_path"]) {
        const file_path = path.resolve(attachment_spec["file_path"] as string);
        if (!fs.existsSync(file_path)) {
          throw new Error(`Attachment file not found: ${file_path}`);
        }
        const file_bytes = fs.readFileSync(file_path);
        encoded_content = file_bytes.toString("base64");
        resolved_filename = (attachment_spec["filename"] as string) ?? path.basename(file_path);
      } else if (attachment_spec["content_base64"]) {
        encoded_content = attachment_spec["content_base64"] as string;
        resolved_filename = (attachment_spec["filename"] as string) ?? "attachment";
      } else {
        throw new Error("Each attachment must have either file_path or content_base64");
      }

      sdk_attachments.push({
        filename: resolved_filename,
        content_base64: encoded_content,
        content_type: (attachment_spec["content_type"] as string) ?? _guess_mime_type_from_filename(resolved_filename),
        inline: attachment_spec["inline"] as boolean | undefined,
        content_id: attachment_spec["content_id"] as string | undefined,
      });
    }
  }

  const send_options: MailpalSendOptions = {
    to: params["to"] as string[],
    subject: params["subject"] as string,
    text_body: params["text"] as string | undefined,
    html_body: params["html"] as string | undefined,
    cc: params["cc"] as string[] | undefined,
    bcc: params["bcc"] as string[] | undefined,
    from_address: params["from_address"] as string | undefined,
    from_display_name: params["from_display_name"] as string | undefined,
    reply_to: params["reply_to"] as string | undefined,
    in_reply_to: params["in_reply_to"] as string | undefined,
    references: params["references"] as string | undefined,
    attachments: sdk_attachments,
    attestation_mode: sdk_attestation_mode_string,
    smtp_host: params["smtp_host"] as string | undefined,
    smtp_port: params["smtp_port"] as number | undefined,
    smtp_username: params["smtp_username"] as string | undefined,
    smtp_password: params["smtp_password"] as string | undefined,
    smtp_domain: params["smtp_domain"] as string | undefined,
    smtp_security: params["smtp_security"] as "starttls" | "tls" | "none" | undefined,
    smtp_envelope_from: params["smtp_envelope_from"] as string | undefined,
    deliver: deliver_via_smtp,
  };

  const result = await oneid.mailpal.send(send_options);

  if (output_mode === "send") {
    return JSON.stringify(result, null, 2);
  }

  const result_dict: Record<string, unknown> = {
    message_id: result.message_id,
    from_address: result.from_address,
    attestation_headers_included: result.attestation_headers_included,
    contact_token_header_included: result.contact_token_header_included,
    sd_jwt_header_included: result.sd_jwt_header_included,
    direct_attestation_header_included: result.direct_attestation_header_included,
    delivered_via_smtp: false,
    output_mode,
  };

  if (output_mode === "rfc5322" && result.rfc5322_message_bytes) {
    result_dict["rfc5322_message"] = result.rfc5322_message_bytes.toString("utf-8");
  } else if (output_mode === "rfc5322_base64" && result.rfc5322_message_bytes) {
    result_dict["rfc5322_message_base64"] = result.rfc5322_message_bytes.toString("base64");
  }

  return JSON.stringify(result_dict, null, 2);
}


async function _handle_mailpal_send_raw_preassembled_message_operation(
  params: Record<string, unknown>,
  readme_text: string,
): Promise<string> {
  const raw_b64 = params["rfc5322_base64"] as string;
  if (!raw_b64) {
    return _format_gateway_error_response_as_json(
      "missing_param",
      "rfc5322_base64 is required.",
      "Provide the complete RFC 5322 message as a base64-encoded string.",
      readme_text,
    );
  }

  let message_bytes: Buffer;
  try {
    message_bytes = Buffer.from(raw_b64, "base64");
  } catch (decode_error) {
    return _format_gateway_error_response_as_json(
      "invalid_param_value",
      `Failed to decode rfc5322_base64: ${decode_error}`,
      "Ensure the value is valid base64-encoded RFC 5322 message bytes.",
      readme_text,
    );
  }

  let recipient_list = params["to"] as string | string[];
  if (typeof recipient_list === "string") {
    recipient_list = [recipient_list];
  }

  const _security_to_default_port: Record<string, number> = { "starttls": 587, "tls": 465, "none": 25 };
  const effective_security = (params["smtp_security"] as string) ?? "starttls";
  const effective_host = (params["smtp_host"] as string) ?? "smtp.mailpal.com";
  const effective_port = (params["smtp_port"] as number) ?? _security_to_default_port[effective_security] ?? 587;
  const smtp_user = params["smtp_username"] as string | undefined;
  const smtp_pass = params["smtp_password"] as string | undefined;
  const effective_envelope_from = (params["smtp_envelope_from"] as string) ?? smtp_user;

  const _net = await import("node:net");
  const _tls = await import("node:tls");

  try {
    await new Promise<void>((resolve, reject) => {
      if (effective_security === "tls") {
        const socket = _tls.connect(
          { host: effective_host, port: effective_port, servername: effective_host, rejectUnauthorized: true, timeout: 30_000 },
          () => { /* connected */ },
        );
        setup_smtp_client(socket, smtp_user, smtp_pass, effective_envelope_from, recipient_list as string[], message_bytes, resolve, reject);
        socket.on("error", (err: Error) => reject(new Error(`SMTP TLS error: ${err.message}`)));
        socket.on("timeout", () => { socket.destroy(); reject(new Error("SMTP TLS timeout")); });
      } else {
        const socket = _net.createConnection({ host: effective_host, port: effective_port, timeout: 30_000 });
        const use_starttls = (effective_security === "starttls");
        setup_smtp_client_plain(socket, smtp_user, smtp_pass, effective_envelope_from, recipient_list as string[], message_bytes, use_starttls, _tls, effective_host, resolve, reject);
        socket.on("error", (err: Error) => reject(new Error(`SMTP error: ${err.message}`)));
        socket.on("timeout", () => { socket.destroy(); reject(new Error("SMTP timeout")); });
      }
    });
  } catch (smtp_error) {
    return JSON.stringify({ ok: false, error: String(smtp_error) });
  }

  return JSON.stringify({ ok: true, bytes_sent: message_bytes.length, recipients: recipient_list });
}

function setup_smtp_client(
  socket: import("node:tls").TLSSocket,
  smtp_user: string | undefined,
  smtp_pass: string | undefined,
  envelope_from: string | undefined,
  recipient_list: string[],
  message_bytes: Buffer,
  resolve: () => void,
  reject: (err: Error) => void,
): void {
  let response_buffer = "";
  let phase = "greeting";
  let command_queue: string[] = [];

  function send_cmd(cmd: string) { socket.write(cmd + "\r\n"); }

  function handle_response(code: number, line: string) {
    if (phase === "greeting") {
      if (code !== 220) { return reject(new Error(`SMTP greeting failed: ${line}`)); }
      phase = "ehlo"; send_cmd("EHLO oneid-sdk");
    } else if (phase === "ehlo") {
      if (code !== 250) { return reject(new Error(`SMTP EHLO failed: ${line}`)); }
      if (smtp_user && smtp_pass) {
        phase = "auth";
        const auth_str = Buffer.from(`\x00${smtp_user}\x00${smtp_pass}`).toString("base64");
        send_cmd(`AUTH PLAIN ${auth_str}`);
      } else {
        phase = "mail_from";
        send_cmd(`MAIL FROM:<${envelope_from ?? ""}>`);
      }
    } else if (phase === "auth") {
      if (code !== 235) { return reject(new Error(`SMTP auth failed: ${line}`)); }
      phase = "mail_from"; send_cmd(`MAIL FROM:<${envelope_from ?? smtp_user ?? ""}>`);
    } else if (phase === "mail_from") {
      if (code !== 250) { return reject(new Error(`SMTP MAIL FROM failed: ${line}`)); }
      phase = "rcpt_to"; command_queue = [...recipient_list];
      send_cmd(`RCPT TO:<${command_queue.shift()!}>`);
    } else if (phase === "rcpt_to") {
      if (code !== 250) { return reject(new Error(`SMTP RCPT TO failed: ${line}`)); }
      if (command_queue.length > 0) { send_cmd(`RCPT TO:<${command_queue.shift()!}>`); }
      else { phase = "data_cmd"; send_cmd("DATA"); }
    } else if (phase === "data_cmd") {
      if (code !== 354) { return reject(new Error(`SMTP DATA failed: ${line}`)); }
      phase = "data_done"; socket.write(message_bytes); socket.write(Buffer.from("\r\n.\r\n"));
    } else if (phase === "data_done") {
      if (code !== 250) { return reject(new Error(`SMTP rejected: ${line}`)); }
      phase = "quit"; send_cmd("QUIT");
    } else if (phase === "quit") {
      socket.destroy(); resolve();
    }
  }

  socket.on("data", (data: Buffer) => {
    response_buffer += data.toString("utf-8");
    while (response_buffer.includes("\r\n")) {
      const end = response_buffer.indexOf("\r\n");
      const line = response_buffer.substring(0, end);
      response_buffer = response_buffer.substring(end + 2);
      const code = parseInt(line.substring(0, 3), 10);
      if (line[3] !== "-") { handle_response(code, line); }
    }
  });
}

function setup_smtp_client_plain(
  socket: import("node:net").Socket,
  smtp_user: string | undefined,
  smtp_pass: string | undefined,
  envelope_from: string | undefined,
  recipient_list: string[],
  message_bytes: Buffer,
  use_starttls: boolean,
  _tls: typeof import("node:tls"),
  host: string,
  resolve: () => void,
  reject: (err: Error) => void,
): void {
  let response_buffer = "";
  let phase = "greeting";
  let command_queue: string[] = [];
  let secure_socket: import("node:tls").TLSSocket | null = null;

  function active_socket() { return secure_socket ?? socket; }
  function send_cmd(cmd: string) { active_socket().write(cmd + "\r\n"); }

  function handle_response(code: number, line: string) {
    if (phase === "greeting") {
      if (code !== 220) { return reject(new Error(`SMTP greeting failed: ${line}`)); }
      phase = "ehlo1"; send_cmd("EHLO oneid-sdk");
    } else if (phase === "ehlo1") {
      if (code !== 250) { return reject(new Error(`SMTP EHLO failed: ${line}`)); }
      if (use_starttls) {
        phase = "starttls"; send_cmd("STARTTLS");
      } else if (smtp_user && smtp_pass) {
        phase = "auth";
        const auth_str = Buffer.from(`\x00${smtp_user}\x00${smtp_pass}`).toString("base64");
        send_cmd(`AUTH PLAIN ${auth_str}`);
      } else {
        phase = "mail_from"; send_cmd(`MAIL FROM:<${envelope_from ?? ""}>`);
      }
    } else if (phase === "starttls") {
      if (code !== 220) { return reject(new Error(`SMTP STARTTLS failed: ${line}`)); }
      phase = "tls_upgrade";
      secure_socket = _tls.connect(
        { socket, servername: host, rejectUnauthorized: true },
        () => {
          phase = "ehlo2";
          secure_socket!.on("data", on_data);
          socket.removeAllListeners("data");
          send_cmd("EHLO oneid-sdk");
        },
      );
      secure_socket.on("error", (err: Error) => reject(new Error(`SMTP TLS error: ${err.message}`)));
    } else if (phase === "ehlo2") {
      if (code !== 250) { return reject(new Error(`SMTP EHLO after TLS failed: ${line}`)); }
      if (smtp_user && smtp_pass) {
        phase = "auth";
        const auth_str = Buffer.from(`\x00${smtp_user}\x00${smtp_pass}`).toString("base64");
        send_cmd(`AUTH PLAIN ${auth_str}`);
      } else {
        phase = "mail_from"; send_cmd(`MAIL FROM:<${envelope_from ?? ""}>`);
      }
    } else if (phase === "auth") {
      if (code !== 235) { return reject(new Error(`SMTP auth failed: ${line}`)); }
      phase = "mail_from"; send_cmd(`MAIL FROM:<${envelope_from ?? smtp_user ?? ""}>`);
    } else if (phase === "mail_from") {
      if (code !== 250) { return reject(new Error(`SMTP MAIL FROM failed: ${line}`)); }
      phase = "rcpt_to"; command_queue = [...recipient_list];
      send_cmd(`RCPT TO:<${command_queue.shift()!}>`);
    } else if (phase === "rcpt_to") {
      if (code !== 250) { return reject(new Error(`SMTP RCPT TO failed: ${line}`)); }
      if (command_queue.length > 0) { send_cmd(`RCPT TO:<${command_queue.shift()!}>`); }
      else { phase = "data_cmd"; send_cmd("DATA"); }
    } else if (phase === "data_cmd") {
      if (code !== 354) { return reject(new Error(`SMTP DATA failed: ${line}`)); }
      phase = "data_done"; active_socket().write(message_bytes); active_socket().write(Buffer.from("\r\n.\r\n"));
    } else if (phase === "data_done") {
      if (code !== 250) { return reject(new Error(`SMTP rejected: ${line}`)); }
      phase = "quit"; send_cmd("QUIT");
    } else if (phase === "quit") {
      active_socket().destroy(); resolve();
    }
  }

  function on_data(data: Buffer) {
    response_buffer += data.toString("utf-8");
    while (response_buffer.includes("\r\n")) {
      const end = response_buffer.indexOf("\r\n");
      const line = response_buffer.substring(0, end);
      response_buffer = response_buffer.substring(end + 2);
      const code = parseInt(line.substring(0, 3), 10);
      if (line[3] !== "-") { handle_response(code, line); }
    }
  }

  socket.on("data", on_data);
}


async function _handle_mailpal_search_emails_operation(params: Record<string, unknown>): Promise<string> {
  const jmap_filter: Record<string, unknown> = {};
  if (params["query"]) { jmap_filter["text"] = params["query"]; }
  if (params["from_address"]) { jmap_filter["from"] = params["from_address"]; }
  if (params["to_address"]) { jmap_filter["to"] = params["to_address"]; }
  if (params["subject"]) { jmap_filter["subject"] = params["subject"]; }
  if (params["since"]) { jmap_filter["after"] = params["since"]; }
  if (params["before"]) { jmap_filter["before"] = params["before"]; }
  if (params["has_attachment"] !== undefined) { jmap_filter["hasAttachment"] = params["has_attachment"]; }

  const result_limit = Math.min(Number(params["limit"] ?? 20), 100);

  const sdk_token = await oneid.get_token();
  const _jmap_account_id = "default";
  const method_calls = [
    ["Email/query", {
      accountId: _jmap_account_id,
      filter: jmap_filter,
      sort: [{ property: "receivedAt", isAscending: false }],
      limit: result_limit,
    }, "search_query"],
    ["Email/get", {
      accountId: _jmap_account_id,
      "#ids": { resultOf: "search_query", name: "Email/query", path: "/ids" },
      properties: ["id", "from", "to", "subject", "receivedAt", "preview", "hasAttachment", "size"],
    }, "search_get"],
  ];

  const api_response = await send_authenticated_request_to_mailpal_rest_api(
    "/jmap", "POST", {
      using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
      methodCalls: method_calls,
    }, undefined, sdk_token.access_token,
  );
  return JSON.stringify(api_response, null, 2);
}


async function _handle_mailpal_delete_emails_operation(params: Record<string, unknown>): Promise<string> {
  const message_ids_to_process: string[] = [...((params["message_ids"] as string[]) ?? [])];
  if (params["message_id"]) {
    message_ids_to_process.push(params["message_id"] as string);
  }

  if (message_ids_to_process.length === 0) {
    return JSON.stringify({ error: "Provide message_id or message_ids." });
  }

  const is_permanent_deletion = params["permanent"] === true;
  const sdk_token = await oneid.get_token();
  const _jmap_account_id = "default";

  if (is_permanent_deletion) {
    const api_response = await send_authenticated_request_to_mailpal_rest_api(
      "/jmap", "POST", {
        using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        methodCalls: [
          ["Email/set", { accountId: _jmap_account_id, destroy: message_ids_to_process }, "delete"],
        ],
      }, undefined, sdk_token.access_token,
    );
    return JSON.stringify(api_response, null, 2);
  }

  const trash_lookup_response = await send_authenticated_request_to_mailpal_rest_api(
    "/jmap", "POST", {
      using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
      methodCalls: [
        ["Mailbox/query", { accountId: _jmap_account_id, filter: { role: "trash" } }, "find_trash"],
        ["Mailbox/get", {
          accountId: _jmap_account_id,
          "#ids": { resultOf: "find_trash", name: "Mailbox/query", path: "/ids" },
          properties: ["id"],
        }, "get_trash"],
      ],
    }, undefined, sdk_token.access_token,
  );

  const trash_responses = (trash_lookup_response["methodResponses"] as unknown[][]) ?? [];
  let trash_mailbox_id: string | null = null;
  for (const entry of trash_responses) {
    if (entry[0] === "Mailbox/get") {
      const list = ((entry[1] as Record<string, unknown>)["list"] as Record<string, unknown>[]) ?? [];
      if (list.length > 0) { trash_mailbox_id = list[0]["id"] as string; }
    }
  }

  if (!trash_mailbox_id) {
    return JSON.stringify({ error: "Could not find Trash folder on this JMAP server." });
  }

  const email_updates: Record<string, unknown> = {};
  for (const msg_id of message_ids_to_process) {
    email_updates[msg_id] = { mailboxIds: { [trash_mailbox_id]: true } };
  }

  const api_response = await send_authenticated_request_to_mailpal_rest_api(
    "/jmap", "POST", {
      using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
      methodCalls: [
        ["Email/set", { accountId: _jmap_account_id, update: email_updates }, "trash_emails"],
      ],
    }, undefined, sdk_token.access_token,
  );
  return JSON.stringify(api_response, null, 2);
}


async function _handle_mailpal_move_emails_operation(
  params: Record<string, unknown>,
  readme_text: string,
): Promise<string> {
  const message_ids_to_move: string[] = [...((params["message_ids"] as string[]) ?? [])];
  if (params["message_id"]) {
    message_ids_to_move.push(params["message_id"] as string);
  }

  if (message_ids_to_move.length === 0) {
    return JSON.stringify({ error: "Provide message_id or message_ids." });
  }

  const target_folder_name = params["to_folder"] as string;
  const sdk_token = await oneid.get_token();
  const _jmap_account_id = "default";

  const friendly_name_to_jmap_role: Record<string, string> = {
    "trash": "trash", "deleted": "trash", "deleted items": "trash",
    "inbox": "inbox",
    "sent": "sent", "sent items": "sent", "sent mail": "sent",
    "drafts": "drafts", "draft": "drafts",
    "junk": "junk", "spam": "junk", "junk mail": "junk",
    "archive": "archive",
  };

  const all_mailboxes_response = await send_authenticated_request_to_mailpal_rest_api(
    "/jmap", "POST", {
      using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
      methodCalls: [
        ["Mailbox/get", { accountId: _jmap_account_id, properties: ["id", "name", "role"] }, "all_mailboxes"],
      ],
    }, undefined, sdk_token.access_token,
  );

  const mailbox_results = (all_mailboxes_response["methodResponses"] as unknown[][]) ?? [];
  let target_mailbox_id: string | null = null;
  const all_mailboxes = ((mailbox_results[0]?.[1] as Record<string, unknown>)?.["list"] as Record<string, unknown>[]) ?? [];

  const mapped_role = friendly_name_to_jmap_role[target_folder_name.toLowerCase()];
  if (mapped_role) {
    for (const mb of all_mailboxes) {
      if (mb["role"] === mapped_role) { target_mailbox_id = mb["id"] as string; break; }
    }
  }
  if (!target_mailbox_id) {
    const lower_target = target_folder_name.toLowerCase();
    for (const mb of all_mailboxes) {
      if ((mb["name"] as string).toLowerCase() === lower_target) { target_mailbox_id = mb["id"] as string; break; }
    }
  }

  if (!target_mailbox_id) {
    const available_names = all_mailboxes.map((mb) => mb["name"] as string).join(", ");
    return _format_gateway_error_response_as_json(
      "folder_not_found",
      `Folder '${target_folder_name}' not found.`,
      `Available folders: ${available_names}. You can also use common names like Trash, Inbox, Sent, Drafts, Junk, Archive.`,
      readme_text,
    );
  }

  const email_updates: Record<string, unknown> = {};
  for (const msg_id of message_ids_to_move) {
    email_updates[msg_id] = { mailboxIds: { [target_mailbox_id]: true } };
  }

  const api_response = await send_authenticated_request_to_mailpal_rest_api(
    "/jmap", "POST", {
      using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
      methodCalls: [
        ["Email/set", { accountId: _jmap_account_id, update: email_updates }, "move_emails"],
      ],
    }, undefined, sdk_token.access_token,
  );
  return JSON.stringify(api_response, null, 2);
}


async function _handle_mailpal_subscribe_to_inbox_operation(): Promise<string> {
  const sdk_token = await oneid.get_token();
  const effective_token = sdk_token.access_token;

  let agent_identifier_from_jwt_subject_claim = "unknown";
  try {
    let jwt_payload_segment = effective_token.split(".")[1];
    const padding_needed = 4 - (jwt_payload_segment.length % 4);
    if (padding_needed < 4) {
      jwt_payload_segment += "=".repeat(padding_needed);
    }
    const decoded_jwt_payload = JSON.parse(
      Buffer.from(jwt_payload_segment, "base64url").toString("utf-8"),
    );
    agent_identifier_from_jwt_subject_claim = decoded_jwt_payload["sub"] ?? "unknown";
  } catch {
    /* best effort */
  }

  subscribed_inbox_resource_uri = `mailpal://inbox/${agent_identifier_from_jwt_subject_claim}`;
  bearer_token_for_active_sse_inbox_connection = effective_token;

  await _start_background_sse_listener_for_inbox_event_notifications();

  return JSON.stringify({
    subscribed: true,
    uri: subscribed_inbox_resource_uri,
    transport: "stdio",
    message:
      "Listening for new mail. The MCP server will push notifications when " +
      "new email arrives. You can also call mailpal(operation=\"wait_for_email\") " +
      "to block until new mail, or poll mailpal(operation=\"check_inbox\") periodically.",
  }, null, 2);
}


async function _handle_mailpal_wait_for_email_operation(params: Record<string, unknown>): Promise<string> {
  if (!inbox_sse_abort_controller || !subscribed_inbox_resource_uri) {
    return JSON.stringify({
      received: false,
      error: "Not subscribed. Call mailpal(operation=\"subscribe\") first.",
    }, null, 2);
  }

  const timeout_seconds = Math.max(1, Math.min(Number(params["timeout_seconds"] ?? 300), 3600));

  try {
    const event_data = await Promise.race([
      new Promise<string>((resolve) => {
        pending_inbox_wait_resolvers.push({ resolve });
      }),
      new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error("timeout")), timeout_seconds * 1000);
      }),
    ]);

    return JSON.stringify({
      received: true,
      timed_out: false,
      event_data,
      message: "Mailbox state changed -- new mail likely arrived. Call mailpal(operation=\"check_inbox\") now.",
    }, null, 2);
  } catch {
    return JSON.stringify({
      received: false,
      timed_out: true,
      waited_seconds: timeout_seconds,
      message: "No new mail within timeout. Call again to keep waiting, or check inbox.",
    }, null, 2);
  }
}


async function _handle_mailpal_register_email_arrival_callback_operation(
  params: Record<string, unknown>,
): Promise<string> {
  if (!inbox_sse_abort_controller || !subscribed_inbox_resource_uri) {
    return JSON.stringify({
      registered: false,
      error: "Not subscribed. Call mailpal(operation=\"subscribe\") first.",
    }, null, 2);
  }

  const callback_id = `cb_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;

  const new_callback = {
    callback_id,
    callback_type: "webhook",
    webhook_url: params["webhook_url"],
    webhook_method: params["webhook_method"] ?? "POST",
    webhook_headers: params["webhook_headers"] ?? {},
    registered_at: Date.now(),
  };
  registered_email_arrival_callbacks.push(new_callback);

  return JSON.stringify({
    registered: true,
    callback_id,
    webhook_url: params["webhook_url"],
    total_registered_callbacks: registered_email_arrival_callbacks.length,
    message: "Webhook registered. It will receive POST payloads when new email arrives.",
  }, null, 2);
}


async function _handle_mailpal_unregister_email_arrival_callback_operation(
  params: Record<string, unknown>,
): Promise<string> {
  const callback_id = params["callback_id"] as string;

  if (callback_id === "all") {
    const removed_count = registered_email_arrival_callbacks.length;
    registered_email_arrival_callbacks = [];
    return JSON.stringify({
      removed: true,
      removed_count,
      message: `All ${removed_count} callback(s) removed.`,
    }, null, 2);
  }

  const index_to_remove = registered_email_arrival_callbacks.findIndex(
    cb => cb["callback_id"] === callback_id,
  );

  if (index_to_remove === -1) {
    return JSON.stringify({
      removed: false,
      error: `No callback found with id '${callback_id}'.`,
    }, null, 2);
  }

  registered_email_arrival_callbacks.splice(index_to_remove, 1);
  return JSON.stringify({
    removed: true,
    callback_id,
    remaining_callbacks: registered_email_arrival_callbacks.length,
    message: "Callback removed.",
  }, null, 2);
}


// ========================================================================
// Gateway tool: mailpal
// ========================================================================

mailpal_mcp_server_instance.tool(
  "mailpal",
  "Email for AI agents -- send, receive, manage email with hardware attestation (mailpal.com). Call with operation=\"readme\" for full documentation and available operations.",
  {
    operation: z.string().describe("The operation to perform (call with \"readme\" for documentation)"),
    params: z.record(z.unknown()).optional().describe("Parameters for the operation"),
  },
  async ({ operation, params }) => {
    const effective_params: Record<string, unknown> = params ?? {};
    const readme_text = _generate_mailpal_readme_documentation_text();
    const all_operation_names = Object.keys(_MAILPAL_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES);

    if (operation === "readme") {
      return _format_as_mcp_text_content(readme_text);
    }

    if (!(operation in _MAILPAL_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES)) {
      const suggestions = _find_closest_matching_operation_names_by_similarity(operation, all_operation_names);
      const suggestion_text = suggestions.length > 0 ? ` Did you mean: ${JSON.stringify(suggestions)}?` : "";
      return _format_as_mcp_text_content(_format_gateway_error_response_as_json(
        "unknown_operation",
        `Unknown operation '${operation}'.${suggestion_text}`,
        "Call mailpal(operation=\"readme\") for all available operations.",
        readme_text,
        { available_operations: all_operation_names },
      ));
    }

    const known_param_names = _MAILPAL_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES[operation];
    const required_param_names = _MAILPAL_REQUIRED_PARAMS_PER_OPERATION[operation] ?? new Set();

    const validation_error = _validate_params_and_return_error_json_if_invalid(
      effective_params, operation, known_param_names, required_param_names, readme_text, "mailpal",
    );
    if (validation_error !== null) {
      return _format_as_mcp_text_content(validation_error);
    }

    try {
      if (operation === "activate_account") {
        const activate_options: MailpalActivateOptions = {};
        if (effective_params["challenge_token"]) { activate_options.challenge_token = effective_params["challenge_token"] as string; }
        if (effective_params["challenge_answer"]) { activate_options.challenge_answer = effective_params["challenge_answer"] as string; }
        if (effective_params["display_name"]) { activate_options.display_name = effective_params["display_name"] as string; }
        const result = await oneid.mailpal.activate(activate_options);
        return _format_as_mcp_json_content(result);
      }

      if (operation === "send") {
        const result_text = await _handle_mailpal_send_email_operation_with_output_mode_support(effective_params, readme_text);
        return _format_as_mcp_text_content(result_text);
      }

      if (operation === "send_raw") {
        const result_text = await _handle_mailpal_send_raw_preassembled_message_operation(effective_params, readme_text);
        return _format_as_mcp_text_content(result_text);
      }

      if (operation === "search") {
        const result_text = await _handle_mailpal_search_emails_operation(effective_params);
        return _format_as_mcp_text_content(result_text);
      }

      if (operation === "delete") {
        const result_text = await _handle_mailpal_delete_emails_operation(effective_params);
        return _format_as_mcp_text_content(result_text);
      }

      if (operation === "move") {
        const result_text = await _handle_mailpal_move_emails_operation(effective_params, readme_text);
        return _format_as_mcp_text_content(result_text);
      }

      if (operation === "check_inbox") {
        const messages = await oneid.mailpal.inbox({
          limit: Number(effective_params["limit"] ?? 20),
          offset: Number(effective_params["offset"] ?? 0),
          unread_only: effective_params["unread_only"] === true,
        });
        return _format_as_mcp_json_content({ messages });
      }

      if (operation === "read_message") {
        const message_id = effective_params["message_id"] as string;
        const sdk_token = await oneid.get_token();
        const api_response = await send_authenticated_request_to_mailpal_rest_api(
          `/inbox/${encodeURIComponent(message_id)}`,
          "GET", undefined, undefined, sdk_token.access_token,
        );
        return _format_as_mcp_json_content(api_response);
      }

      if (operation === "subscribe") {
        const result_text = await _handle_mailpal_subscribe_to_inbox_operation();
        return _format_as_mcp_text_content(result_text);
      }

      if (operation === "wait_for_email") {
        const result_text = await _handle_mailpal_wait_for_email_operation(effective_params);
        return _format_as_mcp_text_content(result_text);
      }

      if (operation === "register_callback") {
        const result_text = await _handle_mailpal_register_email_arrival_callback_operation(effective_params);
        return _format_as_mcp_text_content(result_text);
      }

      if (operation === "unregister_callback") {
        const result_text = await _handle_mailpal_unregister_email_arrival_callback_operation(effective_params);
        return _format_as_mcp_text_content(result_text);
      }

      if (operation === "jmap") {
        const using = (effective_params["using"] as string[]) ?? [
          "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail",
        ];
        const sdk_token = await oneid.get_token();
        const api_response = await send_authenticated_request_to_mailpal_rest_api(
          "/jmap", "POST", {
            using,
            methodCalls: effective_params["method_calls"],
          }, undefined, sdk_token.access_token,
        );
        return _format_as_mcp_json_content(api_response);
      }

    } catch (operation_error) {
      return _format_as_mcp_text_content(_format_gateway_error_response_as_json(
        "operation_failed",
        `Operation '${operation}' failed: ${operation_error}`,
        "Check the error message and retry. Call mailpal(operation=\"readme\") for docs.",
        readme_text,
      ));
    }

    return _format_as_mcp_text_content(_format_gateway_error_response_as_json(
      "internal_error",
      `Operation '${operation}' is defined but has no handler.`,
      "This is a server bug. Please report it.",
      readme_text,
    ));
  },
);


// ========================================================================
// Gateway tool: oneid
// ========================================================================

mailpal_mcp_server_instance.tool(
  "oneid",
  "Hardware-anchored identity for AI agents (1id.com). Manage identity, devices, peer verification, and credentials. Call with operation=\"readme\" for full documentation.",
  {
    operation: z.string().describe("The operation to perform (call with \"readme\" for documentation)"),
    params: z.record(z.unknown()).optional().describe("Parameters for the operation"),
  },
  async ({ operation, params }) => {
    const effective_params: Record<string, unknown> = params ?? {};
    const readme_text = _generate_oneid_readme_documentation_text();
    const all_operation_names = Object.keys(_ONEID_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES);

    if (operation === "readme") {
      return _format_as_mcp_text_content(readme_text);
    }

    if (!(operation in _ONEID_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES)) {
      const suggestions = _find_closest_matching_operation_names_by_similarity(operation, all_operation_names);
      const suggestion_text = suggestions.length > 0 ? ` Did you mean: ${JSON.stringify(suggestions)}?` : "";
      return _format_as_mcp_text_content(_format_gateway_error_response_as_json(
        "unknown_operation",
        `Unknown operation '${operation}'.${suggestion_text}`,
        "Call oneid(operation=\"readme\") for all available operations.",
        readme_text,
        { available_operations: all_operation_names },
      ));
    }

    const known_param_names = _ONEID_OPERATIONS_AND_THEIR_ACCEPTED_PARAMETER_NAMES[operation];
    const required_param_names = _ONEID_REQUIRED_PARAMS_PER_OPERATION[operation] ?? new Set();

    const validation_error = _validate_params_and_return_error_json_if_invalid(
      effective_params, operation, known_param_names, required_param_names, readme_text, "oneid",
    );
    if (validation_error !== null) {
      return _format_as_mcp_text_content(validation_error);
    }

    try {
      if (operation === "get_or_create_identity") {
        const identity = await oneid.getOrCreateIdentity({
          display_name: effective_params["display_name"] as string | undefined,
          operator_email: effective_params["operator_email"] as string | undefined,
          requested_handle: effective_params["requested_handle"] as string | undefined,
          get_only: effective_params["get_only"] === true,
        });
        return _format_as_mcp_json_content(identity);
      }

      if (operation === "status") {
        const world_status = await oneid.status();
        return _format_as_mcp_json_content(world_status);
      }

      if (operation === "detect_hardware") {
        let hardware_security_modules: unknown[] = [];
        try {
          const { detect_available_hsms } = await import("1id/helper");
          hardware_security_modules = await detect_available_hsms();
        } catch {
          hardware_security_modules = [];
        }
        return _format_as_mcp_json_content({ hardware_security_modules });
      }

      if (operation === "get_bearer_token") {
        const token = await oneid.get_token();
        return _format_as_mcp_json_content({
          access_token: token.access_token,
          token_type: token.token_type,
          expires_at: String(token.expires_at),
        });
      }

      if (operation === "sign_challenge") {
        const nonce_hex = effective_params["nonce_hex"] as string;
        const nonce_bytes = Buffer.from(nonce_hex, "hex");
        const proof_bundle = await oneid.signChallenge(nonce_bytes);
        return _format_as_mcp_json_content(proof_bundle);
      }

      if (operation === "verify_peer") {
        const nonce_hex = effective_params["nonce_hex"] as string;
        const nonce_bytes = Buffer.from(nonce_hex, "hex");
        const proof_bundle_dict = JSON.parse(effective_params["proof_bundle_json"] as string) as IdentityProofBundle;
        const verified = await oneid.verifyPeerIdentity(nonce_bytes, proof_bundle_dict);
        return _format_as_mcp_json_content(verified);
      }

      if (operation === "list_credential_pointers") {
        const result = await oneid.listCredentialPointers(
          effective_params["agent_id"] as string | undefined,
        );
        return _format_as_mcp_json_content(result);
      }

      if (operation === "generate_consent_token") {
        const result = await oneid.generateConsentToken(
          effective_params["issuer_id"] as string,
          effective_params["credential_type"] as string,
          Number(effective_params["valid_for_seconds"] ?? 86400),
        );
        return _format_as_mcp_json_content(result);
      }

      if (operation === "set_pointer_visibility") {
        const result = await oneid.setCredentialPointerVisibility(
          effective_params["pointer_id"] as string,
          effective_params["publicly_visible"] === true,
        );
        return _format_as_mcp_json_content(result);
      }

      if (operation === "remove_pointer") {
        const result = await oneid.removeCredentialPointer(
          effective_params["pointer_id"] as string,
        );
        return _format_as_mcp_json_content(result);
      }

      if (operation === "list_devices") {
        const result = await oneid.listDevices();
        return _format_as_mcp_json_content(result);
      }

      if (operation === "add_device") {
        const result = await oneid.addDevice(
          (effective_params["device_type"] as string) ?? undefined,
          (effective_params["existing_device_fingerprint"] as string) ?? undefined,
          (effective_params["existing_device_type"] as string) ?? undefined,
        );
        return _format_as_mcp_json_content(result);
      }

      if (operation === "lock_hardware") {
        const result = await oneid.lockHardware();
        return _format_as_mcp_json_content(result);
      }

      if (operation === "burn_device") {
        const result = await oneid.burnDevice(
          effective_params["device_fingerprint"] as string,
          effective_params["device_type"] as string,
          effective_params["co_device_fingerprint"] as string,
          effective_params["co_device_type"] as string,
          (effective_params["reason"] as string) ?? undefined,
        );
        return _format_as_mcp_json_content(result);
      }

      if (operation === "request_burn") {
        const result = await oneid.requestBurn(
          effective_params["device_fingerprint"] as string,
          effective_params["device_type"] as string,
          (effective_params["reason"] as string) ?? undefined,
        );
        return _format_as_mcp_json_content(result);
      }

      if (operation === "confirm_burn") {
        const result = await oneid.confirmBurn(
          effective_params["token_id"] as string,
          effective_params["co_device_signature_b64"] as string,
          effective_params["co_device_fingerprint"] as string,
          effective_params["co_device_type"] as string,
        );
        return _format_as_mcp_json_content(result);
      }

    } catch (operation_error) {
      return _format_as_mcp_text_content(_format_gateway_error_response_as_json(
        "operation_failed",
        `Operation '${operation}' failed: ${operation_error}`,
        "Check the error message and retry. Call oneid(operation=\"readme\") for docs.",
        readme_text,
      ));
    }

    return _format_as_mcp_text_content(_format_gateway_error_response_as_json(
      "internal_error",
      `Operation '${operation}' is defined but has no handler.`,
      "This is a server bug. Please report it.",
      readme_text,
    ));
  },
);


// ========================================================================
// Entry point
// ========================================================================

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await mailpal_mcp_server_instance.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`mailpal-mcp-server fatal: ${err}\n`);
  process.exit(1);
});
