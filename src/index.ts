#!/usr/bin/env node
/**
 * MailPal MCP server -- SDK-backed email + identity tools for AI agents.
 *
 * Delegates to the `1id` Node.js SDK for all operations involving the agent's
 * cryptographic identity. The SDK handles TPM authentication, MIME message
 * assembly, attestation computation, header injection, and direct SMTP submission.
 *
 * attestation_mode=3 (both Mode 1 direct-CMS + Mode 2 SD-JWT) is the default.
 *
 * Three REST API tools remain for operations the SDK doesn't yet cover:
 *   mailpal_read_message, mailpal_subscribe_to_inbox, mailpal_jmap.
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

let inbox_sse_connection_abort_controller: AbortController | null = null;
let subscribed_inbox_resource_uri: string | null = null;
let bearer_token_for_active_sse_inbox_connection: string = "";

const _ATTESTATION_MODE_MCP_INTEGER_TO_SDK_STRING: Record<number, MailpalSendOptions["attestation_mode"]> = {
  0: "none",
  1: "direct",
  2: "sd-jwt",
  3: "both",
};

function format_as_mcp_text_content(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
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
    "User-Agent": "mailpal-mcp-server/1.0.0",
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
// MCP server instance
// ========================================================================

const mailpal_mcp_server_instance = new McpServer({
  name: "mailpal",
  version: "1.0.0",
}, {
  capabilities: {
    logging: {},
    resources: { subscribe: true },
  },
  instructions:
    "MailPal provides free email for AI agents with hardware attestation. " +
    "Every agent gets a real @mailpal.com address with full SMTP/IMAP/JMAP. " +
    "Use mailpal_activate_account first if you don't have an account yet. " +
    "Use mailpal_send_email to send (Mode 1+2 attestation is ON by default). " +
    "Use mailpal_check_inbox and mailpal_read_message to read email. " +
    "Use mailpal_subscribe_to_inbox for real-time new-mail notifications. " +
    "Use mailpal_jmap for any JMAP operation not covered by convenience tools. " +
    "Identity tools (oneid_*) manage your hardware-anchored identity, devices, " +
    "peer verification, and credential pointers.",
});


// ========================================================================
// SDK-backed MailPal tools
// ========================================================================

mailpal_mcp_server_instance.tool(
  "mailpal_activate_account",
  "Activate a @mailpal.com email account for this agent. " +
  "Two-phase Proof-of-Intelligence flow: " +
  "Phase 1 (omit challenge fields): returns a POI challenge the agent must solve. " +
  "Phase 2 (include challenge_token + challenge_answer): verifies and creates the account. " +
  "Idempotent: returns existing account info if already activated. " +
  "Uses the local 1id identity for authentication (TPM challenge-response).",
  {
    challenge_token: z.string().optional().describe("Token from phase 1 response (omit for phase 1)"),
    challenge_answer: z.string().optional().describe("Your answer to the POI challenge (omit for phase 1)"),
    display_name: z.string().optional().describe("Display name for the account"),
  },
  async ({ challenge_token, challenge_answer, display_name }) => {
    const activate_options: MailpalActivateOptions = {};
    if (challenge_token) { activate_options.challenge_token = challenge_token; }
    if (challenge_answer) { activate_options.challenge_answer = challenge_answer; }
    if (display_name) { activate_options.display_name = display_name; }
    const result = await oneid.mailpal.activate(activate_options);
    return format_as_mcp_text_content(result);
  },
);


const _COMMON_FILE_EXTENSION_TO_MIME_TYPE: Record<string, string> = {
  ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
  ".gif": "image/gif", ".webp": "image/webp", ".svg": "image/svg+xml",
  ".pdf": "application/pdf", ".zip": "application/zip",
  ".txt": "text/plain", ".html": "text/html", ".csv": "text/csv",
  ".json": "application/json", ".xml": "application/xml",
  ".doc": "application/msword", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".mp3": "audio/mpeg", ".mp4": "video/mp4", ".wav": "audio/wav",
};

function _guess_mime_type_from_file_extension(file_path_string: string): string {
  const extension = path.extname(file_path_string).toLowerCase();
  return _COMMON_FILE_EXTENSION_TO_MIME_TYPE[extension] ?? "application/octet-stream";
}

mailpal_mcp_server_instance.tool(
  "mailpal_send_email",
  "Send an email from the agent's @mailpal.com address with hardware attestation. " +
  "attestation_mode=3 (default): Both Mode 1 (direct CMS) and Mode 2 (SD-JWT). " +
  "attestation_mode=2: Mode 2 only (SD-JWT via 1id.com). " +
  "attestation_mode=1: Mode 1 only (direct TPM CMS, sovereign tier). " +
  "attestation_mode=0: No attestation headers. " +
  "Mode 1 is silently skipped if the identity lacks a certificate chain. " +
  "Builds the MIME message locally, computes attestation from exact wire bytes, " +
  "and submits directly via SMTP to smtp.mailpal.com (no REST API intermediary). " +
  "Supports file attachments via the attachments parameter (local file paths or base64 content). " +
  "For inline images in HTML, set inline=true and reference via cid:content_id in your HTML.",
  {
    to: z.array(z.string()).describe("Recipient email addresses"),
    subject: z.string().describe("Email subject line"),
    text: z.string().optional().describe("Plain text body (at least one of text/html required)"),
    html: z.string().optional().describe("HTML body"),
    cc: z.array(z.string()).optional().describe("CC recipients"),
    bcc: z.array(z.string()).optional().describe("BCC recipients"),
    from_address: z.string().optional().describe("Override sender (must be one of your addresses)"),
    from_display_name: z.string().optional().describe("Sender display name"),
    reply_to: z.string().optional().describe("Reply-To address (where replies should go, if different from sender)"),
    in_reply_to: z.string().optional().describe("Message-ID of the email being replied to (for threading)"),
    references: z.string().optional().describe("Space-separated Message-IDs of the thread (for threading)"),
    attachments: z.array(z.object({
      file_path: z.string().optional().describe("Local file path to attach (reads file from disk)"),
      content_base64: z.string().optional().describe("Base64-encoded file content (alternative to file_path)"),
      filename: z.string().optional().describe("Override filename (defaults to basename of file_path)"),
      content_type: z.string().optional().describe("MIME type (auto-detected from extension if omitted)"),
      inline: z.boolean().optional().describe("If true, attach inline for HTML cid: references"),
      content_id: z.string().optional().describe("Content-ID for inline images (used with cid: in HTML)"),
    })).optional().describe("File attachments (local paths or base64 content)"),
    attestation_mode: z.number().int().min(0).max(3).default(3)
      .describe("3 = both Mode 1+2 (default), 2 = SD-JWT only, 1 = direct CMS only, 0 = none"),
  },
  async ({ to, subject, text, html, cc, bcc, from_address, from_display_name, reply_to, in_reply_to, references, attachments, attestation_mode }) => {
    const sdk_attestation_mode = _ATTESTATION_MODE_MCP_INTEGER_TO_SDK_STRING[attestation_mode] ?? "both";

    let sdk_attachments: Array<{filename: string; content_base64: string; content_type?: string; inline?: boolean; content_id?: string}> | null = null;
    if (attachments && attachments.length > 0) {
      sdk_attachments = [];
      for (const attachment_spec of attachments) {
        let base64_content: string;
        let resolved_filename: string;

        if (attachment_spec.file_path) {
          const absolute_file_path = path.resolve(attachment_spec.file_path);
          if (!fs.existsSync(absolute_file_path)) {
            throw new Error(`Attachment file not found: ${absolute_file_path}`);
          }
          const file_buffer = fs.readFileSync(absolute_file_path);
          base64_content = file_buffer.toString("base64");
          resolved_filename = attachment_spec.filename ?? path.basename(absolute_file_path);
        } else if (attachment_spec.content_base64) {
          base64_content = attachment_spec.content_base64;
          resolved_filename = attachment_spec.filename ?? "attachment";
        } else {
          throw new Error("Each attachment must have either file_path or content_base64");
        }

        const resolved_content_type = attachment_spec.content_type
          ?? _guess_mime_type_from_file_extension(resolved_filename);

        sdk_attachments.push({
          filename: resolved_filename,
          content_base64: base64_content,
          content_type: resolved_content_type,
          inline: attachment_spec.inline ?? false,
          content_id: attachment_spec.content_id,
        });
      }
    }

    const result = await oneid.mailpal.send({
      to,
      subject,
      text_body: text ?? null,
      html_body: html ?? null,
      cc: cc ?? null,
      bcc: bcc ?? null,
      from_address: from_address ?? null,
      from_display_name: from_display_name ?? null,
      reply_to: reply_to ?? null,
      in_reply_to: in_reply_to ?? null,
      references: references ?? null,
      attachments: sdk_attachments,
      attestation_mode: sdk_attestation_mode,
    });
    return format_as_mcp_text_content(result);
  },
);


mailpal_mcp_server_instance.tool(
  "mailpal_check_inbox",
  "Check inbox for new or unread messages. Returns summaries (sender, subject, date). " +
  "Use mailpal_read_message to get full content of a specific message. " +
  "Uses the local 1id identity for authentication.",
  {
    limit: z.number().int().min(1).max(100).default(20).describe("Maximum messages to return (default 20)"),
    offset: z.number().int().min(0).default(0).describe("Skip this many messages for pagination"),
    unread_only: z.boolean().default(false).describe("Only return unread messages"),
  },
  async ({ limit, offset, unread_only }) => {
    const messages = await oneid.mailpal.inbox({ limit, offset, unread_only });
    return format_as_mcp_text_content({ messages });
  },
);


// ========================================================================
// REST API-backed MailPal tools (SDK doesn't cover these yet)
// ========================================================================

mailpal_mcp_server_instance.tool(
  "mailpal_read_message",
  "Read the full content of a specific email message including text body, HTML body, " +
  "attachment metadata, attestation headers, threading info (messageId, inReplyTo, references), " +
  "and all other metadata. Authenticates automatically using the SDK's TPM identity.",
  {
    message_id: z.string().describe("Message ID from mailpal_check_inbox results"),
  },
  async ({ message_id }) => {
    const sdk_token = await oneid.get_token();
    return format_as_mcp_text_content(
      await send_authenticated_request_to_mailpal_rest_api(
        `/inbox/${encodeURIComponent(message_id)}`, "GET", undefined, undefined,
        sdk_token.access_token,
      )
    );
  },
);


let pending_inbox_state_change_resolve_callbacks: Array<(value: string) => void> = [];

interface RegisteredEmailArrivalCallback {
  callback_id: string;
  callback_type: "webhook" | "tool_call";
  webhook_url?: string;
  webhook_method?: string;
  webhook_headers?: Record<string, string>;
  tool_name?: string;
  tool_arguments_template?: Record<string, unknown>;
  registered_at: string;
}

let registered_email_arrival_callbacks: RegisteredEmailArrivalCallback[] = [];

async function execute_registered_email_arrival_callbacks_on_new_mail(event_data: string): Promise<void> {
  for (const callback of registered_email_arrival_callbacks) {
    try {
      if (callback.callback_type === "webhook" && callback.webhook_url) {
        const webhook_payload = {
          event: "new_email",
          callback_id: callback.callback_id,
          uri: subscribed_inbox_resource_uri ?? "mailpal://inbox",
          timestamp: new Date().toISOString(),
          raw_event: event_data,
        };
        await fetch(callback.webhook_url, {
          method: callback.webhook_method ?? "POST",
          headers: {
            "Content-Type": "application/json",
            ...(callback.webhook_headers ?? {}),
          },
          body: JSON.stringify(webhook_payload),
          signal: AbortSignal.timeout(10000),
        }).catch(() => {});
      }
    } catch { /* best-effort callback delivery */ }
  }
}

async function start_background_sse_listener_for_inbox_event_notifications(): Promise<void> {
  if (inbox_sse_connection_abort_controller) {
    inbox_sse_connection_abort_controller.abort();
    inbox_sse_connection_abort_controller = null;
  }

  inbox_sse_connection_abort_controller = new AbortController();

  const connect_to_sse_and_relay_events = async (): Promise<void> => {
    try {
      const effective_sse_token = bearer_token_for_active_sse_inbox_connection || MAILPAL_BEARER_AUTH_TOKEN;
      const sse_http_response = await fetch(
        `${MAILPAL_REST_API_BASE_URL}/inbox/events`,
        {
          headers: {
            "Authorization": `Bearer ${effective_sse_token}`,
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
          },
          signal: inbox_sse_connection_abort_controller!.signal,
        },
      );

      if (!sse_http_response.ok || !sse_http_response.body) {
        const error_text = sse_http_response.ok ? "no body" : `HTTP ${sse_http_response.status}`;
        console.error(`SSE connection failed: ${error_text}`);
        return;
      }

      const response_body_stream_reader = sse_http_response.body.getReader();
      const utf8_text_decoder = new TextDecoder();
      let incomplete_line_buffer = "";
      let current_sse_event_type = "";
      let current_sse_data_lines: string[] = [];

      while (true) {
        const { done: stream_is_exhausted, value: raw_chunk_bytes } =
          await response_body_stream_reader.read();
        if (stream_is_exhausted) { break; }

        incomplete_line_buffer += utf8_text_decoder.decode(raw_chunk_bytes, { stream: true });
        const fully_received_lines = incomplete_line_buffer.split("\n");
        incomplete_line_buffer = fully_received_lines.pop() ?? "";

        for (const sse_line of fully_received_lines) {
          if (sse_line.startsWith("event:")) {
            current_sse_event_type = sse_line.slice(6).trim();
          } else if (sse_line.startsWith("data:")) {
            current_sse_data_lines.push(sse_line.slice(5).trim());
          } else if (sse_line.startsWith(":")) {
            /* keepalive comment -- ignore */
          } else if (sse_line.trim() === "") {
            if (current_sse_data_lines.length > 0) {
              const event_type = current_sse_event_type || "state_change";
              const event_data = current_sse_data_lines.join("\n");

              if (event_type === "state_change" || event_type === "StateChange" || event_type === "state") {
                if (subscribed_inbox_resource_uri) {
                  try {
                    await mailpal_mcp_server_instance.server.sendResourceUpdated({
                      uri: subscribed_inbox_resource_uri,
                    });
                  } catch { /* MCP client may not support resource notifications */ }
                }

                try {
                  await mailpal_mcp_server_instance.sendLoggingMessage({
                    level: "info",
                    logger: "mailpal",
                    data: {
                      event: "new_email",
                      uri: subscribed_inbox_resource_uri ?? "mailpal://inbox",
                      message: "New email received. Call mailpal_check_inbox to see what arrived.",
                      raw_event: event_data,
                    },
                  });
                } catch { /* MCP client may not support logging notifications */ }

                execute_registered_email_arrival_callbacks_on_new_mail(event_data).catch(() => {});

                for (const resolve_callback of pending_inbox_state_change_resolve_callbacks) {
                  resolve_callback(event_data);
                }
                pending_inbox_state_change_resolve_callbacks = [];
              }
            }
            current_sse_event_type = "";
            current_sse_data_lines = [];
          }
        }
      }
    } catch (sse_connection_error: unknown) {
      if (
        sse_connection_error instanceof DOMException &&
        sse_connection_error.name === "AbortError"
      ) { return; }
      if (
        inbox_sse_connection_abort_controller &&
        !inbox_sse_connection_abort_controller.signal.aborted
      ) {
        setTimeout(() => { connect_to_sse_and_relay_events(); }, 5000);
      }
    }
  };

  connect_to_sse_and_relay_events();
}

mailpal_mcp_server_instance.tool(
  "mailpal_subscribe_to_inbox",
  "Subscribe to real-time new-mail notifications for this agent's inbox. " +
  "Once subscribed, the server pushes notifications/resources/updated when new mail arrives. " +
  "Call mailpal_check_inbox after receiving a notification to see what's new. " +
  "Also enables mailpal_wait_for_email (blocking poll until new mail). " +
  "Works on both stdio and Streamable HTTP transports. " +
  "Authenticates automatically using the SDK's TPM identity.",
  {},
  async () => {
    const sdk_token = await oneid.get_token();
    const effective_token_for_subscription = sdk_token.access_token;

    let agent_identifier_from_jwt_subject_claim = "unknown";
    try {
      const jwt_payload_base64_segment = effective_token_for_subscription.split(".")[1];
      if (jwt_payload_base64_segment) {
        const decoded_jwt_payload_object = JSON.parse(
          Buffer.from(jwt_payload_base64_segment, "base64url").toString("utf-8"),
        );
        agent_identifier_from_jwt_subject_claim =
          (decoded_jwt_payload_object as { sub?: string }).sub ?? "unknown";
      }
    } catch { /* JWT parsing failed; use placeholder */ }

    subscribed_inbox_resource_uri =
      `mailpal://inbox/${agent_identifier_from_jwt_subject_claim}`;
    bearer_token_for_active_sse_inbox_connection = effective_token_for_subscription;

    await start_background_sse_listener_for_inbox_event_notifications();

    return format_as_mcp_text_content({
      subscribed: true,
      uri: subscribed_inbox_resource_uri,
      transport: "stdio",
      message:
        "Listening for new mail. The MCP server will push notifications/resources/updated " +
        "when new email arrives. You can also call mailpal_wait_for_email to block until " +
        "new mail is detected, or poll mailpal_check_inbox periodically.",
    });
  },
);


mailpal_mcp_server_instance.tool(
  "mailpal_wait_for_email",
  "Block until new email arrives or timeout. Requires mailpal_subscribe_to_inbox first. " +
  "Returns immediately if subscription detects a mailbox state change. " +
  "This is the most reliable way for AI agents to 'sleep until woken by email' since " +
  "most AI runtimes cannot consume async MCP notifications. " +
  "After this returns, call mailpal_check_inbox to see the new messages. " +
  "Default timeout: 300 seconds (5 minutes). Max: 3600 seconds (1 hour).",
  {
    timeout_seconds: z.number().int().min(1).max(3600).default(300)
      .describe("Maximum seconds to wait for new mail (default 300, max 3600)"),
  },
  async ({ timeout_seconds }) => {
    if (!inbox_sse_connection_abort_controller || !subscribed_inbox_resource_uri) {
      return format_as_mcp_text_content({
        received: false,
        error: "Not subscribed. Call mailpal_subscribe_to_inbox first.",
      });
    }

    const wait_result = await Promise.race([
      new Promise<string>((resolve) => {
        pending_inbox_state_change_resolve_callbacks.push(resolve);
      }),
      new Promise<null>((resolve) => {
        setTimeout(() => { resolve(null); }, timeout_seconds * 1000);
      }),
    ]);

    if (wait_result === null) {
      return format_as_mcp_text_content({
        received: false,
        timed_out: true,
        waited_seconds: timeout_seconds,
        message: "No new mail within timeout. Call again to keep waiting, or check inbox.",
      });
    }

    return format_as_mcp_text_content({
      received: true,
      timed_out: false,
      event_data: wait_result,
      message: "Mailbox state changed -- new mail likely arrived. Call mailpal_check_inbox now.",
    });
  },
);


mailpal_mcp_server_instance.tool(
  "mailpal_register_email_callback",
  "Register a webhook URL to be called when new email arrives. " +
  "Requires mailpal_subscribe_to_inbox first. When the inbox SSE detects new mail, " +
  "this server will POST a JSON payload to your webhook_url containing the event details. " +
  "This is the most reliable way for external systems to react to incoming email " +
  "without maintaining a persistent connection. " +
  "Multiple callbacks can be registered simultaneously. " +
  "Returns a callback_id you can use with mailpal_unregister_email_callback to remove it.",
  {
    webhook_url: z.string().url().describe("HTTPS URL to POST the new-email event payload to"),
    webhook_method: z.string().default("POST")
      .describe("HTTP method for the webhook (default: POST)"),
    webhook_headers: z.record(z.string()).optional()
      .describe("Optional extra HTTP headers to include in the webhook request (e.g. auth tokens)"),
  },
  async ({ webhook_url, webhook_method, webhook_headers }) => {
    if (!inbox_sse_connection_abort_controller || !subscribed_inbox_resource_uri) {
      return format_as_mcp_text_content({
        registered: false,
        error: "Not subscribed. Call mailpal_subscribe_to_inbox first.",
      });
    }

    const callback_id = `cb_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const new_callback: RegisteredEmailArrivalCallback = {
      callback_id,
      callback_type: "webhook",
      webhook_url,
      webhook_method,
      webhook_headers,
      registered_at: new Date().toISOString(),
    };
    registered_email_arrival_callbacks.push(new_callback);

    return format_as_mcp_text_content({
      registered: true,
      callback_id,
      webhook_url,
      total_registered_callbacks: registered_email_arrival_callbacks.length,
      message: "Webhook registered. It will receive POST payloads when new email arrives.",
    });
  },
);


mailpal_mcp_server_instance.tool(
  "mailpal_unregister_email_callback",
  "Remove a previously registered email arrival webhook callback. " +
  "Pass the callback_id returned by mailpal_register_email_callback. " +
  "Pass callback_id='all' to remove all registered callbacks.",
  {
    callback_id: z.string().describe("The callback_id to remove, or 'all' to remove every registered callback"),
  },
  async ({ callback_id }) => {
    if (callback_id === "all") {
      const removed_count = registered_email_arrival_callbacks.length;
      registered_email_arrival_callbacks = [];
      return format_as_mcp_text_content({
        removed: true,
        removed_count,
        message: `All ${removed_count} callback(s) removed.`,
      });
    }

    const index_of_callback_to_remove = registered_email_arrival_callbacks.findIndex(
      (cb) => cb.callback_id === callback_id,
    );
    if (index_of_callback_to_remove === -1) {
      return format_as_mcp_text_content({
        removed: false,
        error: `No callback found with id '${callback_id}'.`,
      });
    }

    registered_email_arrival_callbacks.splice(index_of_callback_to_remove, 1);
    return format_as_mcp_text_content({
      removed: true,
      callback_id,
      remaining_callbacks: registered_email_arrival_callbacks.length,
      message: "Callback removed.",
    });
  },
);


mailpal_mcp_server_instance.tool(
  "mailpal_jmap",
  "Send raw JMAP method calls through the authenticated MailPal proxy. " +
  "Use for any operation not covered by convenience tools: " +
  "delete messages, move between folders, flag/unflag, search, manage folders, " +
  "contacts (CardDAV), calendars (CalDAV), sieve filters, blob upload for attachments, " +
  "identity management -- anything JMAP (RFC 8620/8621) supports. " +
  "The accountId is auto-injected by the server. " +
  "Common patterns: " +
  'Delete: [["Email/set", {"destroy": ["id1"]}, "d1"]] | ' +
  'Move: [["Email/set", {"update": {"id1": {"mailboxIds": {"folder": true}}}}, "m1"]] | ' +
  'Mark read: [["Email/set", {"update": {"id1": {"keywords/$seen": true}}}, "r1"]] | ' +
  'Search: [["Email/query", {"filter": {"text": "invoice"}, "limit": 20}, "s1"], ' +
  '["Email/get", {"#ids": {"resultOf": "s1", "name": "Email/query", "path": "/ids"}, ' +
  '"properties": ["id","from","subject","receivedAt","preview"]}, "s2"]]',
  {
    using: z.array(z.string()).default([
      "urn:ietf:params:jmap:core",
      "urn:ietf:params:jmap:mail",
    ]).describe("JMAP capability URIs"),
    method_calls: z.array(z.array(z.unknown())).describe(
      "JMAP methodCalls array. Each element: [methodName, args, callId]. " +
      'Example: [["Email/query", {"filter": {"inMailbox": "abc"}, "limit": 10}, "q1"]]',
    ),
  },
  async ({ using, method_calls }) => {
    const sdk_token = await oneid.get_token();
    return format_as_mcp_text_content(
      await send_authenticated_request_to_mailpal_rest_api("/jmap", "POST", {
        using,
        methodCalls: method_calls,
      }, undefined, sdk_token.access_token)
    );
  },
);


// ========================================================================
// SDK-backed 1id Identity tools
// ========================================================================

mailpal_mcp_server_instance.tool(
  "oneid_get_or_create_identity",
  "Get or create a hardware-anchored 1id identity for this agent. " +
  "If already enrolled, returns the existing identity instantly (no network call). " +
  "If not enrolled, auto-detects hardware (TPM, YubiKey, Secure Enclave) and " +
  "enrolls at the highest available trust tier. " +
  "Pass get_only=true to recover context without risking a new enrollment. " +
  "Trust tiers (highest to lowest): " +
  "sovereign (TPM) > portable (YubiKey) > enclave (SE) > virtual (vTPM) > declared (software)",
  {
    display_name: z.string().optional().describe("Friendly name for the agent (e.g., 'Clawdia', 'Sparky')"),
    operator_email: z.string().optional().describe("Human contact email for handle purchases and recovery"),
    requested_handle: z.string().optional().describe("Vanity handle (e.g., 'clawdia'). Random = free; chosen = $10+/year"),
    get_only: z.boolean().default(false).describe("If true, only return existing identity -- never create new"),
  },
  async ({ display_name, operator_email, requested_handle, get_only }) => {
    const identity = await oneid.getOrCreateIdentity({
      display_name: display_name ?? null,
      operator_email: operator_email ?? null,
      requested_handle: requested_handle ?? null,
      get_only,
    });
    return format_as_mcp_text_content(identity);
  },
);


mailpal_mcp_server_instance.tool(
  "oneid_status",
  "Get the full picture of this agent's 1id identity and connected services. " +
  "Returns identity details, devices, connected RP services, available services, " +
  "and operator guidance. Results are cached for 5 minutes. " +
  "Recommended for context recovery after restarts or memory loss.",
  {},
  async () => {
    const world_status = await oneid.status();
    return format_as_mcp_text_content(world_status);
  },
);


mailpal_mcp_server_instance.tool(
  "oneid_get_bearer_token",
  "Get an OAuth2 Bearer token for the current 1id identity. " +
  "The token is a signed JWT containing identity claims (sub, handle, trust_tier). " +
  "Use this for authenticating with external APIs that accept 1id tokens. " +
  "Tokens are cached and automatically refreshed when expired.",
  {},
  async () => {
    const token = await oneid.get_token();
    return format_as_mcp_text_content({
      access_token: token.access_token,
      token_type: "Bearer",
      expires_at: token.expires_at?.toISOString?.() ?? String(token.expires_at),
    });
  },
);


// ========================================================================
// SDK-backed Peer Verification tools
// ========================================================================

mailpal_mcp_server_instance.tool(
  "oneid_sign_challenge",
  "Sign a verifier-provided nonce to prove this agent's hardware identity. " +
  "Protocol step 2 of 3 in peer-to-peer identity verification: " +
  "1. Verifier generates a random nonce (32+ bytes) " +
  "2. Agent calls this tool with the nonce -> returns proof bundle " +
  "3. Verifier calls oneid_verify_peer_identity with the bundle " +
  "The proof bundle contains: signature, certificate chain, agent_id, trust tier. " +
  "No secrets are exchanged. The verifier never contacts 1id.com.",
  {
    nonce_hex: z.string().describe("The verifier's nonce as a hex string (e.g., 64 hex chars for 32 bytes)"),
  },
  async ({ nonce_hex }) => {
    const nonce_bytes = Buffer.from(nonce_hex, "hex");
    const proof_bundle = await oneid.signChallenge(nonce_bytes);
    return format_as_mcp_text_content(proof_bundle);
  },
);


mailpal_mcp_server_instance.tool(
  "oneid_verify_peer_identity",
  "Verify another agent's identity proof bundle. Entirely offline after first trust root fetch. " +
  "Protocol step 3 of 3 in peer-to-peer identity verification. " +
  "Validates the certificate chain to a trusted 1id root, then verifies " +
  "the nonce signature against the leaf certificate's public key.",
  {
    nonce_hex: z.string().describe("The original nonce you sent to the prover (hex string)"),
    proof_bundle_json: z.string().describe("The JSON proof bundle from the prover's oneid_sign_challenge"),
  },
  async ({ nonce_hex, proof_bundle_json }) => {
    const nonce_bytes = Buffer.from(nonce_hex, "hex");
    const proof_bundle_dict = JSON.parse(proof_bundle_json) as IdentityProofBundle;
    const verified = await oneid.verifyPeerIdentity(nonce_bytes, proof_bundle_dict);
    return format_as_mcp_text_content(verified);
  },
);


// ========================================================================
// SDK-backed Credential Pointer tools
// ========================================================================

mailpal_mcp_server_instance.tool(
  "oneid_generate_credential_consent_token",
  "Generate a consent token for a credential authority to register a credential pointer. " +
  "The agent calls this to authorize a specific issuer to register exactly one " +
  "credential pointer. Give the returned token to the credential authority. " +
  "Example: An agent scored high on the CEH exam. The exam authority uses this " +
  "token to register a 'ceh-certification' pointer on the agent's identity.",
  {
    issuer_id: z.string().describe("DID or URI of the credential authority (e.g., 'did:web:eccouncil.org')"),
    credential_type: z.string().describe("Type of credential (e.g., 'ceh-certification', 'degree', 'license')"),
    valid_for_seconds: z.number().int().min(60).max(604800).default(86400)
      .describe("Token validity period in seconds (default 86400 = 24 hours)"),
  },
  async ({ issuer_id, credential_type, valid_for_seconds }) => {
    const result = await oneid.generateConsentToken(issuer_id, credential_type, valid_for_seconds);
    return format_as_mcp_text_content(result);
  },
);


mailpal_mcp_server_instance.tool(
  "oneid_list_credential_pointers",
  "List credential pointers for an identity. " +
  "If agent_id is omitted, returns all pointers for this agent (authenticated, full view). " +
  "If agent_id is a different identity, returns only publicly visible pointers. " +
  "Credential pointers link an agent's identity to credentials held by external " +
  "authorities. 1id never stores credential content -- only pointer metadata.",
  {
    agent_id: z.string().optional().describe("Identity to query. Omit to query your own pointers"),
  },
  async ({ agent_id }) => {
    const result = await oneid.listCredentialPointers(agent_id ?? null);
    return format_as_mcp_text_content(result);
  },
);


mailpal_mcp_server_instance.tool(
  "oneid_set_credential_pointer_visibility",
  "Toggle a credential pointer between public and private visibility. " +
  "Public pointers are visible to anyone querying the agent's identity. " +
  "Private pointers are only visible to the agent itself.",
  {
    pointer_id: z.string().describe("The pointer to update (prefix: cp-)"),
    publicly_visible: z.boolean().describe("True = publicly visible, False = private"),
  },
  async ({ pointer_id, publicly_visible }) => {
    const result = await oneid.setCredentialPointerVisibility(pointer_id, publicly_visible);
    return format_as_mcp_text_content(result);
  },
);


mailpal_mcp_server_instance.tool(
  "oneid_remove_credential_pointer",
  "Soft-delete a credential pointer. The pointer is marked removed and no longer " +
  "appears in list results. Never hard-deleted (preserves audit trail).",
  {
    pointer_id: z.string().describe("The pointer to remove (prefix: cp-)"),
  },
  async ({ pointer_id }) => {
    const result = await oneid.removeCredentialPointer(pointer_id);
    return format_as_mcp_text_content(result);
  },
);


// ========================================================================
// SDK-backed Device Management tools
// ========================================================================

mailpal_mcp_server_instance.tool(
  "oneid_list_devices",
  "List all hardware devices (active and burned) bound to this identity. " +
  "Shows device type, fingerprint, status, trust tier, TPM manufacturer or " +
  "PIV serial, binding timestamp, and burn details if applicable.",
  {},
  async () => {
    const result = await oneid.listDevices();
    return format_as_mcp_text_content(result);
  },
);


mailpal_mcp_server_instance.tool(
  "oneid_lock_hardware",
  "Permanently lock this identity to its single active hardware device. " +
  "IRREVERSIBLE. Once locked: " +
  "- No new devices can be added " +
  "- The existing device cannot be burned " +
  "- The identity is permanently bound to one physical chip " +
  "Preconditions: identity must be hardware-tier with exactly 1 active device.",
  {},
  async () => {
    const result = await oneid.lockHardware();
    return format_as_mcp_text_content(result);
  },
);


mailpal_mcp_server_instance.tool(
  "oneid_add_device",
  "Add a new hardware device to this identity. " +
  "Two paths: (1) declared->hardware upgrade (auto-detects TPM/YubiKey, no co-location), " +
  "(2) hardware->hardware co-location binding (requires existing_device_fingerprint and type). " +
  "The device_type param is optional ('tpm' or 'piv'); if omitted, auto-detects best available.",
  {
    device_type: z.string().optional().describe("Optional: 'tpm' or 'piv'. Auto-detects if omitted."),
    existing_device_fingerprint: z.string().optional().describe("For hardware-to-hardware: fingerprint of existing device."),
    existing_device_type: z.string().optional().describe("For hardware-to-hardware: 'tpm' or 'piv'."),
  },
  async ({ device_type, existing_device_fingerprint, existing_device_type }) => {
    const result = await oneid.addDevice(
      device_type ?? null,
      existing_device_fingerprint ?? null,
      existing_device_type ?? null,
    );
    return format_as_mcp_text_content(result);
  },
);


mailpal_mcp_server_instance.tool(
  "oneid_burn_device",
  "Permanently retire (burn) a device from this identity (IRREVERSIBLE). " +
  "The device fingerprint is permanently marked in the anti-Sybil registry. " +
  "Requires a co-device (different active device on same identity) to co-sign, " +
  "preventing malware from silently destroying hardware utility.",
  {
    device_fingerprint: z.string().describe("Fingerprint of the device to burn."),
    device_type: z.string().describe("Type of device to burn: 'tpm' or 'piv'."),
    co_device_fingerprint: z.string().describe("Fingerprint of the co-signing device."),
    co_device_type: z.string().describe("Type of co-signing device: 'tpm' or 'piv'."),
    reason: z.string().optional().describe("Optional reason for the burn (e.g. 'migrated to new hardware')."),
  },
  async ({ device_fingerprint, device_type, co_device_fingerprint, co_device_type, reason }) => {
    const result = await oneid.burnDevice(
      device_fingerprint, device_type,
      co_device_fingerprint, co_device_type,
      reason ?? null,
    );
    return format_as_mcp_text_content(result);
  },
);


mailpal_mcp_server_instance.tool(
  "oneid_request_burn",
  "Request a burn confirmation token (step 1 of 2 for async burn workflows). " +
  "Returns a token_id valid for 5 minutes. Use with oneid_confirm_burn to complete.",
  {
    device_fingerprint: z.string().describe("Fingerprint of the device to burn."),
    device_type: z.string().describe("Type: 'tpm' or 'piv'."),
    reason: z.string().optional().describe("Optional burn reason."),
  },
  async ({ device_fingerprint, device_type, reason }) => {
    const result = await oneid.requestBurn(device_fingerprint, device_type, reason ?? null);
    return format_as_mcp_text_content(result);
  },
);


mailpal_mcp_server_instance.tool(
  "oneid_confirm_burn",
  "Confirm a device burn with a co-device signature (step 2 of 2). " +
  "Use the token_id from oneid_request_burn.",
  {
    token_id: z.string().describe("Burn confirmation token from oneid_request_burn."),
    co_device_signature_b64: z.string().describe("Base64-encoded co-device signature."),
    co_device_fingerprint: z.string().describe("Fingerprint of the co-signing device."),
    co_device_type: z.string().describe("Type of co-signing device: 'tpm' or 'piv'."),
  },
  async ({ token_id, co_device_signature_b64, co_device_fingerprint, co_device_type }) => {
    const result = await oneid.confirmBurn(
      token_id, co_device_signature_b64, co_device_fingerprint, co_device_type,
    );
    return format_as_mcp_text_content(result);
  },
);


// ========================================================================
// Entry point
// ========================================================================

async function initialize_and_start_mailpal_mcp_stdio_server(): Promise<void> {
  const stdio_transport_connection = new StdioServerTransport();
  await mailpal_mcp_server_instance.connect(stdio_transport_connection);
}

initialize_and_start_mailpal_mcp_stdio_server().catch((server_startup_error: unknown) => {
  console.error("MailPal MCP server failed to start:", server_startup_error);
  process.exit(1);
});
