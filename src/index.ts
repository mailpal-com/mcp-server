#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const MAILPAL_REST_API_BASE_URL = process.env.MAILPAL_API_URL ?? "https://mailpal.com/api/v1";
const MAILPAL_BEARER_AUTH_TOKEN = process.env.MAILPAL_TOKEN ?? "";

let inbox_sse_connection_abort_controller: AbortController | null = null;
let subscribed_inbox_resource_uri: string | null = null;

async function send_authenticated_request_to_mailpal_rest_api(
  api_endpoint_path: string,
  http_method: "GET" | "POST" = "GET",
  json_request_body?: Record<string, unknown>,
  url_query_parameters?: Record<string, string>,
): Promise<Record<string, unknown>> {
  const full_request_url = new URL(`${MAILPAL_REST_API_BASE_URL}${api_endpoint_path}`);
  if (url_query_parameters) {
    for (const [param_name, param_value] of Object.entries(url_query_parameters)) {
      full_request_url.searchParams.set(param_name, param_value);
    }
  }

  const http_request_headers: Record<string, string> = {
    "Accept": "application/json",
    "User-Agent": "mailpal-mcp-server/1.0.0",
  };
  if (MAILPAL_BEARER_AUTH_TOKEN) {
    http_request_headers["Authorization"] = `Bearer ${MAILPAL_BEARER_AUTH_TOKEN}`;
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

function format_api_response_as_mcp_text_content(api_response_data: Record<string, unknown>) {
  return { content: [{ type: "text" as const, text: JSON.stringify(api_response_data, null, 2) }] };
}

const mailpal_mcp_server_instance = new McpServer({
  name: "mailpal",
  version: "1.0.0",
}, {
  instructions:
    "MailPal provides free email for AI agents with hardware attestation. " +
    "Every agent gets a real @mailpal.com address with full SMTP/IMAP/JMAP/CalDAV/CardDAV. " +
    "Use mailpal_activate_account first if you don't have an account yet. " +
    "Use mailpal_send_email to send (hardware attestation is ON by default). " +
    "Use mailpal_check_inbox and mailpal_read_message to read email. " +
    "Use mailpal_subscribe_to_inbox for real-time new-mail notifications. " +
    "Use mailpal_jmap for any JMAP operation not covered by convenience tools " +
    "(delete, move, flag, search, folders, contacts, calendars, sieve filters, etc.).",
});


// Tool 1: mailpal_activate_account -- Two-phase POI account provisioning
mailpal_mcp_server_instance.tool(
  "mailpal_activate_account",
  "Activate a @mailpal.com email account for this agent. " +
  "Two-phase Proof-of-Intelligence flow: " +
  "Phase 1 (omit challenge fields): returns a POI challenge the agent must solve. " +
  "Phase 2 (include challenge_token + challenge_answer): verifies and creates the account. " +
  "Idempotent: returns existing account info if already activated.",
  {
    challenge_token: z.string().optional().describe("Token from phase 1 response (omit for phase 1)"),
    challenge_answer: z.string().optional().describe("Your answer to the POI challenge (omit for phase 1)"),
    display_name: z.string().optional().describe("Display name for the account"),
  },
  async ({ challenge_token, challenge_answer, display_name }) => {
    const activate_request_body: Record<string, unknown> = {};
    if (challenge_token) { activate_request_body.challenge_token = challenge_token; }
    if (challenge_answer) { activate_request_body.challenge_answer = challenge_answer; }
    if (display_name) { activate_request_body.display_name = display_name; }
    return format_api_response_as_mcp_text_content(
      await send_authenticated_request_to_mailpal_rest_api("/activate", "POST", activate_request_body)
    );
  },
);


// Tool 2: mailpal_send_email -- Hardware attestation ON by default (mode 2)
mailpal_mcp_server_instance.tool(
  "mailpal_send_email",
  "Send an email from the agent's @mailpal.com address. " +
  "Hardware attestation is ON by default (attestation_mode=2: issuer-mediated SD-JWT via 1id.com). " +
  "This is MailPal's core purpose: proving emails come from real hardware. " +
  "Set attestation_mode=1 for direct TPM CMS (sovereign tier only, maximum trust). " +
  "Set attestation_mode=0 for no attestation (fallback for declared/virtual tiers). " +
  "If your trust tier is too low for the requested mode, returns an error (never silently downgrades). " +
  "For attachments, use mailpal_jmap with Blob/upload + Email/set + EmailSubmission/set.",
  {
    to: z.array(z.string()).describe("Recipient email addresses"),
    subject: z.string().describe("Email subject line"),
    text: z.string().optional().describe("Plain text body (at least one of text/html required)"),
    html: z.string().optional().describe("HTML body"),
    cc: z.array(z.string()).optional().describe("CC recipients"),
    bcc: z.array(z.string()).optional().describe("BCC recipients"),
    reply_to: z.string().optional().describe("Reply-To address"),
    in_reply_to: z.string().optional().describe("Message-ID for threading"),
    from_address: z.string().optional().describe("Override sender (must be one of your addresses)"),
    from_display_name: z.string().optional().describe("Sender display name"),
    attestation_mode: z.number().int().min(0).max(2).default(2)
      .describe("2 = SD-JWT via 1id.com (default), 1 = direct TPM CMS, 0 = no attestation"),
  },
  async ({ to, subject, text, html, cc, bcc, reply_to, in_reply_to, from_address, from_display_name, attestation_mode }) => {
    const email_composition_fields: Record<string, unknown> = { to, subject };
    if (text) { email_composition_fields.text = text; }
    if (html) { email_composition_fields.html = html; }
    if (cc) { email_composition_fields.cc = cc; }
    if (bcc) { email_composition_fields.bcc = bcc; }
    if (reply_to) { email_composition_fields.reply_to = reply_to; }
    if (in_reply_to) { email_composition_fields.in_reply_to = in_reply_to; }
    if (from_address) { email_composition_fields.from = from_address; }
    if (from_display_name) { email_composition_fields.from_display_name = from_display_name; }

    if (attestation_mode === 0) {
      return format_api_response_as_mcp_text_content(
        await send_authenticated_request_to_mailpal_rest_api("/send", "POST", email_composition_fields)
      );
    }

    const prepare_phase_response = await send_authenticated_request_to_mailpal_rest_api(
      "/send/prepare", "POST", email_composition_fields
    );
    const prepare_token_value = (prepare_phase_response as { data?: { prepare_token?: string } })
      .data?.prepare_token;
    if (!prepare_token_value) {
      return format_api_response_as_mcp_text_content(prepare_phase_response);
    }

    return format_api_response_as_mcp_text_content(
      await send_authenticated_request_to_mailpal_rest_api("/send/commit", "POST", {
        prepare_token: prepare_token_value,
        attestation_mode,
      })
    );
  },
);


// Tool 3: mailpal_check_inbox -- Inbox summaries
mailpal_mcp_server_instance.tool(
  "mailpal_check_inbox",
  "Check inbox for new or unread messages. Returns summaries (sender, subject, date, preview), not full bodies. " +
  "Use mailpal_read_message to get full content of a specific message.",
  {
    limit: z.number().int().min(1).max(100).default(20).describe("Maximum messages to return (default 20)"),
    offset: z.number().int().min(0).default(0).describe("Skip this many messages for pagination"),
    unread_only: z.boolean().default(false).describe("Only return unread messages"),
  },
  async ({ limit, offset, unread_only }) => {
    return format_api_response_as_mcp_text_content(
      await send_authenticated_request_to_mailpal_rest_api("/inbox", "GET", undefined, {
        limit: String(limit),
        offset: String(offset),
        unread_only: String(unread_only),
      })
    );
  },
);


// Tool 4: mailpal_read_message -- Full message content
mailpal_mcp_server_instance.tool(
  "mailpal_read_message",
  "Read the full content of a specific email message including text body, HTML body, headers, and all metadata.",
  {
    message_id: z.string().describe("Message ID from mailpal_check_inbox results"),
  },
  async ({ message_id }) => {
    return format_api_response_as_mcp_text_content(
      await send_authenticated_request_to_mailpal_rest_api(
        `/inbox/${encodeURIComponent(message_id)}`
      )
    );
  },
);


// Tool 5: mailpal_subscribe_to_inbox -- Real-time push via background SSE
async function start_background_sse_listener_for_inbox_event_notifications(): Promise<void> {
  if (inbox_sse_connection_abort_controller) {
    inbox_sse_connection_abort_controller.abort();
    inbox_sse_connection_abort_controller = null;
  }

  inbox_sse_connection_abort_controller = new AbortController();

  const connect_to_sse_and_relay_events = async (): Promise<void> => {
    try {
      const sse_http_response = await fetch(
        `${MAILPAL_REST_API_BASE_URL}/inbox/events`,
        {
          headers: {
            "Authorization": `Bearer ${MAILPAL_BEARER_AUTH_TOKEN}`,
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
          },
          signal: inbox_sse_connection_abort_controller!.signal,
        },
      );

      if (!sse_http_response.ok || !sse_http_response.body) { return; }

      const response_body_stream_reader = sse_http_response.body.getReader();
      const utf8_text_decoder = new TextDecoder();
      let incomplete_line_buffer = "";

      while (true) {
        const { done: stream_is_exhausted, value: raw_chunk_bytes } =
          await response_body_stream_reader.read();
        if (stream_is_exhausted) { break; }

        incomplete_line_buffer += utf8_text_decoder.decode(raw_chunk_bytes, { stream: true });
        const fully_received_lines = incomplete_line_buffer.split("\n");
        incomplete_line_buffer = fully_received_lines.pop() ?? "";

        for (const sse_event_line of fully_received_lines) {
          if (sse_event_line.startsWith("data:") && subscribed_inbox_resource_uri) {
            try {
              await mailpal_mcp_server_instance.server.sendResourceUpdated({
                uri: subscribed_inbox_resource_uri,
              });
            } catch {
              /* MCP client may not support resource notifications */
            }
          }
        }
      }
    } catch (sse_connection_error: unknown) {
      if (
        sse_connection_error instanceof DOMException &&
        sse_connection_error.name === "AbortError"
      ) {
        return;
      }
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
  "Works on both stdio and Streamable HTTP transports.",
  {},
  async () => {
    if (!MAILPAL_BEARER_AUTH_TOKEN) {
      return format_api_response_as_mcp_text_content({
        error: "MAILPAL_TOKEN environment variable is required for inbox subscription",
        subscribed: false,
      });
    }

    let agent_identifier_from_jwt_subject_claim = "unknown";
    try {
      const jwt_payload_base64_segment = MAILPAL_BEARER_AUTH_TOKEN.split(".")[1];
      if (jwt_payload_base64_segment) {
        const decoded_jwt_payload_object = JSON.parse(
          Buffer.from(jwt_payload_base64_segment, "base64url").toString("utf-8"),
        );
        agent_identifier_from_jwt_subject_claim =
          (decoded_jwt_payload_object as { sub?: string }).sub ?? "unknown";
      }
    } catch {
      /* JWT parsing failed; use placeholder */
    }

    subscribed_inbox_resource_uri =
      `mailpal://inbox/${agent_identifier_from_jwt_subject_claim}`;

    await start_background_sse_listener_for_inbox_event_notifications();

    return format_api_response_as_mcp_text_content({
      subscribed: true,
      uri: subscribed_inbox_resource_uri,
      transport: "stdio",
      message:
        "Listening for new mail. You will receive notifications/resources/updated when new email arrives.",
    });
  },
);


// Tool 6: mailpal_jmap -- Raw JMAP passthrough (escape hatch)
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
  'Flag: [["Email/set", {"update": {"id1": {"keywords/$flagged": true}}}, "f1"]] | ' +
  'Search: [["Email/query", {"filter": {"text": "invoice"}, "limit": 20}, "s1"], ' +
  '["Email/get", {"#ids": {"resultOf": "s1", "name": "Email/query", "path": "/ids"}, ' +
  '"properties": ["id","from","subject","receivedAt","preview"]}, "s2"]] | ' +
  'List folders: [["Mailbox/query", {}, "mq"], ["Mailbox/get", {"#ids": {"resultOf": "mq", ' +
  '"name": "Mailbox/query", "path": "/ids"}, ' +
  '"properties": ["id","name","role","totalEmails","unreadEmails"]}, "mg"]]',
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
    return format_api_response_as_mcp_text_content(
      await send_authenticated_request_to_mailpal_rest_api("/jmap", "POST", {
        using,
        methodCalls: method_calls,
      })
    );
  },
);


async function initialize_and_start_mailpal_mcp_stdio_server(): Promise<void> {
  const stdio_transport_connection = new StdioServerTransport();
  await mailpal_mcp_server_instance.connect(stdio_transport_connection);
}

initialize_and_start_mailpal_mcp_stdio_server().catch((server_startup_error: unknown) => {
  console.error("MailPal MCP server failed to start:", server_startup_error);
  process.exit(1);
});
