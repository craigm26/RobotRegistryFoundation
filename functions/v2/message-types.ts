/**
 * GET /v2/message-types  (R2)
 * Plan 6 Task 5 — RCAN message-type registry.
 *
 * Lists every RCAN message type with its first-supported protocol version
 * and human-readable purpose. Sourced from rcan-spec authoritative tables.
 */

const MESSAGE_TYPES = [
  { name: "INVOKE", since_version: "3.0.0", purpose: "Request a tool invocation against a robot." },
  { name: "TELEMETRY", since_version: "3.0.0", purpose: "Stream a telemetry sample." },
  { name: "STATUS", since_version: "3.0.0", purpose: "Report a robot's current state." },
  { name: "ESTOP", since_version: "3.0.0", purpose: "Trigger a hardware emergency stop." },
  { name: "AUTHORIZE", since_version: "3.1.0", purpose: "HiTL authorization signal." },
  { name: "PENDANT_HEARTBEAT", since_version: "3.2.0", purpose: "Pendant peripheral heartbeat." },
];

export const onRequest: PagesFunction = async ({ request }) => {
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405, headers: { "Content-Type": "application/json" },
    });
  }
  const body = {
    matrix_version: "1.0",
    message_types: MESSAGE_TYPES,
  };
  return new Response(JSON.stringify(body), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300",
    },
  });
};
