/**
 * Cloudflare Pages Function: domeinnaam-beschikbaarheid checken
 * URL: /api/domain-check?name=voorbeeld
 *
 * .com — via de publieke RDAP-dienst van Verisign (opvolger van WHOIS).
 * .be  — DNS Belgium biedt geen RDAP aan voor .be zelf (enkel voor hun
 *        gTLD's .brussels/.vlaanderen), dus hier gebruiken we het klassieke
 *        WHOIS-protocol (poort 43) via een TCP-socket, wat kan dankzij de
 *        cloudflare:sockets runtime-API.
 */

import { connect } from "cloudflare:sockets";

const NAME_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  const raw = (url.searchParams.get("name") || "").trim().toLowerCase();
  const name = raw.replace(/\.(be|com|eu|net|org)$/, "");

  if (!name || !NAME_PATTERN.test(name)) {
    return jsonResponse(
      { error: "Ongeldige domeinnaam. Gebruik enkel letters, cijfers en koppeltekens." },
      400
    );
  }

  const [be, com] = await Promise.all([checkBe(name), checkCom(name)]);

  return jsonResponse({ name, results: { be, com } });
}

async function checkCom(name) {
  const domain = `${name}.com`;
  try {
    const res = await fetch(`https://rdap.verisign.com/com/v1/domain/${domain}`, {
      headers: { accept: "application/rdap+json" },
    });
    if (res.status === 404) return { domain, available: true };
    if (res.status === 200) return { domain, available: false };
    return { domain, available: null };
  } catch (err) {
    return { domain, available: null };
  }
}

async function checkBe(name) {
  const domain = `${name}.be`;
  try {
    const text = await whoisQuery("whois.dns.be", 43, domain);
    const match = text.match(/Status:\s*(NOT AVAILABLE|AVAILABLE)/i);
    if (!match) return { domain, available: null, debug: text.slice(0, 300) };
    return { domain, available: match[1].toUpperCase() === "AVAILABLE" };
  } catch (err) {
    return { domain, available: null, debug: `${err.name}: ${err.message}` };
  }
}

async function whoisQuery(hostname, port, query) {
  const socket = connect({ hostname, port });
  const writer = socket.writable.getWriter();
  await writer.write(new TextEncoder().encode(`${query}\r\n`));
  await writer.close();

  const reader = socket.readable.getReader();
  const decoder = new TextDecoder();
  let text = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    text += decoder.decode(value, { stream: true });
  }

  await socket.close();
  return text;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}
