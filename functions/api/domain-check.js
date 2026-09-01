/**
 * Cloudflare Pages Function: domeinnaam-beschikbaarheid checken
 * URL: /api/domain-check?name=voorbeeld
 *
 * Controleert of "voorbeeld.be" en "voorbeeld.com" nog vrij zijn via de
 * officiële RDAP-diensten van DNS Belgium en Verisign (opvolger van WHOIS).
 * Geen API-key nodig — RDAP is publiek en open.
 */

const RDAP_ENDPOINTS = {
  be: (domain) => `https://rdap.dnsbelgium.be/domain/${domain}`,
  com: (domain) => `https://rdap.verisign.com/com/v1/domain/${domain}`,
};

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

  const tlds = Object.keys(RDAP_ENDPOINTS);
  const checks = await Promise.all(tlds.map((tld) => checkTld(name, tld)));

  const results = {};
  tlds.forEach((tld, i) => {
    results[tld] = checks[i];
  });

  return jsonResponse({ name, results });
}

async function checkTld(name, tld) {
  const domain = `${name}.${tld}`;
  try {
    const res = await fetch(RDAP_ENDPOINTS[tld](domain), {
      headers: { accept: "application/rdap+json" },
    });

    if (res.status === 404) return { domain, available: true };
    if (res.status === 200) return { domain, available: false };
    return { domain, available: null };
  } catch (err) {
    return { domain, available: null };
  }
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
