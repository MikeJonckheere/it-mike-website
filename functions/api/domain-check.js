/**
 * Cloudflare Pages Function: domeinnaam-beschikbaarheid checken
 * URL: /api/domain-check?name=voorbeeld
 *
 * .com — via de publieke RDAP-dienst van Verisign (opvolger van WHOIS),
 *        gratis en zonder key.
 * .be  — DNS Belgium biedt geen RDAP aan voor .be zelf, en het klassieke
 *        WHOIS-protocol (poort 43) draait via ruwe TCP-sockets die op deze
 *        Cloudflare Pages-deployment niet bruikbaar bleken. Daarom via de
 *        WhoisXML Domain Availability API (HTTP/JSON, geen TCP nodig).
 *        Vereist de omgevingsvariabele WHOISXML_API_KEY in Cloudflare Pages
 *        (Settings → Environment variables). Zonder key: available: null.
 */

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

  const [be, com] = await Promise.all([
    checkBe(name, context.env.WHOISXML_API_KEY),
    checkCom(name),
  ]);

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

async function checkBe(name, apiKey) {
  const domain = `${name}.be`;
  if (!apiKey) return { domain, available: null };

  try {
    const params = new URLSearchParams({
      apiKey,
      domainName: domain,
      outputFormat: "JSON",
      credits: "DA",
      mode: "DNS_AND_WHOIS",
    });
    const res = await fetch(`https://domain-availability.whoisxmlapi.com/api/v1?${params}`);
    if (!res.ok) return { domain, available: null };

    const data = await res.json();
    const status = (data.domainAvailability || data.DomainInfo?.domainAvailability || "")
      .toUpperCase();

    if (status === "AVAILABLE") return { domain, available: true };
    if (status === "UNAVAILABLE") return { domain, available: false };
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
