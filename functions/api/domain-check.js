/**
 * Cloudflare Pages Function: domeinnaam-beschikbaarheid checken
 * URL: /api/domain-check?name=voorbeeld
 *
 * .com — live via de publieke RDAP-dienst van Verisign (opvolger van
 *        WHOIS), gratis en zonder key.
 * .be  — DNS Belgium biedt geen RDAP aan voor .be zelf. Het klassieke
 *        WHOIS-protocol (poort 43) via ruwe TCP-sockets bleek niet bruikbaar
 *        op deze Cloudflare Pages-deployment, en een betaalde WHOIS-API
 *        (WhoisXML) gaf voor .be onbetrouwbare resultaten. Daarom geeft
 *        deze functie voor .be altijd available: null terug; de pagina
 *        linkt in dat geval door naar de officiële checker van DNS
 *        Belgium.
 *
 * Bescherming tegen misbruik: enkel aanvragen die effectief van
 * it-mike.be zelf komen (Origin/Referer-check) worden aanvaard, en
 * resultaten worden 10 minuten gecached per naam via Cloudflare's Cache API.
 */

const NAME_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const ALLOWED_HOSTS = ["it-mike.be", "www.it-mike.be"];
const CACHE_TTL_SECONDS = 600;

export async function onRequestGet(context) {
  const { request } = context;
  const url = new URL(request.url);

  if (!isAllowedOrigin(request)) {
    return jsonResponse({ error: "Niet toegestaan." }, 403);
  }

  const raw = (url.searchParams.get("name") || "").trim().toLowerCase();
  const name = raw.replace(/\.(be|com|eu|net|org)$/, "");

  if (!name || !NAME_PATTERN.test(name)) {
    return jsonResponse(
      { error: "Ongeldige domeinnaam. Gebruik enkel letters, cijfers en koppeltekens." },
      400
    );
  }

  const cache = caches.default;
  const cacheKey = new Request(`https://cache.internal/domain-check/${name}`);
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  const com = await checkCom(name);
  const be = { domain: `${name}.be`, available: null };

  const payload = JSON.stringify({ name, results: { be, com } });

  const cacheable = new Response(payload, {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": `public, max-age=${CACHE_TTL_SECONDS}`,
    },
  });
  context.waitUntil(cache.put(cacheKey, cacheable));

  return new Response(payload, {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function isAllowedOrigin(request) {
  const check = (value) => {
    try {
      const h = new URL(value).hostname;
      return ALLOWED_HOSTS.includes(h) || h.endsWith(".pages.dev");
    } catch (err) {
      return false;
    }
  };
  const origin = request.headers.get("Origin");
  if (origin) return check(origin);
  const referer = request.headers.get("Referer");
  if (referer) return check(referer);
  return false;
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

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}
