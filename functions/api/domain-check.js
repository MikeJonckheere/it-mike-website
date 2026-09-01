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
 *
 * Bescherming van het .be-quotum (500 calls/maand bij WhoisXML):
 *  1. Enkel aanvragen die effectief van it-mike.be zelf komen (Origin/
 *     Referer-check) — blokkeert rechtstreekse curl/script-aanroepen en
 *     inbedding vanaf andere sites.
 *  2. Resultaten worden 10 minuten gecached per naam via Cloudflare's Cache
 *     API — herhaalde checks van dezelfde naam kosten geen extra call.
 *  3. Per IP max. 5 .be-opzoekingen/uur en globaal max. 15/dag, bijgehouden
 *     in een KV-namespace (binding RATE_LIMIT_KV). Zonder die binding wordt
 *     deze stap overgeslagen — de rest blijft gewoon werken.
 */

const NAME_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const ALLOWED_HOSTS = ["it-mike.be", "www.it-mike.be"];
const CACHE_TTL_SECONDS = 600;
const BE_HOURLY_IP_CAP = 5;
const BE_DAILY_GLOBAL_CAP = 15;

export async function onRequestGet(context) {
  const { request, env } = context;
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

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const limited = await isRateLimited(env, ip);

  const [be, com] = await Promise.all([
    limited ? Promise.resolve({ domain: `${name}.be`, available: null }) : checkBe(name, env.WHOISXML_API_KEY),
    checkCom(name),
  ]);

  const payload = JSON.stringify({ name, results: { be, com } });

  if (!limited) {
    const cacheable = new Response(payload, {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": `public, max-age=${CACHE_TTL_SECONDS}`,
      },
    });
    context.waitUntil(cache.put(cacheKey, cacheable));
  }

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

async function isRateLimited(env, ip) {
  if (!env.RATE_LIMIT_KV) return false;

  const now = new Date();
  const day = now.toISOString().slice(0, 10);
  const hour = now.toISOString().slice(0, 13);
  const globalKey = `be:global:${day}`;
  const ipKey = `be:ip:${ip}:${hour}`;

  const [globalCount, ipCount] = await Promise.all([
    env.RATE_LIMIT_KV.get(globalKey),
    env.RATE_LIMIT_KV.get(ipKey),
  ]);

  if (parseInt(globalCount || "0", 10) >= BE_DAILY_GLOBAL_CAP) return true;
  if (parseInt(ipCount || "0", 10) >= BE_HOURLY_IP_CAP) return true;

  await Promise.all([
    env.RATE_LIMIT_KV.put(globalKey, String(parseInt(globalCount || "0", 10) + 1), { expirationTtl: 86400 }),
    env.RATE_LIMIT_KV.put(ipKey, String(parseInt(ipCount || "0", 10) + 1), { expirationTtl: 3600 }),
  ]);

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
