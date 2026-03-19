/**
 * Cloudflare Pages Function: GitHub OAuth proxy voor Decap CMS
 * URL: /api/auth
 *
 * Vereiste omgevingsvariabelen (in Cloudflare Pages dashboard):
 *   GITHUB_CLIENT_ID     — van je GitHub OAuth App
 *   GITHUB_CLIENT_SECRET — van je GitHub OAuth App
 */
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const code = url.searchParams.get("code");

  // Stap 1: geen code → redirect naar GitHub login
  if (!code) {
    const params = new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      redirect_uri: `${url.origin}/api/auth`,
      scope: "repo",
    });
    return Response.redirect(
      `https://github.com/login/oauth/authorize?${params}`,
      302
    );
  }

  // Stap 2: code aanwezig → wissel in voor access token
  const tokenRes = await fetch(
    "https://github.com/login/oauth/access_token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
      }),
    }
  );

  const tokenData = await tokenRes.json();

  if (tokenData.error) {
    return new Response(
      `Authenticatie mislukt: ${tokenData.error_description}`,
      { status: 400 }
    );
  }

  // Stap 3: geef token terug aan Decap CMS via postMessage
  const authPayload = JSON.stringify({
    token: tokenData.access_token,
    provider: "github",
  });

  const html = `<!DOCTYPE html>
<html>
<body>
<script>
(function () {
  var payload = ${JSON.stringify("authorization:github:success:" + authPayload)};
  function receiveMessage(e) {
    window.opener.postMessage(payload, e.origin);
  }
  window.addEventListener("message", receiveMessage, false);
  window.opener.postMessage("authorizing:github", "*");
})();
</script>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html" },
  });
}
