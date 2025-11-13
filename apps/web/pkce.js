export async function startLogin({ domain, clientId, redirectUri }) {
  // 1) Create PKCE verifier
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const verifier = btoa(String.fromCharCode(...array))
                  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/,"");
  localStorage.setItem("pkce_verifier", verifier);

  // 2) Create challenge (S256)
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
                    .replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");

  // 3) Build the authorize URL (code + PKCE)
  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri: redirectUri,
    scope: "openid email profile",
    code_challenge_method: "S256",
    code_challenge: challenge
  });
  window.location = `https://${domain}/oauth2/authorize?${params.toString()}`;
}
