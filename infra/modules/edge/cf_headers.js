function handler(event) {
  var response = event.response;
  var headers = response.headers;

  headers['strict-transport-security'] = { value: 'max-age=63072000; includeSubDomains; preload' };
  headers['x-content-type-options'] = { value: 'nosniff' };
  headers['x-frame-options'] = { value: 'DENY' };
  headers['referrer-policy'] = { value: 'no-referrer' };
  // adjust CSP to your needs; this is a sane default for static + API calls
  headers['content-security-policy'] = { value: "default-src 'self'; connect-src 'self' https://*.execute-api.us-east-1.amazonaws.com; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'" };
  return response;
}
