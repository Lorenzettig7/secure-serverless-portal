function handler(event) {
  var request = event.request;
  var uri = request.uri;

  // If /dir/ -> serve /dir/index.html
  if (uri.endsWith('/')) {
    request.uri += 'index.html';
    return request;
  }

  // If no file extension (no dot), treat as virtual directory -> /index.html
  if (!uri.includes('.')) {
    request.uri += '/index.html';
    return request;
  }

  // If the URI already has an extension (e.g., .html, .js, .css, .png), DO NOT rewrite
  return request;
}

