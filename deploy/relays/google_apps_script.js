// ============================================================================
// LumiNet Serverless Google Apps Script Relay
// ============================================================================
//
// This script acts as a serverless bridge between the LumiNet Client (GsaTunnelConn)
// and the LumiNet EvasionRelayServer.
//
// How to deploy:
// 1. Go to https://script.google.com/
// 2. Create a new project.
// 3. Paste this code.
// 4. Update the CONFIG variables below.
// 5. Click "Deploy" -> "New deployment" -> Select "Web app".
// 6. Execute as: "Me", Who has access: "Anyone".
// 7. Copy the Web App URL and use it in LumiNet client configuration.

var CONFIG = {
  // Authentication key to authorize requests. Must match the client's CovertGsaKey.
  AUTH_KEY: "covert-gsa-key-change-me",

  // The actual URL of your LumiNet EvasionRelayServer /tunnel endpoint.
  // Note: GsaTunnelConn routes stateful TCP sessions through this relay.
  RELAY_URL: "https://your-evasion-relay-server.com/tunnel"
};

function doPost(e) {
  try {
    // 1. Verify Authentication
    var clientAuth = e.parameter.key || getHeader(e, "X-GSA-Auth-Key");
    if (!clientAuth && e.postData && e.postData.contents) {
      // Fallback check inside payload if headers are stripped by edge proxies
      try {
        var tempPayload = JSON.parse(e.postData.contents);
        if (tempPayload.auth_key) {
          clientAuth = tempPayload.auth_key;
        }
      } catch (ex) {}
    }

    if (clientAuth !== CONFIG.AUTH_KEY) {
      return ContentService.createTextOutput(JSON.stringify({
        error: "Unauthorized: Invalid or missing X-GSA-Auth-Key"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // 2. Extract client payload
    var requestBody = e.postData.contents;

    // 3. Forward to EvasionRelayServer
    var options = {
      method: "post",
      contentType: "application/json",
      payload: requestBody,
      headers: {
        "X-LumiNet-Relay-Hop": "1",
        "X-GSA-Auth-Key": CONFIG.AUTH_KEY
      },
      muteHttpExceptions: true
    };

    var response = UrlFetchApp.fetch(CONFIG.RELAY_URL, options);
    var responseCode = response.getResponseCode();
    var responseBody = response.getContentText();

    // 4. Return response to LumiNet client
    return ContentService.createTextOutput(responseBody)
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({
      error: "Relay Internal Error: " + error.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  // Diagnostic health check
  return ContentService.createTextOutput(JSON.stringify({
    status: "ok",
    service: "LumiNet GSA Serverless Relay",
    version: "1.0.0"
  })).setMimeType(ContentService.MimeType.JSON);
}

function getHeader(e, headerName) {
  if (!e.headers) return null;
  var key = headerName.toLowerCase();
  for (var h in e.headers) {
    if (h.toLowerCase() === key) {
      return e.headers[h];
    }
  }
  return null;
}
