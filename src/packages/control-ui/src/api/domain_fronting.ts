export interface DomainFrontingConfig {
  frontDomain: string;
  originHost: string;
  path?: string;
  headers?: Record<string, string>;
}

export interface PreparedFrontedRequest {
  sni: string;
  hostHeader: string;
  path: string;
  rawHeaderString: string;
}

export function buildFrontedRequest(config: DomainFrontingConfig): PreparedFrontedRequest {
  if (!config.frontDomain) throw new Error("frontDomain is required");
  if (!config.originHost) throw new Error("originHost is required");

  const path = config.path || "/";
  let raw = `GET ${path} HTTP/1.1\r\nHost: ${config.originHost}\r\n`;
  if (config.headers) {
    for (const [k, v] of Object.entries(config.headers)) {
      if (k.toLowerCase() !== "host") {
        raw += `${k}: ${v}\r\n`;
      }
    }
  }
  raw += "\r\n";

  return {
    sni: config.frontDomain,
    hostHeader: config.originHost,
    path,
    rawHeaderString: raw,
  };
}
