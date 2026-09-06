// SPDX-License-Identifier: MIT
//
// dnscrypt stamp-feed detection for the import flow (roadmap item 5).
// Pure text heuristics only — actual sdns:// parsing lives in the daemon
// (networking/dns/dnsstamp.go, integrations/sub/parser_stamps.go); the UI
// just needs to detect stamp lines so users are told where they belong.

export interface StampFeedSplit {
  /** Lines that are raw sdns:// stamps (DNS resolver configs). */
  stamps: string[];
  /** Everything else (share links, base64, YAML, …). */
  other: string[];
}

const STAMP_PREFIX = 'sdns://';

function isStampLine(line: string): boolean {
  return line.trim().toLowerCase().startsWith(STAMP_PREFIX);
}

/** Split imported subscription text into stamp lines and everything else. */
export function splitStampFeed(text: string): StampFeedSplit {
  const stamps: string[] = [];
  const other: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (isStampLine(line)) {
      stamps.push(line.trim());
    } else if (line.trim() !== '') {
      other.push(line);
    }
  }
  return { stamps, other };
}

/** Human-facing summary for the import hint. Empty string when no stamps. */
export function stampFeedHint(text: string): string {
  const { stamps } = splitStampFeed(text);
  if (stamps.length === 0) {
    return '';
  }
  const noun = stamps.length === 1 ? 'stamp' : 'stamps';
  return (
    `${stamps.length} dnscrypt DNS ${noun} detected. ` +
    'DNS stamps configure resolvers, not proxy nodes — import them under DNS settings.'
  );
}
