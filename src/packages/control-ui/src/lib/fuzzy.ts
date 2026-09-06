export interface FuzzyMatch {
  matched: boolean;
  score: number;
  indices: number[];
}

// fuzzyMatch is a deterministic subsequence matcher designed for short command
// labels. It keeps cdin's useful consecutive-run bias, then hardens it with
// word-boundary/prefix bonuses and bounded gap/length penalties.
export function fuzzyMatch(candidate: string, query: string): FuzzyMatch {
  const haystack = candidate.trim();
  const needle = query.trim();
  if (!needle) return { matched: true, score: 0, indices: [] };
  if (!haystack) return { matched: false, score: Number.NEGATIVE_INFINITY, indices: [] };

  const lowerCandidate = haystack.toLocaleLowerCase();
  const lowerQuery = needle.toLocaleLowerCase();
  if (lowerCandidate === lowerQuery) {
    return { matched: true, score: 10_000 - haystack.length, indices: [...haystack].map((_, index) => index) };
  }

  const indices: number[] = [];
  let cursor = 0;
  let score = 0;
  let run = 0;
  for (let q = 0; q < lowerQuery.length; q += 1) {
    const wanted = lowerQuery[q];
    let found = -1;
    for (let i = cursor; i < lowerCandidate.length; i += 1) {
      if (lowerCandidate[i] === wanted) {
        found = i;
        break;
      }
    }
    if (found < 0) return { matched: false, score: Number.NEGATIVE_INFINITY, indices: [] };

    indices.push(found);
    const gap = found - cursor;
    const boundary = found === 0 || /[\s/_-]/.test(haystack[found - 1] ?? '');
    const exactCase = haystack[found] === needle[q];
    run = gap === 0 ? run + 1 : 1;
    score += run * 12;
    if (boundary) score += 24;
    if (exactCase) score += 2;
    score -= gap * 4;
    cursor = found + 1;
  }

  if (lowerCandidate.startsWith(lowerQuery)) score += 300;
  score -= Math.max(0, haystack.length - needle.length);
  return { matched: true, score, indices };
}
