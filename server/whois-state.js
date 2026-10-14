// WHOIS text -> 'available' | 'registered' | 'unknown'. Registries word "not found" in many ways; rate-limit replies are never treated as a verdict.
const FREE = /(no match for|not found|no data found|no entries found|no object found|nothing found|no such domain|not registered|available for registration|does not exist|^\s*status:\s*(free|available)|\bis (free|available)\s*$)/mi;
const LIMITED = /(rate.?limit|too many (queries|requests|connections)|query limit|quota exceeded|access denied|blacklisted|try again later|exceeded)/i;
export function whoisState(t) {
  if (!t || !t.trim()) return 'unknown';
  const hasDom = /^\s*domain( name)?\s*:\s*\S/mi.test(t);
  if (t.length < 1500 && LIMITED.test(t) && !hasDom) return 'unknown';
  if (t.length < 4000 && FREE.test(t) && !(hasDom && /^\s*(registrar|registry domain id|creation date|created|registered)\b/mi.test(t))) return 'available';
  return hasDom ? 'registered' : 'unknown';
}

