/**
 * 보안 뉴스 모으기 — 국내외 보안 뉴스 RSS와 GitHub 보안 권고를 가져와 한 목록으로 합친다.
 * 출처 하나가 실패해도 나머지는 보여준다. 외부 글은 태그를 지우고 글자만 남긴다.
 */

export const SOURCES = [
  { id: 'boho-notice', name: '보호나라 보안공지', lang: 'ko', kind: 'rss', url: 'https://www.boho.or.kr/kr/rss.do?bbsId=B0000133' },
  { id: 'boho-vuln', name: '보호나라 취약점 정보', lang: 'ko', kind: 'rss', url: 'https://www.boho.or.kr/kr/rss.do?bbsId=B0000302' },
  { id: 'dailysecu', name: '데일리시큐', lang: 'ko', kind: 'rss', url: 'https://www.dailysecu.com/rss/allArticle.xml' },
  { id: 'thn', name: 'The Hacker News', lang: 'en', kind: 'rss', url: 'https://feeds.feedburner.com/TheHackersNews' },
  { id: 'bleeping', name: 'BleepingComputer', lang: 'en', kind: 'rss', url: 'https://www.bleepingcomputer.com/feed/' },
  { id: 'socket', name: 'Socket 블로그', lang: 'en', kind: 'rss', url: 'https://socket.dev/api/blog/feed.atom' },
  { id: 'gh-malware', name: 'GitHub 악성 패키지', lang: 'en', kind: 'ghsa', url: 'https://api.github.com/advisories?type=malware&per_page=100' },
  { id: 'gh-reviewed', name: 'GitHub 보안 권고', lang: 'en', kind: 'ghsa', url: 'https://api.github.com/advisories?type=reviewed&per_page=40' },
];

// 주제 — 제목·요약에 들어간 낱말로 나눈다 (하나의 글이 여러 주제에 들 수 있다)
export const TOPICS = [
  ['ai', 'AI 보안', /\b(AI|LLM|GPT|ChatGPT|Claude|Gemini|Copilot|MCP|agentic|chatbot|deepfake|machine learning)\b|prompt injection|인공지능|생성형|프롬프트|에이전트|챗봇|딥페이크|AI\s?보안|AI\s?기본법/i],
  ['supply', '공급망·악성 패키지', /\b(npm|PyPI|pip|crates\.io|RubyGems|NuGet|Maven|Go module|open[- ]source|typosquat\w*|dependency|dependencies|packages?|supply[- ]chain|GitHub Actions?|VS ?Code extension)\b|malware in|공급망|오픈소스|패키지|라이브러리/i],
  ['vuln', '취약점·패치', /\b(CVEs?|vulnerabilit\w*|flaws?|zero[- ]day|0-day|exploit\w*|patch\w*|RCE|bug)\b|취약점|보안 업데이트|패치|제로데이/i],
  ['breach', '해킹·유출', /\b(breach\w*|leak\w*|ransomware|hack\w*|stolen|data theft|phishing|botnet)\b|유출|랜섬웨어|해킹|침해|피싱|봇넷|악성코드/i],
  ['policy', '법·정책', /\b(regulations?|regulators?|laws?|lawsuit|fined|GDPR|FTC|EU|AI Act|sanction\w*|indict\w*|arrest\w*)\b|법안|법률|법령|개정안|기본법|보호법|규제|과징금|과태료|가이드라인|정책|개인정보|당국|검거|기소/i],
];

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', hellip: '…', middot: '·', rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“', ndash: '–', mdash: '—' };
function decode(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(n) && n > 0 && n < 0x110000 ? String.fromCodePoint(n) : '';
    }
    return ENT[e.toLowerCase()] ?? m;
  });
}
const cdata = (s) => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
// 태그를 지우고 글자만 (decode 를 두 번 하는 건 &amp;lt; 처럼 두 번 감싼 글 때문)
const text = (s) => decode(decode(cdata(s ?? '')).replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
const cut = (s, n) => (s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s);

function tag(block, name) {
  const m = block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i'));
  return m ? m[1] : '';
}
function atomLink(block) {
  const links = [...block.matchAll(/<link\b([^>]*)\/?>/gi)].map((m) => m[1]);
  const pick = links.find((a) => /rel=["']alternate["']/.test(a)) ?? links.find((a) => !/rel=/.test(a)) ?? links[0] ?? '';
  return (pick.match(/href=["']([^"']+)["']/) ?? [])[1] ?? '';
}

// 국내 피드는 "2026-11-19 13:58:26"처럼 시간대 없이 오므로 한국 시간으로 읽는다
function parseDate(raw) {
  const s = text(raw);
  if (!s) return null;
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?$/);
  const d = m ? new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4] ?? '00'}:${m[5] ?? '00'}:${m[6] ?? '00'}+09:00`) : new Date(s);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function safeUrl(u) {
  try {
    const url = new URL(decode(cdata(u)).trim());
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

export function parseFeed(xml) {
  const blocks = [...xml.matchAll(/<(item|entry)\b[\s\S]*?<\/\1>/gi)].map((m) => m[0]);
  return blocks.map((b) => {
    const isAtom = /^<entry/i.test(b);
    return {
      title: text(tag(b, 'title')),
      url: safeUrl(isAtom ? atomLink(b) : tag(b, 'link') || tag(b, 'guid')),
      summary: cut(text(tag(b, 'description') || tag(b, 'summary') || tag(b, 'content')), 220),
      // 요약할 때 본문을 못 받으면 쓰는 피드 원문 (화면 목록에는 보내지 않음)
      desc: cut(text(tag(b, 'content:encoded') || tag(b, 'content') || tag(b, 'description') || tag(b, 'summary')), 6000),
      date: parseDate(tag(b, 'pubDate') || tag(b, 'published') || tag(b, 'updated') || tag(b, 'dc:date')),
    };
  });
}

function advisoryItem(a) {
  const pkgs = [...new Set((a.vulnerabilities ?? []).map((v) => v.package && `${v.package.ecosystem}:${v.package.name}`).filter(Boolean))];
  const bits = [a.severity && a.severity !== 'unknown' ? `위험도 ${a.severity}` : '', pkgs.length ? pkgs.slice(0, 3).join(', ') + (pkgs.length > 3 ? ` 외 ${pkgs.length - 3}개` : '') : '', a.cve_id ?? ''];
  return {
    title: text(a.summary ?? a.ghsa_id ?? ''),
    url: safeUrl(a.html_url ?? ''),
    summary: bits.filter(Boolean).join(' · '),
    desc: String(a.description ?? '').slice(0, 20_000),
    patched: (a.vulnerabilities ?? []).filter((v) => v.package && v.first_patched_version).map((v) => `${v.package.name} ${v.first_patched_version}`).slice(0, 5),
    date: parseDate(a.published_at ?? a.updated_at ?? ''),
    severity: a.severity ?? null,
    // GitHub 악성 패키지 목록은 모두 공급망 주제
    forceTopics: a.type === 'malware' ? ['supply'] : pkgs.length ? ['vuln'] : [],
  };
}

// 악성 패키지는 한 번에 수십 개씩 올라오므로 같은 시간(1시간 단위)·같은 생태계끼리 한 글로 묶는다
export function parseAdvisories(list) {
  list = Array.isArray(list) ? list : [];
  const out = [];
  const groups = new Map();
  for (const a of list) {
    if (a.type !== 'malware') { out.push(advisoryItem(a)); continue; }
    const eco = a.vulnerabilities?.[0]?.package?.ecosystem ?? '';
    const key = `${eco}|${String(a.published_at ?? '').slice(0, 13)}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(a);
  }
  for (const g of groups.values()) {
    if (g.length === 1) { out.push(advisoryItem(g[0])); continue; }
    const names = [...new Set(g.flatMap((a) => (a.vulnerabilities ?? []).map((v) => v.package?.name)).filter(Boolean))];
    const eco = g[0].vulnerabilities?.[0]?.package?.ecosystem ?? '';
    out.push({
      title: text(`${eco} 악성 패키지 ${g.length}개 신고됨`),
      url: safeUrl(g[0].html_url ?? ''),
      summary: cut(text(names.slice(0, 6).join(', ') + (names.length > 6 ? ` 외 ${names.length - 6}개` : '')), 220),
      date: g.map((a) => parseDate(a.published_at ?? '')).filter(Boolean).sort().pop() ?? null,
      severity: 'critical',
      forceTopics: ['supply'],
      group: names.length,
    });
  }
  return out.sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''));
}

function topicsOf(item) {
  const hay = `${item.title} ${item.summary}`;
  const t = new Set(item.forceTopics ?? []);
  for (const [id, , re] of TOPICS) if (re.test(hay)) t.add(id);
  return [...t];
}

async function load(src, fetchOpts) {
  const headers = { 'User-Agent': 'ai-law-scanner (security news)', Accept: src.kind === 'ghsa' ? 'application/vnd.github+json' : 'application/rss+xml, application/atom+xml, application/xml, text/xml' };
  if (src.kind === 'ghsa' && process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetch(src.url, { headers, signal: AbortSignal.timeout(12_000), ...fetchOpts });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const body = await res.text();
  if (body.length > 5_000_000) throw new Error('너무 큰 응답');
  return src.kind === 'ghsa' ? parseAdvisories(JSON.parse(body)) : parseFeed(body);
}

/** 모든 출처를 동시에 가져와 최신순으로 합친다. */
export async function collectNews({ fetchOpts = {}, perSource = 30, maxAgeDays = 60 } = {}) {
  const since = Date.now() - maxAgeDays * 86_400_000;
  const results = await Promise.allSettled(SOURCES.map((s) => load(s, fetchOpts)));
  const seen = new Set();
  const items = [];
  const sources = SOURCES.map((s, i) => {
    const r = results[i];
    if (r.status === 'rejected') return { id: s.id, name: s.name, lang: s.lang, ok: false, count: 0, error: String(r.reason?.message ?? r.reason).slice(0, 120) };
    let count = 0;
    for (const it of r.value.slice(0, perSource)) {
      if (!it.title || !it.url || seen.has(it.url)) continue;
      if (it.date && Date.parse(it.date) < since) continue;
      seen.add(it.url);
      const { forceTopics, ...rest } = it;
      items.push({ ...rest, source: s.id, sourceName: s.name, lang: s.lang, topics: topicsOf(it) });
      count++;
    }
    return { id: s.id, name: s.name, lang: s.lang, ok: true, count };
  });
  items.sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''));
  return { updatedAt: new Date().toISOString(), topics: TOPICS.map(([id, label]) => ({ id, label })), sources, items };
}
