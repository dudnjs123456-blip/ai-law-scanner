/**
 * GET /api/summary?url=<기사 주소> — 기사 핵심 요약
 *
 * - 지금 보안 뉴스 목록에 있는 기사만 요약한다 (아무 주소나 대신 받아 주는 통로가 되지 않게)
 * - 기사 본문을 받아 lib/summarize.mjs 로 중요한 문장을 고른다. 본문을 못 받으면 피드 원문으로 요약한다
 * - 같은 기사는 하루 동안 CDN 에 저장해 두므로 다시 요약하지 않는다
 */
import { collectNews } from '../../../lib/news.mjs';
import { extractArticle, markdownToText, summarize } from '../../../lib/summarize.mjs';

export const runtime = 'nodejs';
export const maxDuration = 20;

const UA = 'Mozilla/5.0 (compatible; ai-law-scanner/0.6; +https://ai-law-scanner.vercel.app)';
const json = (body, status = 200, cache = 'public, s-maxage=86400, stale-while-revalidate=604800') =>
  Response.json(body, { status, headers: { 'Cache-Control': status === 200 ? cache : 'no-store' } });

async function fetchBody(url) {
  const res = await fetch(url, { headers: { 'User-Agent': UA, Accept: 'text/html' }, redirect: 'follow', signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > 3_000_000) { reader.cancel(); break; }
    chunks.push(value);
  }
  return extractArticle(new TextDecoder('utf-8').decode(Buffer.concat(chunks)));
}

export async function GET(req) {
  const url = new URL(req.url).searchParams.get('url') ?? '';
  const news = await collectNews({ fetchOpts: { next: { revalidate: 1800 } } });
  const item = news.items.find((i) => i.url === url);
  if (!item) return json({ error: '보안 뉴스 목록에 있는 기사만 요약할 수 있어요.' }, 404);
  if (item.group) return json({ error: '여러 패키지를 묶은 항목이라 요약하지 않아요.' }, 400);

  let text = '';
  let from = 'article';
  if (item.source.startsWith('gh-')) {
    text = markdownToText(item.desc);
    from = 'advisory';
  } else {
    try { text = await fetchBody(url); } catch { text = ''; }
    // 본문이 너무 짧으면(차단·로그인 화면 등) 피드에 실린 글로 대신한다
    if (text.length < Math.min(400, (item.desc ?? '').length)) { text = item.desc ?? ''; from = 'feed'; }
  }
  const s = await summarize({ title: item.title, text, lang: item.lang });
  if (item.patched?.length && !s.action) s.action = `고친 버전: ${item.patched.join(', ')} 이상으로 올리세요.`;
  else if (item.patched?.length) s.patched = item.patched;
  if (!s.points.length) return json({ error: '요약할 본문을 찾지 못했어요.' }, 422);
  return json({ url, from, ...s });
}
