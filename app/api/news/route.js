/**
 * GET /api/news — 최신 보안 뉴스 목록
 *
 * 30분마다 새로 모은다(ISR). 그 사이 요청은 저장해 둔 결과를 바로 돌려주므로
 * 방문자가 많아도 뉴스 사이트와 GitHub API 에 부담을 주지 않는다.
 */
import { collectNews } from '../../../lib/news.mjs';

export const runtime = 'nodejs';
export const revalidate = 1800;

export async function GET() {
  const data = await collectNews({ fetchOpts: { next: { revalidate: 1800 } } });
  // 요약용 원문(desc·patched)은 목록에서 빼서 응답을 가볍게 한다
  const items = data.items.map(({ desc, patched, ...rest }) => ({ ...rest, summarizable: !rest.group }));
  return Response.json({ ...data, items }, {
    headers: { 'Cache-Control': 'public, s-maxage=1800, stale-while-revalidate=3600' },
  });
}
