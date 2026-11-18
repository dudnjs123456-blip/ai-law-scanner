export default function DrawPanel() {
  async function go(p: string) { await fetch('/api/draw', { method: 'POST', body: JSON.stringify({ prompt: p }) }); }
  return (<div><input placeholder="그리고 싶은 풍경" onChange={(e) => go(e.target.value)} /><p>이 이미지는 AI가 생성했어요. 워터마크가 포함돼요.</p></div>);
}
