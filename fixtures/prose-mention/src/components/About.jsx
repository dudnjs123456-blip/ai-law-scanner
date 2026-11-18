// 포트폴리오 소개 화면. AI 도구 이름이 소개 문장 안에만 나온다 (이 앱은 AI를 쓰지 않는다)
const projects = [
  { name: '게임', text: '대사마다 ElevenLabs로 만든 목소리를 입혔고, 배경은 Adobe Firefly로 만들었습니다.' },
];
export default function About() {
  return <ul>{projects.map((p) => <li key={p.name}>{p.text}</li>)}</ul>;
}
