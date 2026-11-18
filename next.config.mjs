/** @type {import('next').NextConfig} */
const nextConfig = {
  // 첫 화면은 public/index.html (진단 페이지)
  async rewrites() {
    return [{ source: '/', destination: '/index.html' }];
  },
  serverExternalPackages: ['tar'],
  // 테스트용 코드와 예전 결과 파일은 서버에 올리지 않는다
  outputFileTracingExcludes: { '*': ['fixtures/**', 'reports/**'] },
};

export default nextConfig;
