import OpenAI from 'openai';
const client = new OpenAI();
export async function POST(req: Request) {
  const { prompt } = await req.json();
  const img = await client.images.generate({ model: 'gpt-image-1', prompt });
  return Response.json(img);
}
