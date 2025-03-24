// main.ts
import {
  Application,
  Context,
  Router,
  Status,
} from "https://deno.land/x/oak@v12.6.1/mod.ts";
import { config as dotenv } from "https://deno.land/x/dotenv@v3.2.2/mod.ts";
import { Logger } from "https://deno.land/std@0.224.0/log/logger.ts";

// 环境变量配置
await dotenv({ export: true });

// 日志配置
const logger = new Logger("openai-proxy", {
  level: "INFO",
  format: "[%datetime%] %levelname% %msg%",
});

// 模型类型定义
interface ChatMessage {
  role: string;
  content: string;
  name?: string;
}

interface ChatCompletionRequest {
  model: string;
  messages: ChatMessage[];
  temperature?: number;
  top_p?: number;
  n?: number;
  stream?: boolean;
  stop?: string[] | string;
  max_tokens?: number;
  presence_penalty?: number;
  frequency_penalty?: number;
  user?: string;
}

// 全局配置
const DEEPSIDER_API_BASE = "https://api.chargpt.ai/api/v2";
let TOKEN_INDEX = 0;

// 模型映射表
const MODEL_MAPPING: Record<string, string> = {
  "gpt-3.5-turbo": "anthropic/claude-3.5-sonnet",
  "gpt-4": "anthropic/claude-3.7-sonnet",
  "gpt-4o": "openai/gpt-4o",
  "gpt-4-turbo": "openai/gpt-4o",
  "gpt-4o-mini": "openai/gpt-4o-mini",
  "claude-3-sonnet-20240229": "anthropic/claude-3.5-sonnet",
  "claude-3-opus-20240229": "anthropic/claude-3.7-sonnet",
  "claude-3.5-sonnet": "anthropic/claude-3.5-sonnet",
  "claude-3.7-sonnet": "anthropic/claude-3.7-sonnet",
};

// 工具函数
function getHeaders(apiKey: string): Headers {
  const tokens = apiKey.split(",");
  const currentToken = tokens[TOKEN_INDEX % tokens.length].trim();
  TOKEN_INDEX = (TOKEN_INDEX + 1) % tokens.length;

  return new Headers({
    "accept": "*/*",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "content-type": "application/json",
    "origin": "chrome-extension://client",
    "i-lang": "zh-CN",
    "i-version": "1.1.64",
    "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "Windows",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
    "user-agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "authorization": `Bearer ${currentToken}`,
  });
}

function mapOpenAIToDeepsiderModel(model: string): string {
  return MODEL_MAPPING[model] || "anthropic/claude-3.7-sonnet";
}

function formatMessagesForDeepsider(messages: ChatMessage[]): string {
  let prompt = "";
  for (const msg of messages) {
    switch (msg.role) {
      case "system":
        prompt = `${msg.content}\n\n${prompt}`;
        break;
      case "user":
        prompt += `Human: ${msg.content}\n\n`;
        break;
      case "assistant":
        prompt += `Assistant: ${msg.content}\n\n`;
        break;
      default:
        prompt += `Human (${msg.role}): ${msg.content}\n\n`;
    }
  }

  if (messages.length > 0 && messages[messages.length - 1].role !== "user") {
    prompt += "Human: ";
  }

  return prompt.trim();
}

// 中间件
async function verifyApiKey(ctx: Context, next: () => Promise<unknown>) {
  const authHeader = ctx.request.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    ctx.throw(Status.Unauthorized, "Invalid API key format");
  }
  ctx.state.apiKey = authHeader.slice(7);
  await next();
}

// 路由配置
const router = new Router();

router.get("/", (ctx: Context) => {
  ctx.response.body = { message: "OpenAI API Proxy服务已启动 连接至DeepSider API" };
});

router.get("/v1/models", verifyApiKey, (ctx: Context) => {
  const models = Object.keys(MODEL_MAPPING).map((model) => ({
    id: model,
    object: "model",
    created: Date.now(),
    owned_by: "openai-proxy",
  }));

  ctx.response.body = {
    object: "list",
    data: models,
  };
});

router.post("/v1/chat/completions", verifyApiKey, async (ctx: Context) => {
  const body = await ctx.request.body().value as ChatCompletionRequest;
  const requestId = `${Date.now()}${Math.random().toString().slice(-6)}`;
  const deepsiderModel = mapOpenAIToDeepsiderModel(body.model);
  const prompt = formatMessagesForDeepsider(body.messages);
  const apiKey = ctx.state.apiKey;

  const payload = {
    model: deepsiderModel,
    prompt,
    webAccess: "close",
    timezone: "Asia/Shanghai",
  };

  try {
    const response = await fetch(
      `${DEEPSIDER_API_BASE}/chat/conversation`,
      {
        method: "POST",
        headers: getHeaders(apiKey),
        body: JSON.stringify(payload),
      },
    );

    if (!response.ok) {
      const errorText = await response.text();
      logger.error(`DeepSider API请求失败: ${response.status} - ${errorText}`);
      ctx.throw(response.status, "API请求失败");
    }

    if (body.stream) {
      ctx.response.type = "text/event-stream";
      ctx.response.body = createStreamResponse(response, requestId, body.model);
    } else {
      const fullResponse = await processNonStreamResponse(response);
      ctx.response.body = generateOpenAIResponse(fullResponse, requestId, body.model);
    }
  } catch (error) {
    logger.error(`处理请求时出错: ${error}`);
    ctx.throw(Status.InternalServerError, error.message);
  }
});

// 流式响应处理
function createStreamResponse(
  response: Response,
  requestId: string,
  model: string,
): ReadableStream<Uint8Array> {
  const timestamp = Math.floor(Date.now() / 1000);
  const reader = response.body!.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  return new ReadableStream({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          controller.enqueue(new TextEncoder().encode("data: [DONE]\n\n"));
          controller.close();
          return;
        }

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;

          try {
            const data = JSON.parse(line.slice(6));
            if (data.code === 202 && data.data?.type === "chat") {
              const content = data.data.content || "";
              const chunk = {
                id: `chatcmpl-${requestId}`,
                object: "chat.completion.chunk",
                created: timestamp,
                model,
                choices: [{
                  index: 0,
                  delta: { content },
                  finish_reason: null,
                }],
              };
              controller.enqueue(
                new TextEncoder().encode(`data: ${JSON.stringify(chunk)}\n\n`),
              );
            } else if (data.code === 203) {
              const chunk = {
                id: `chatcmpl-${requestId}`,
                object: "chat.completion.chunk",
                created: timestamp,
                model,
                choices: [{
                  index: 0,
                  delta: {},
                  finish_reason: "stop",
                }],
              };
              controller.enqueue(
                new TextEncoder().encode(`data: ${JSON.stringify(chunk)}\n\n`),
              );
              controller.enqueue(
                new TextEncoder().encode("data: [DONE]\n\n"),
              );
            }
          } catch (e) {
            logger.warning(`无法解析响应: ${line}`);
          }
        }
      } catch (error) {
        logger.error(`流式响应处理出错: ${error}`);
        controller.close();
      }
    },
  });
}

// 非流式响应处理
async function processNonStreamResponse(response: Response): Promise<string> {
  const reader = response.body!.getReader();
  const decoder = new TextDecoder();
  let fullResponse = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    
    const chunk = decoder.decode(value);
    const lines = chunk.split("\n");
    
    for (const line of lines) {
      if (!line.startsWith("data: ")) continue;
      
      try {
        const data = JSON.parse(line.slice(6));
        if (data.code === 202 && data.data?.type === "chat") {
          fullResponse += data.data.content || "";
        }
      } catch (e) {
        logger.error(`非流式响应出错`);
      }
    }
  }

  return fullResponse;
}

function generateOpenAIResponse(
  content: string,
  requestId: string,
  model: string,
): unknown {
  return {
    id: `chatcmpl-${requestId}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{
      index: 0,
      message: { role: "assistant", content },
      finish_reason: "stop",
    }],
    usage: {
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    },
  };
}

// 应用配置
const app = new Application();
app.use(async (ctx, next) => {
  ctx.response.headers.set("Access-Control-Allow-Origin", "*");
  ctx.response.headers.set("Access-Control-Allow-Methods", "*");
  ctx.response.headers.set("Access-Control-Allow-Headers", "*");
  await next();
});
app.use(router.routes());
app.use(router.allowedMethods());

// 启动服务
const port = parseInt(Deno.env.get("PORT") || "7860");
logger.info(`启动OpenAI API代理服务 端口: ${port}`);
await app.listen({ port });
