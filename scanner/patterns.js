/**
 * Central pattern registry for all scanners.
 * Each pattern: { name, pattern, severity, category, description, falsePositiveFilter?, requiresContext? }
 */

const SCAN_PATTERNS = {
  // ── API Keys & Tokens ──
  apiKeys: [
    { name: "AWS Access Key ID", pattern: /(?:^|[^A-Za-z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9]|$)/g, severity: "critical", category: "api-key", description: "AWS Access Key ID found. Can grant access to AWS services." },
    { name: "AWS Secret Access Key", pattern: /(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: "critical", category: "api-key", description: "AWS Secret Access Key found." },
    { name: "Google API Key", pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: "high", category: "api-key", description: "Google API Key detected." },
    { name: "Google OAuth Client ID", pattern: /[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com/g, severity: "medium", category: "api-key", description: "Google OAuth Client ID found." },
    { name: "Google OAuth Client Secret", pattern: /GOCSPX-[A-Za-z0-9_-]{28}/g, severity: "critical", category: "api-key", description: "Google OAuth Client Secret found." },
    { name: "Stripe Secret Key", pattern: /sk_live_[0-9a-zA-Z]{24,99}/g, severity: "critical", category: "api-key", description: "Stripe Secret Key found." },
    { name: "Stripe Publishable Key", pattern: /pk_live_[0-9a-zA-Z]{24,99}/g, severity: "low", category: "api-key", description: "Stripe Publishable Key (intended to be public)." },
    { name: "Stripe Test Key", pattern: /(?:sk_test|pk_test)_[0-9a-zA-Z]{24,99}/g, severity: "medium", category: "api-key", description: "Stripe test key found in production." },
    { name: "GitHub Personal Access Token", pattern: /ghp_[A-Za-z0-9_]{36,255}/g, severity: "critical", category: "api-key", description: "GitHub PAT found." },
    { name: "GitHub OAuth Token", pattern: /gho_[A-Za-z0-9_]{36,255}/g, severity: "critical", category: "api-key", description: "GitHub OAuth Token found." },
    { name: "GitHub App Token", pattern: /(?:ghs|ghr)_[A-Za-z0-9_]{36,255}/g, severity: "critical", category: "api-key", description: "GitHub App Token found." },
    { name: "GitLab Token", pattern: /glpat-[A-Za-z0-9\-_]{20,}/g, severity: "critical", category: "api-key", description: "GitLab PAT found." },
    { name: "GitLab Pipeline Token", pattern: /glptt-[A-Za-z0-9\-_]{20,}/g, severity: "critical", category: "api-key", description: "GitLab Pipeline Trigger Token found." },
    { name: "Slack Token", pattern: /xox[bporas]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g, severity: "critical", category: "api-key", description: "Slack API Token found." },
    { name: "Slack Webhook URL", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g, severity: "high", category: "api-key", description: "Slack Webhook URL found." },
    { name: "Discord Webhook", pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g, severity: "high", category: "api-key", description: "Discord Webhook URL found." },
    { name: "Discord Bot Token", pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g, severity: "critical", category: "api-key", description: "Discord Bot Token found." },
    { name: "Twilio API Key", pattern: /SK[0-9a-fA-F]{32}/g, severity: "high", category: "api-key", description: "Twilio API Key found." },
    { name: "Twilio Account SID", pattern: /AC[a-z0-9]{32}/g, severity: "medium", category: "api-key", description: "Twilio Account SID found." },
    { name: "SendGrid API Key", pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g, severity: "critical", category: "api-key", description: "SendGrid API Key found." },
    { name: "Mailgun API Key", pattern: /key-[0-9a-zA-Z]{32}/g, severity: "high", category: "api-key", description: "Mailgun API Key found." },
    { name: "Mailchimp API Key", pattern: /[0-9a-f]{32}-us\d{1,2}/g, severity: "high", category: "api-key", description: "Mailchimp API Key found." },
    { name: "Firebase Key", pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g, severity: "high", category: "api-key", description: "Firebase Cloud Messaging Key found." },
    { name: "Heroku API Key", pattern: /[hH]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/gi, severity: "high", category: "api-key", description: "Heroku API Key found." },
    { name: "Private Key Block", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g, severity: "critical", category: "api-key", description: "Private key found in source." },
    { name: "JSON Web Token", pattern: /eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}/g, severity: "high", category: "api-key", description: "JWT token found." },
    { name: "Bearer Token", pattern: /['"][Bb]earer\s+[A-Za-z0-9\-_\.~\+\/]{20,}=*['"]/g, severity: "high", category: "api-key", description: "Bearer token found in source." },
    { name: "Basic Auth Credentials", pattern: /['"][Bb]asic\s+[A-Za-z0-9+\/]{16,}={0,2}['"]/g, severity: "high", category: "api-key", description: "Basic auth credentials (Base64 encoded)." },
    { name: "Shopify Access Token", pattern: /shpat_[a-fA-F0-9]{32}/g, severity: "critical", category: "api-key", description: "Shopify Admin API Token found." },
    { name: "Shopify Shared Secret", pattern: /shpss_[a-fA-F0-9]{32}/g, severity: "critical", category: "api-key", description: "Shopify Shared Secret found." },
    { name: "PayPal Braintree Token", pattern: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g, severity: "critical", category: "api-key", description: "PayPal/Braintree production token found." },
    { name: "Square Access Token", pattern: /sq0atp-[0-9A-Za-z\-_]{22}/g, severity: "critical", category: "api-key", description: "Square Access Token found." },
    { name: "Square OAuth Secret", pattern: /sq0csp-[0-9A-Za-z\-_]{43}/g, severity: "critical", category: "api-key", description: "Square OAuth Secret found." },
    { name: "Telegram Bot Token", pattern: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/g, severity: "high", category: "api-key", description: "Telegram Bot Token found." },
    { name: "Algolia API Key", pattern: /[a-f0-9]{32}/g, severity: "low", category: "api-key", description: "Potential Algolia/generic 32-char hex key.", requiresContext: true },
    { name: "Mapbox Token", pattern: /pk\.[a-zA-Z0-9]{60,}/g, severity: "medium", category: "api-key", description: "Mapbox public token found." },
    { name: "OpenAI API Key (legacy)", pattern: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/g, severity: "critical", category: "api-key", description: "OpenAI API Key found (legacy format)." },
    { name: "OpenAI Service Account", pattern: /sk-svcacct-[A-Za-z0-9_-]{40,}/g, severity: "critical", category: "api-key", description: "OpenAI service account key found." },
    { name: "OpenAI API Key", pattern: /sk-(?!proj-|ant-|or-|svcacct-|live_|test_)[A-Za-z0-9_-]{32,}/g, severity: "high", category: "api-key", description: "Potential OpenAI/DeepSeek API key found." },
    { name: "Anthropic API Key", pattern: /sk-ant-[A-Za-z0-9\-_]{20,}/g, severity: "critical", category: "api-key", description: "Anthropic API Key found." },
    { name: "Supabase Key", pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}/g, severity: "medium", category: "api-key", description: "Supabase anon/service key found." },
    { name: "Datadog API Key", pattern: /(?:dd|datadog)[_-]?(?:api[_-]?key|app[_-]?key)\s*[:=]\s*['"]([a-f0-9]{32,40})['"]/gi, severity: "high", category: "api-key", description: "Datadog API Key found." },
    { name: "New Relic Key", pattern: /NRAK-[A-Z0-9]{27}/g, severity: "high", category: "api-key", description: "New Relic API Key found." },
    { name: "Sentry DSN", pattern: /https:\/\/[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io\/\d+/g, severity: "medium", category: "api-key", description: "Sentry DSN found. Can be used to send fake error data." },
    { name: "Cloudflare API Key", pattern: /(?:cloudflare)[_-]?(?:api[_-]?key)\s*[:=]\s*['"]([a-f0-9]{37})['"]/gi, severity: "critical", category: "api-key", description: "Cloudflare API Key found." },
    { name: "DigitalOcean Token", pattern: /dop_v1_[a-f0-9]{64}/g, severity: "critical", category: "api-key", description: "DigitalOcean Personal Access Token found." },
    { name: "NPM Token", pattern: /npm_[A-Za-z0-9]{36}/g, severity: "critical", category: "api-key", description: "NPM access token found." },
    { name: "PyPI Token", pattern: /pypi-[A-Za-z0-9_-]{50,}/g, severity: "critical", category: "api-key", description: "PyPI API token found." },
    { name: "Vault Token", pattern: /hvs\.[A-Za-z0-9_-]{24,}/g, severity: "critical", category: "api-key", description: "HashiCorp Vault token found." },
    // ── Additional API Keys (2024+) ──
    { name: "OpenAI Project Key", pattern: /sk-proj-[A-Za-z0-9_-]{40,}/g, severity: "critical", category: "api-key", description: "OpenAI project API key found." },
    { name: "Groq API Key", pattern: /gsk_[A-Za-z0-9]{48,}/g, severity: "critical", category: "api-key", description: "Groq API key found." },
    { name: "Mistral API Key", pattern: /[a-zA-Z0-9]{32}:fx/g, severity: "high", category: "api-key", description: "Potential Mistral/DeepL API key found." },
    { name: "Cohere API Key", pattern: /[a-zA-Z0-9]{40}/g, severity: "low", category: "api-key", description: "Potential Cohere API key.", requiresContext: true },
    { name: "Replicate API Token", pattern: /r8_[A-Za-z0-9]{37}/g, severity: "critical", category: "api-key", description: "Replicate API token found." },
    { name: "HuggingFace Token", pattern: /hf_[A-Za-z0-9]{34,}/g, severity: "critical", category: "api-key", description: "HuggingFace API token found." },
    { name: "Vercel Token", pattern: /(?:vercel|vc)_[A-Za-z0-9_-]{24,}/gi, severity: "high", category: "api-key", description: "Vercel deployment token found." },
    { name: "Supabase Service Role", pattern: /sbp_[a-f0-9]{40,}/g, severity: "critical", category: "api-key", description: "Supabase service role key found." },
    { name: "PlanetScale Token", pattern: /pscale_tkn_[A-Za-z0-9_-]{30,}/g, severity: "critical", category: "api-key", description: "PlanetScale database token found." },
    { name: "Notion API Key", pattern: /ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{43}/g, severity: "high", category: "api-key", description: "Notion API integration token found." },
    { name: "Linear API Key", pattern: /lin_api_[A-Za-z0-9]{40,}/g, severity: "high", category: "api-key", description: "Linear API key found." },
    { name: "Airtable API Key", pattern: /pat[A-Za-z0-9]{14}\.[a-f0-9]{64}/g, severity: "high", category: "api-key", description: "Airtable personal access token found." },
    { name: "Contentful Token", pattern: /CFPAT-[A-Za-z0-9_-]{43}/g, severity: "high", category: "api-key", description: "Contentful personal access token found." },
    { name: "Figma Token", pattern: /figd_[A-Za-z0-9_-]{40,}/g, severity: "high", category: "api-key", description: "Figma personal access token found." },
    { name: "Livekit API Key", pattern: /API[a-zA-Z0-9]{20,}/g, severity: "medium", category: "api-key", description: "Potential Livekit/streaming API key.", requiresContext: true },
    { name: "Turnstile Site Key", pattern: /0x[0-9a-fA-F]{22}/g, severity: "low", category: "api-key", description: "Cloudflare Turnstile site key found.", requiresContext: true },
    { name: "Pusher Key", pattern: /(?:pusher|PUSHER)[_-]?(?:key|app[_-]?key)\s*[:=]\s*['"]([a-f0-9]{20})['"]/gi, severity: "medium", category: "api-key", description: "Pusher app key found." },
    { name: "Algolia App ID + Key", pattern: /(?:algolia|ALGOLIA)[_-]?(?:app[_-]?id|api[_-]?key|search[_-]?key)\s*[:=]\s*['"]([a-zA-Z0-9]{10,})['"]/gi, severity: "medium", category: "api-key", description: "Algolia key found." },
    { name: "Plaid Client Secret", pattern: /(?:plaid)[_-]?(?:secret|client[_-]?secret)\s*[:=]\s*['"]([a-f0-9]{30})['"]/gi, severity: "critical", category: "api-key", description: "Plaid client secret found." },
    { name: "Razorpay Key", pattern: /rzp_(?:live|test)_[A-Za-z0-9]{14,}/g, severity: "high", category: "api-key", description: "Razorpay API key found." },
    { name: "Coinbase API Key", pattern: /(?:coinbase)[_-]?(?:api[_-]?key|secret)\s*[:=]\s*['"]([A-Za-z0-9]{16,})['"]/gi, severity: "critical", category: "api-key", description: "Coinbase API key found." },
    { name: "Binance API Key", pattern: /(?:binance)[_-]?(?:api[_-]?key|secret)\s*[:=]\s*['"]([A-Za-z0-9]{64})['"]/gi, severity: "critical", category: "api-key", description: "Binance API key found." },
    { name: "Infura API Key", pattern: /(?:infura)[_-]?(?:key|project[_-]?id|api[_-]?key)\s*[:=]\s*['"]([a-f0-9]{32})['"]/gi, severity: "high", category: "api-key", description: "Infura project key found." },
    { name: "Alchemy API Key", pattern: /(?:alchemy)[_-]?(?:key|api[_-]?key)\s*[:=]\s*['"]([A-Za-z0-9_-]{32,})['"]/gi, severity: "high", category: "api-key", description: "Alchemy API key found." },
    { name: "Moralis API Key", pattern: /(?:moralis)[_-]?(?:key|api[_-]?key)\s*[:=]\s*['"]([A-Za-z0-9]{32,})['"]/gi, severity: "high", category: "api-key", description: "Moralis API key found." },
    // ── AI/LLM Provider Keys ──
    { name: "OpenRouter API Key", pattern: /sk-or-v1-[A-Za-z0-9]{48,}/g, severity: "critical", category: "api-key", description: "OpenRouter API key found." },
    { name: "OpenRouter Key (alt)", pattern: /sk-or-[A-Za-z0-9_-]{40,}/g, severity: "critical", category: "api-key", description: "OpenRouter API key found." },
    { name: "DeepSeek API Key", pattern: /(?:deepseek|DEEPSEEK)[_-]?(?:api[_-]?key|key|token)\s*[:=]\s*['"]([A-Za-z0-9_-]{30,})['"]/gi, severity: "critical", category: "api-key", description: "DeepSeek API key found." },
    { name: "Perplexity API Key", pattern: /pplx-[A-Za-z0-9]{48,}/g, severity: "critical", category: "api-key", description: "Perplexity API key found." },
    { name: "Together AI Key", pattern: /(?:together|TOGETHER)[_-]?(?:api[_-]?key|key)\s*[:=]\s*['"]([a-f0-9]{64})['"]/gi, severity: "critical", category: "api-key", description: "Together AI API key found." },
    { name: "Fireworks AI Key", pattern: /fw_[A-Za-z0-9]{40,}/g, severity: "critical", category: "api-key", description: "Fireworks AI API key found." },
    { name: "Mistral API Key (prefix)", pattern: /(?:mistral|MISTRAL)[_-]?(?:api[_-]?key|key)\s*[:=]\s*['"]([A-Za-z0-9]{32,})['"]/gi, severity: "critical", category: "api-key", description: "Mistral AI API key found." },
    { name: "Cohere API Key (prefix)", pattern: /(?:cohere|COHERE|co)[_-]?(?:api[_-]?key|key|token)\s*[:=]\s*['"]([A-Za-z0-9]{40,})['"]/gi, severity: "critical", category: "api-key", description: "Cohere API key found." },
    { name: "Stability AI Key", pattern: /(?:stability|STABILITY)[_-]?(?:api[_-]?key|key)\s*[:=]\s*['"]([A-Za-z0-9_-]{40,})['"]/gi, severity: "critical", category: "api-key", description: "Stability AI API key found." },
    { name: "ElevenLabs API Key", pattern: /(?:elevenlabs|ELEVENLABS|eleven_labs|xi)[_-]?(?:api[_-]?key|key)\s*[:=]\s*['"]([a-f0-9]{32})['"]/gi, severity: "high", category: "api-key", description: "ElevenLabs API key found." },
    { name: "AssemblyAI Key", pattern: /(?:assemblyai|ASSEMBLYAI|assembly)[_-]?(?:api[_-]?key|key)\s*[:=]\s*['"]([a-f0-9]{32})['"]/gi, severity: "high", category: "api-key", description: "AssemblyAI API key found." },
    { name: "Deepgram API Key", pattern: /(?:deepgram|DEEPGRAM)[_-]?(?:api[_-]?key|key|secret)\s*[:=]\s*['"]([a-f0-9]{40})['"]/gi, severity: "high", category: "api-key", description: "Deepgram API key found." },
    { name: "Pinecone API Key", pattern: /(?:pinecone|PINECONE)[_-]?(?:api[_-]?key|key)\s*[:=]\s*['"]([a-f0-9-]{36})['"]/gi, severity: "high", category: "api-key", description: "Pinecone API key found." },
    { name: "Weaviate API Key", pattern: /(?:weaviate|WEAVIATE)[_-]?(?:api[_-]?key|key)\s*[:=]\s*['"]([A-Za-z0-9]{40,})['"]/gi, severity: "high", category: "api-key", description: "Weaviate API key found." },
    { name: "Qdrant API Key", pattern: /(?:qdrant|QDRANT)[_-]?(?:api[_-]?key|key)\s*[:=]\s*['"]([A-Za-z0-9_-]{30,})['"]/gi, severity: "high", category: "api-key", description: "Qdrant API key found." },
    { name: "Voyage AI Key", pattern: /(?:voyage|VOYAGE)[_-]?(?:api[_-]?key|key)\s*[:=]\s*['"]([A-Za-z0-9_-]{30,})['"]/gi, severity: "high", category: "api-key", description: "Voyage AI API key found." },
    // ── Cloud Provider Keys ──
    { name: "Azure Subscription Key", pattern: /(?:ocp-apim-subscription-key|azure[_-]?(?:api[_-]?key|key|subscription))\s*[:=]\s*['"]([a-f0-9]{32})['"]/gi, severity: "critical", category: "api-key", description: "Azure subscription/API key found." },
    { name: "Azure OpenAI Key", pattern: /(?:azure[_-]?openai|AZURE_OPENAI)[_-]?(?:api[_-]?key|key)\s*[:=]\s*['"]([a-f0-9]{32})['"]/gi, severity: "critical", category: "api-key", description: "Azure OpenAI API key found." },
    { name: "Azure Connection String", pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{44,};/g, severity: "critical", category: "api-key", description: "Azure Storage connection string found." },
    { name: "GCP API Key", pattern: /(?:gcp|google_cloud|GOOGLE)[_-]?(?:api[_-]?key|key)\s*[:=]\s*['"]([A-Za-z0-9_-]{39})['"]/gi, severity: "critical", category: "api-key", description: "Google Cloud API key found." },
    { name: "GCP Service Account", pattern: /"type"\s*:\s*"service_account"[^}]*"private_key"/g, severity: "critical", category: "api-key", description: "GCP service account JSON key detected." },
    { name: "AWS Session Token", pattern: /(?:aws[_-]?session[_-]?token|AWS_SESSION_TOKEN)\s*[:=]\s*['"]([A-Za-z0-9/+=]{100,})['"]/gi, severity: "critical", category: "api-key", description: "AWS session token found." },
    // ── Additional SaaS Keys ──
    { name: "Netlify Token", pattern: /nfp_[A-Za-z0-9]{40,}/g, severity: "high", category: "api-key", description: "Netlify personal access token found." },
    { name: "Fly.io Token", pattern: /FlyV1\s+[A-Za-z0-9_-]{40,}/g, severity: "high", category: "api-key", description: "Fly.io deploy token found." },
    { name: "Railway Token", pattern: /(?:railway|RAILWAY)[_-]?(?:token|api[_-]?key)\s*[:=]\s*['"]([a-f0-9-]{36})['"]/gi, severity: "high", category: "api-key", description: "Railway deploy token found." },
    { name: "Clerk Secret Key", pattern: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g, severity: "critical", category: "api-key", description: "Clerk secret key found." },
    { name: "Auth0 Client Secret", pattern: /(?:auth0|AUTH0)[_-]?(?:client[_-]?secret|secret)\s*[:=]\s*['"]([A-Za-z0-9_-]{32,})['"]/gi, severity: "critical", category: "api-key", description: "Auth0 client secret found." },
    { name: "Okta API Token", pattern: /00[A-Za-z0-9_-]{40}/g, severity: "high", category: "api-key", description: "Potential Okta API token found.", requiresContext: true },
    { name: "Postmark Token", pattern: /(?:postmark|POSTMARK)[_-]?(?:token|api[_-]?key|server[_-]?token)\s*[:=]\s*['"]([a-f0-9-]{36})['"]/gi, severity: "high", category: "api-key", description: "Postmark server token found." },
    { name: "Resend API Key", pattern: /re_[A-Za-z0-9]{20,}/g, severity: "high", category: "api-key", description: "Resend API key found." },
    { name: "Upstash Redis Token", pattern: /(?:upstash|UPSTASH)[_-]?(?:redis[_-]?rest[_-]?token|token)\s*[:=]\s*['"]([A-Za-z0-9=]{30,})['"]/gi, severity: "high", category: "api-key", description: "Upstash Redis REST token found." },
    { name: "Neon Database Token", pattern: /(?:neon|NEON)[_-]?(?:api[_-]?key|db[_-]?token|token)\s*[:=]\s*['"]([A-Za-z0-9_-]{30,})['"]/gi, severity: "high", category: "api-key", description: "Neon database token found." },
    { name: "Turso Database Token", pattern: /(?:turso|TURSO|libsql)[_-]?(?:auth[_-]?token|token)\s*[:=]\s*['"]([A-Za-z0-9._-]{100,})['"]/gi, severity: "high", category: "api-key", description: "Turso/LibSQL auth token found." },
    // ── Generic catch-all for assignment patterns ──
    { name: "Generic API Key Assignment", pattern: /(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token|access[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token|auth[_-]?key|bearer[_-]?token|private[_-]?key|service[_-]?key)\s*[:=]\s*['"]([A-Za-z0-9_\-./+=]{20,})['"]/gi, severity: "high", category: "api-key", description: "API key/token assignment found." }
  ],

  // ── Hardcoded Credentials ──
  credentials: [
    { name: "Hardcoded Password", pattern: /(?:^|[^.\w])(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`\s]{4,})['"`]/gi, severity: "high", category: "credential", description: "Hardcoded password found in source code.", falsePositiveFilter: /^(%[a-z]+%|\*+|x+|\.+|placeholder|example|changeme|undefined|null|none|todo|your[_-]?password|test|demo)$/i },
    { name: "Hardcoded Secret", pattern: /(?:^|[^.\w])(?:secret|secret_key|secretKey|client_secret|clientSecret)\s*[:=]\s*['"`]([^'"`\s]{4,})['"`]/gi, severity: "high", category: "credential", description: "Hardcoded secret value found.", falsePositiveFilter: /^(%[a-z]+%|\*+|x+|placeholder|example|changeme|undefined|null|none|todo|YOUR_|REPLACE)$/i },
    { name: "Database Connection String", pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql|redis|amqp|mariadb):\/\/[^\s'"<>]+/gi, severity: "critical", category: "credential", description: "Database connection string found. May contain credentials." },
    { name: "Generic API Key Assignment", pattern: /(?:^|[^.\w])(?:api_key|apikey|api[-_]?secret|access_key)\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]/gi, severity: "high", category: "credential", description: "Generic API key assignment found." },
    { name: "Authorization Header", pattern: /['"]Authorization['"]\s*:\s*['"]([^'"]{10,})['"]/gi, severity: "high", category: "credential", description: "Hardcoded Authorization header found." },
    { name: "JDBC Connection String", pattern: /jdbc:[a-z:]+\/\/[^\s'"<>]+/gi, severity: "critical", category: "credential", description: "JDBC connection string found." },
    { name: "LDAP Bind Credentials", pattern: /ldaps?:\/\/[^\s'"<>]+/gi, severity: "high", category: "credential", description: "LDAP connection URI found." },
    { name: "SMTP Credentials", pattern: /smtp:\/\/[^\s'"<>]+/gi, severity: "high", category: "credential", description: "SMTP connection string found." },
    { name: "FTP Credentials", pattern: /ftp:\/\/[^@\s'"<>]+@[^\s'"<>]+/gi, severity: "critical", category: "credential", description: "FTP URL with credentials found." }
  ],

  // ── Information Leaks ──
  infoLeaks: [
    { name: "Internal IP Address", pattern: /(?:^|[^0-9.])((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(?:192\.168\.\d{1,3}\.\d{1,3}))(?:[^0-9]|$)/g, severity: "medium", category: "info-leak", description: "Internal/private IP address found." },
    { name: "Email Address", pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, severity: "low", category: "info-leak", description: "Email address found in source.", falsePositiveFilter: /^(example|test|user|admin|info|support|no-?reply)@(example|test|localhost)\./i },
    { name: "Internal URL", pattern: /https?:\/\/[^\s'"<>]*\.(?:internal|local|corp|intranet|dev|staging|test|stage|uat|preprod|qa)\b[^\s'"<>]*/gi, severity: "medium", category: "info-leak", description: "Internal/dev URL found. Reveals infrastructure." },
    { name: "AWS S3 Bucket", pattern: /(?:[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3[.-](?:[a-z]+-)?(?:us|eu|ap|sa|ca|me|af)-[a-z]+-\d\.amazonaws\.com|s3:\/\/[a-z0-9][a-z0-9.-]+|[a-z0-9][a-z0-9.-]+\.s3\.amazonaws\.com)/gi, severity: "medium", category: "info-leak", description: "AWS S3 bucket reference found." },
    { name: "Google Cloud Storage", pattern: /storage\.googleapis\.com\/[a-z0-9._-]+/gi, severity: "medium", category: "info-leak", description: "Google Cloud Storage bucket found." },
    { name: "Azure Blob Storage", pattern: /[a-z0-9]+\.blob\.core\.windows\.net/gi, severity: "medium", category: "info-leak", description: "Azure Blob Storage reference found." },
    { name: "Azure Table/Queue", pattern: /[a-z0-9]+\.(?:table|queue|file)\.core\.windows\.net/gi, severity: "medium", category: "info-leak", description: "Azure Storage reference found." },
    { name: "AWS ARN", pattern: /arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9\/_.-]+/g, severity: "medium", category: "info-leak", description: "AWS ARN found. Reveals account ID and resources." },
    { name: "AWS Account ID", pattern: /(?:account[_-]?id|aws[_-]?account)\s*[:=]\s*['"]?(\d{12})['"]?/gi, severity: "medium", category: "info-leak", description: "AWS Account ID found." },
    { name: "Google Maps API Call", pattern: /maps\.googleapis\.com\/maps\/api\/[a-z]+\?[^\s'"<>]*key=[A-Za-z0-9_-]+/gi, severity: "medium", category: "info-leak", description: "Google Maps API call with key found." },
    { name: "File Path Disclosure", pattern: /(?:\/home\/[a-z_][a-z0-9_-]*|\/var\/www|\/opt\/[a-z]+|C:\\\\(?:Users|inetpub|Program Files)\\\\[^\s'"<>]+|\/etc\/[a-z][a-z0-9_-]*)/g, severity: "low", category: "info-leak", description: "Server file path found." },
    { name: "AWS Lambda URL", pattern: /https?:\/\/[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws\b[^\s'"<>]*/gi, severity: "medium", category: "info-leak", description: "AWS Lambda Function URL found." },
    { name: "AWS API Gateway", pattern: /https?:\/\/[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com\b[^\s'"<>]*/gi, severity: "medium", category: "info-leak", description: "AWS API Gateway endpoint found." },
    { name: "Google Cloud Function", pattern: /https?:\/\/[a-z0-9-]+-[a-z0-9]+\.cloudfunctions\.net\b[^\s'"<>]*/gi, severity: "medium", category: "info-leak", description: "Google Cloud Function URL found." },
    { name: "Azure Function", pattern: /https?:\/\/[a-z0-9-]+\.azurewebsites\.net\b[^\s'"<>]*/gi, severity: "medium", category: "info-leak", description: "Azure Function/App Service URL found." },
    { name: "Firebase Hosting/Functions", pattern: /https?:\/\/[a-z0-9-]+\.(?:web\.app|firebaseapp\.com|cloudfunctions\.net)\b[^\s'"<>]*/gi, severity: "medium", category: "info-leak", description: "Firebase resource URL found." },
    { name: "Kubernetes Internal DNS", pattern: /[a-z0-9-]+\.[a-z0-9-]+\.svc\.cluster\.local\b/gi, severity: "high", category: "info-leak", description: "Kubernetes internal service DNS name found. Reveals cluster topology." },
    { name: "Internal Hostname Pattern", pattern: /https?:\/\/[a-z0-9-]+(?:-(?:internal|private|backend|prod|staging|dev|db|cache|worker|queue|rpc))+\.[a-zA-Z0-9.-]+/gi, severity: "medium", category: "info-leak", description: "Internal hostname pattern found. Reveals infrastructure naming." },
    { name: "OAuth redirect_uri", pattern: /redirect_uri\s*=\s*(?:https?%3A%2F%2F|https?:\/\/)[^\s&'"<>]+/gi, severity: "info", category: "info-leak", description: "OAuth redirect_uri parameter found. Check for open redirect." }
  ],

  // ── Debug & Stack Traces ──
  debug: [
    { name: "Stack Trace", pattern: /(?:Error|Exception|Traceback)[\s\S]{0,50}at\s+[\w.$]+\s+\([^)]+:\d+:\d+\)/g, severity: "medium", category: "debug", description: "Stack trace found. Reveals internal code paths." },
    { name: "Debugger Statement", pattern: /\bdebugger\b\s*;/g, severity: "low", category: "debug", description: "Debugger statement left in code." },
    { name: "Debug Mode Enabled", pattern: /(?:DEBUG|debug_mode|debugMode|FLASK_DEBUG|APP_DEBUG|DJANGO_DEBUG)\s*[:=]\s*(?:true|True|1|['"]true['"])/gi, severity: "medium", category: "debug", description: "Debug mode enabled." },
    { name: "Console Log (Sensitive)", pattern: /console\.(?:log|debug|info|warn)\s*\(\s*['"`](?:[^'"`]*(?:token|key|secret|password|auth|credential|session|cookie|bearer)[^'"`]*?)['"`]/gi, severity: "medium", category: "debug", description: "Console logging of potentially sensitive data." },
    { name: "PHP Error Display", pattern: /(?:display_errors|error_reporting)\s*(?:=|:)\s*(?:On|E_ALL|1)/gi, severity: "medium", category: "debug", description: "PHP error display enabled." },
    { name: "Python Traceback", pattern: /Traceback \(most recent call last\)/g, severity: "medium", category: "debug", description: "Python traceback found." },
    { name: "Java Stack Trace", pattern: /(?:java|javax|org\.springframework|com\.sun)\.[a-zA-Z.]+Exception/g, severity: "medium", category: "debug", description: "Java exception class found." },
    { name: "ASP.NET Error", pattern: /Server Error in .* Application/g, severity: "medium", category: "debug", description: "ASP.NET server error found." },
    { name: "SQL Error Message", pattern: /(?:mysql_fetch|pg_query|ORA-\d{5}|SQLSTATE\[|syntax error.*?SQL|unclosed quotation mark)/gi, severity: "high", category: "debug", description: "SQL error message found. May indicate SQL injection." }
  ],

  // ── Environment Variables ──
  envVars: [
    { name: "process.env Reference", pattern: /process\.env\.([A-Z_][A-Z0-9_]*)/g, severity: "low", category: "env-var", description: "Node.js environment variable reference." },
    { name: "React App Env Variable", pattern: /(REACT_APP_[A-Z_0-9]+)/g, severity: "low", category: "env-var", description: "React env variable reference." },
    { name: "Next.js Public Env Variable", pattern: /(NEXT_PUBLIC_[A-Z_0-9]+)/g, severity: "low", category: "env-var", description: "Next.js public env variable reference." },
    { name: "Vue App Env Variable", pattern: /(VUE_APP_[A-Z_0-9]+)/g, severity: "low", category: "env-var", description: "Vue env variable reference." },
    { name: "Vite Env Variable", pattern: /(VITE_[A-Z_0-9]+)/g, severity: "low", category: "env-var", description: "Vite env variable reference." },
    { name: "Env Variable with Value", pattern: /(?:REACT_APP|NEXT_PUBLIC|VUE_APP|VITE)_[A-Z_0-9]+\s*[:=]\s*['"]([^'"]{4,})['"`]/g, severity: "medium", category: "env-var", description: "Env variable with hardcoded value." },
    { name: "Angular Env Config", pattern: /environment\.(prod|production|staging|dev)\s*[:=]\s*\{/g, severity: "low", category: "env-var", description: "Angular environment config block." },
    { name: "__NEXT_DATA__ Exposed", pattern: /__NEXT_DATA__\s*=\s*\{/g, severity: "low", category: "env-var", description: "Next.js __NEXT_DATA__ JSON blob found. May contain server-side props." }
  ],

  // ── API Endpoints ──
  endpoints: [
    // ── Generic path extraction (catches minified webpack/Next.js/React bundles) ──
    // This is the most important pattern: catches ANY "/api/..." string in quotes
    { name: "API Path", pattern: /['"`](\/api\/[a-zA-Z0-9\/_\-.[\]?=&]+)['"`]/g, severity: "info", category: "endpoint", description: "API path found.", falsePositiveFilter: /^\/api\/?$/ },
    // Catch paths with 2+ segments that look like routes (not static files)
    { name: "Route Path", pattern: /['"`](\/[a-z][a-z0-9-]*\/[a-z:][a-zA-Z0-9\/_\-.:[\]]*?)['"`]/g, severity: "info", category: "endpoint", description: "Route path found in source.", falsePositiveFilter: /(?:\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|json|xml|txt|html)$|^\/_next\/|^\/static\/|^\/assets\/|^\/images\/|^\/img\/|^\/fonts\/|^\/css\/|^\/js\/|^\/node_modules\/|^\/favicon|^\/sockjs-node)/ },
    // Object key patterns common in webpack bundles: apiEndpoint:"/api/...", url:"/tools/..."
    { name: "Config Endpoint", pattern: /(?:apiEndpoint|endpoint|apiUrl|serviceUrl|baseUrl|apiPath|routePath|href|path|url)\s*:\s*['"`](\/[a-zA-Z0-9\/_\-.[\]]{3,})['"`]/gi, severity: "info", category: "endpoint", description: "Endpoint in config/object property." },
    // ── Specific patterns ──
    { name: "Versioned API Path", pattern: /['"`](\/v[1-9]\d?\/[a-zA-Z0-9\/_\-.]+)['"`]/g, severity: "info", category: "endpoint", description: "Versioned API path found." },
    { name: "GraphQL Endpoint", pattern: /['"`](\/graphql\b[^'"`]*)['"`]/g, severity: "info", category: "endpoint", description: "GraphQL endpoint reference." },
    { name: "WebSocket Endpoint", pattern: /wss?:\/\/[^\s'"<>]+/g, severity: "info", category: "endpoint", description: "WebSocket endpoint found." },
    { name: "API Base URL", pattern: /(?:baseURL|apiUrl|API_URL|api_base|API_BASE|API_ENDPOINT|apiEndpoint|backendUrl|BACKEND_URL|serviceUrl|SERVICE_URL)\s*[:=]\s*['"`](https?:\/\/[^'"`]+)['"`]/gi, severity: "medium", category: "endpoint", description: "API base URL configuration found." },
    { name: "Fetch/Axios Call", pattern: /(?:fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*['"`](\/[a-zA-Z0-9\/_\-.]{3,})['"`]/g, severity: "info", category: "endpoint", description: "API call found in JavaScript." },
    { name: "Concat API Call", pattern: /(?:fetch|axios\.\w+|\.(?:get|post|put|delete))\s*\(\s*[a-zA-Z_$][\w.]*\s*\+\s*['"`](\/[a-zA-Z0-9\/_\-.]{2,})['"`]/g, severity: "info", category: "endpoint", description: "API call with concatenated URL found." },
    { name: "String Concat Path", pattern: /\.concat\(\s*['"`](\/[a-zA-Z0-9\/_\-.]{2,})['"`]/g, severity: "info", category: "endpoint", description: "Path in .concat() call (compiled template literal)." },
    { name: "jQuery Ajax URL", pattern: /\$\.(?:ajax|get|post|getJSON)\s*\(\s*['"`](\/[a-zA-Z0-9\/_\-.]{3,})['"`]/g, severity: "info", category: "endpoint", description: "jQuery AJAX call found." },
    { name: "XMLHttpRequest URL", pattern: /\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"`](\/[a-zA-Z0-9\/_\-.]{3,})['"`]/gi, severity: "info", category: "endpoint", description: "XHR API call found." },
    { name: "Backend Route", pattern: /['"`](\/(?:auth|login|logout|register|signup|signin|oauth|callback|token|refresh|verify|reset|forgot|password|upload|download|webhook|socket|events|notifications|search|checkout|payment|billing|subscription|admin|dashboard|internal|debug|health|status|metrics|config|settings|profile|account|users?|session)\b[a-zA-Z0-9\/_\-.]*)['"`]/g, severity: "info", category: "endpoint", description: "Backend route path found." },
    { name: "Full API URL", pattern: /['"`](https?:\/\/[^\s'"`]+\/(?:api|v[1-9]|graphql)\b[^\s'"`]*)['"`]/g, severity: "info", category: "endpoint", description: "Full API URL with domain found." },
    { name: "URL Template Literal", pattern: /`(\/[a-zA-Z0-9_-]+\/\$\{[^}]+\}[^`]*)`/g, severity: "info", category: "endpoint", description: "Dynamic URL in template literal found." },
    { name: "Angular HttpClient", pattern: /(?:this\.http|httpClient)\.(?:get|post|put|patch|delete|request)\s*[<(]\s*['"`](\/[a-zA-Z0-9\/_\-.]{3,})['"`]/gi, severity: "info", category: "endpoint", description: "Angular HTTP call found." }
  ],

  // ── Source Maps ──
  sourceMaps: [
    { name: "Source Map Reference", pattern: /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)/g, severity: "medium", category: "sourcemap", description: "Source map found. May expose original source code." },
    { name: "Source Map Header", pattern: /SourceMap:\s*(\S+\.map)/g, severity: "medium", category: "sourcemap", description: "Source map reference in headers." }
  ],

  // ── DOM Security ──
  domSecurity: [
    { name: "innerHTML Assignment", pattern: /\.innerHTML\s*=\s*[^;]*(?:location|document\.URL|document\.referrer|window\.name|document\.cookie)/g, severity: "high", category: "dom-security", description: "Potential DOM-based XSS: innerHTML assigned from user-controlled source." },
    { name: "document.write Usage", pattern: /document\.write\s*\([^)]*(?:location|document\.URL|document\.referrer|window\.name)/g, severity: "high", category: "dom-security", description: "document.write with user-controlled input." },
    { name: "eval Usage", pattern: /\beval\s*\(\s*(?:[^)]*(?:location|document|window\.name|decodeURI)|['"`][^'"]+['"`]\s*\+)/g, severity: "high", category: "dom-security", description: "eval() with potentially user-controlled input." },
    { name: "Dangerous jQuery Sink", pattern: /\$\s*\(\s*(?:location|document\.URL|document\.referrer|window\.name|window\.location)/g, severity: "high", category: "dom-security", description: "jQuery selector with user-controlled input." },
    { name: "postMessage No Origin Check", pattern: /addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:function\s*\([^)]*\)|[^,]+=>)\s*\{(?:(?!origin).)*\}/g, severity: "medium", category: "dom-security", description: "postMessage listener without origin check." },
    { name: "postMessage Wildcard Origin", pattern: /\.postMessage\s*\([^,)]+,\s*['"]\*['"]\s*\)/g, severity: "medium", category: "dom-security", description: "postMessage sends data to wildcard origin '*'. Any frame can receive it." },
    { name: "Open Redirect Parameter", pattern: /(?:redirect|return|next|url|goto|dest|destination|redir|redirect_uri|return_url|continue|forward)\s*=\s*https?/gi, severity: "medium", category: "dom-security", description: "Potential open redirect parameter in URL." },
    { name: "Prototype Pollution Sink", pattern: /\[['"]__proto__['"]\]\s*=/g, severity: "high", category: "dom-security", description: "Direct __proto__ assignment found. Prototype pollution vector." },
    { name: "Prototype Pollution via Constructor", pattern: /constructor\s*\[\s*['"]prototype['"]\s*\]/g, severity: "high", category: "dom-security", description: "constructor.prototype access found. Prototype pollution vector." },
    { name: "JSONP Callback", pattern: /[?&](?:callback|jsonp|cb|jsonpcallback)\s*=/gi, severity: "medium", category: "dom-security", description: "JSONP callback parameter found. Potential XSS if user-controllable." },
    { name: "WebAssembly Usage", pattern: /WebAssembly\.(?:instantiate|instantiateStreaming|compile)\s*\(/g, severity: "info", category: "dom-security", description: "WebAssembly module loaded. May contain obfuscated logic worth manual review." },
    { name: "Template Injection Marker", pattern: /\{\{\s*[a-zA-Z_$][\w.[\]'"()|]{1,60}\s*\}\}/g, severity: "low", category: "dom-security", description: "Template expression found in HTML. May indicate server-side template injection (SSTI).", requiresContext: false }
  ],

  // ── Technology Fingerprinting ──
  technology: [
    { name: "WordPress", pattern: /(?:=['"]\/wp-content\/|=['"]\/wp-includes\/|<meta[^>]+name=['"]generator['"][^>]+WordPress|wp-json\/wp\/v2)/g, severity: "info", category: "technology", description: "WordPress detected." },
    { name: "React", pattern: /\breact(?:\.production|\.development|DOM)\b|_reactRoot|__REACT_DEVTOOLS/g, severity: "info", category: "technology", description: "React.js detected." },
    { name: "Angular", pattern: /ng-version=["'][0-9]+|angular(?:\.min)?\.js|ng-app=|ng-controller=/g, severity: "info", category: "technology", description: "Angular detected." },
    { name: "Vue.js", pattern: /__vue__|Vue\.(?:component|use|mixin)|v-bind:|v-on:|v-if=/g, severity: "info", category: "technology", description: "Vue.js detected." },
    { name: "Next.js", pattern: /_next\/static|__NEXT_DATA__|next\/router/g, severity: "info", category: "technology", description: "Next.js detected." },
    { name: "Nuxt.js", pattern: /__nuxt|_nuxt\/|nuxtServerInit/g, severity: "info", category: "technology", description: "Nuxt.js detected." },
    { name: "jQuery", pattern: /jquery[.-](\d+\.\d+\.\d+)/gi, severity: "info", category: "technology", description: "jQuery detected with version." },
    { name: "Bootstrap", pattern: /bootstrap[.-](\d+\.\d+\.\d+)/gi, severity: "info", category: "technology", description: "Bootstrap detected with version." },
    { name: "Laravel", pattern: /laravel_session|XSRF-TOKEN|laravel_token/g, severity: "info", category: "technology", description: "Laravel detected." },
    { name: "Django", pattern: /csrfmiddlewaretoken|django\.contrib|__django_/g, severity: "info", category: "technology", description: "Django detected." },
    { name: "Ruby on Rails", pattern: /csrf-token.*authenticity_token|turbolinks|rails-ujs/g, severity: "info", category: "technology", description: "Ruby on Rails detected." },
    { name: "ASP.NET", pattern: /__VIEWSTATE|__EVENTVALIDATION|asp\.net|aspnet/gi, severity: "info", category: "technology", description: "ASP.NET detected." },
    { name: "Spring Framework", pattern: /jsessionid|spring-security|springframework/gi, severity: "info", category: "technology", description: "Spring Framework detected." },
    { name: "Cloudflare", pattern: /__cf_bm|cf-ray[:=]|cdnjs\.cloudflare\.com|cloudflare-static/gi, severity: "info", category: "technology", description: "Cloudflare detected." },
    { name: "Google Analytics", pattern: /(?:gtag|ga)\s*\(\s*['"](?:send|config|event)['"]|google-analytics\.com\/(?:analytics|ga|gtag)/g, severity: "info", category: "technology", description: "Google Analytics tracking detected." },
    { name: "Google Tag Manager", pattern: /googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]+/g, severity: "info", category: "technology", description: "Google Tag Manager detected." },
    { name: "Facebook Pixel", pattern: /fbq\s*\(\s*['"]init['"]|connect\.facebook\.net\/.*fbevents/g, severity: "info", category: "technology", description: "Facebook Pixel tracking detected." },
    { name: "Hotjar", pattern: /hotjar\.com|hj\s*\(\s*['"]identify['"]/g, severity: "info", category: "technology", description: "Hotjar analytics detected." },
    { name: "Segment", pattern: /analytics\.(?:identify|track|page)\s*\(|cdn\.segment\.com/g, severity: "info", category: "technology", description: "Segment analytics detected." },
    { name: "Intercom", pattern: /intercomSettings|widget\.intercom\.io|Intercom\s*\(/g, severity: "info", category: "technology", description: "Intercom widget detected." },
    { name: "Sentry Error Tracking", pattern: /sentry\.io|Sentry\.init|dsn:\s*['"]https:\/\/[^'"]*sentry/g, severity: "info", category: "technology", description: "Sentry error tracking detected." },
    { name: "PostHog Analytics", pattern: /posthog\.init|posthog\.capture|app\.posthog\.com/g, severity: "info", category: "technology", description: "PostHog analytics detected." },
    // Font services
    { name: "Google Font API", pattern: /fonts\.googleapis\.com|fonts\.gstatic\.com/g, severity: "info", category: "technology", description: "Google Fonts detected." },
    { name: "Adobe Fonts", pattern: /use\.typekit\.net|p\.typekit\.net/g, severity: "info", category: "technology", description: "Adobe Fonts (Typekit) detected." },
    // Additional frameworks
    { name: "Svelte", pattern: /svelte-[a-z0-9]+|__svelte/g, severity: "info", category: "technology", description: "Svelte detected." },
    { name: "Gatsby", pattern: /gatsby-image|gatsby-link|\/static\/[a-f0-9]+-/g, severity: "info", category: "technology", description: "Gatsby detected." },
    { name: "Remix", pattern: /__remix|remix-run/g, severity: "info", category: "technology", description: "Remix framework detected." },
    { name: "Tailwind CSS", pattern: /tailwindcss|tailwind\.min\.css/gi, severity: "info", category: "technology", description: "Tailwind CSS detected." },
    // CMS & Platforms
    { name: "Shopify", pattern: /cdn\.shopify\.com|Shopify\.theme/g, severity: "info", category: "technology", description: "Shopify detected." },
    { name: "Squarespace", pattern: /squarespace\.com\/universal|static\.squarespace\.com/g, severity: "info", category: "technology", description: "Squarespace detected." },
    { name: "Wix", pattern: /static\.wixstatic\.com|wix-code-sdk/g, severity: "info", category: "technology", description: "Wix detected." },
    { name: "Webflow", pattern: /assets\.website-files\.com|webflow\.com\/js/g, severity: "info", category: "technology", description: "Webflow detected." },
    { name: "Ghost", pattern: /ghost-(?:url|version)|content\/themes\/casper/g, severity: "info", category: "technology", description: "Ghost CMS detected." },
    { name: "Drupal", pattern: /Drupal\.settings|drupal\.js|sites\/(?:all|default)\/(?:files|themes|modules)/g, severity: "info", category: "technology", description: "Drupal detected." },
    { name: "Joomla", pattern: /\/media\/jui\/|\/components\/com_|Joomla!/g, severity: "info", category: "technology", description: "Joomla detected." },
    // Analytics & Marketing
    { name: "Mixpanel", pattern: /mixpanel\.init|cdn\.mxpnl\.com|api\.mixpanel\.com/g, severity: "info", category: "technology", description: "Mixpanel analytics detected." },
    { name: "Amplitude", pattern: /amplitude\.getInstance|cdn\.amplitude\.com/g, severity: "info", category: "technology", description: "Amplitude analytics detected." },
    { name: "Heap Analytics", pattern: /heap\.load|cdn\.heapanalytics\.com/g, severity: "info", category: "technology", description: "Heap analytics detected." },
    // Misc
    { name: "reCAPTCHA", pattern: /google\.com\/recaptcha|grecaptcha/g, severity: "info", category: "technology", description: "Google reCAPTCHA detected." },
    { name: "hCaptcha", pattern: /hcaptcha\.com\/1\/api|h-captcha/g, severity: "info", category: "technology", description: "hCaptcha detected." },
    { name: "Stripe.js", pattern: /js\.stripe\.com|Stripe\s*\(\s*['"]pk_/g, severity: "info", category: "technology", description: "Stripe.js payment integration detected." },
    { name: "PayPal", pattern: /paypal\.com\/sdk|paypalobjects\.com/g, severity: "info", category: "technology", description: "PayPal integration detected." }
  ],

  // ── Media & Asset URLs ──
  media: [
    // HLS / DASH streaming
    { name: "HLS Playlist (m3u8)", pattern: /['"`](https?:\/\/[^\s'"`]+\.m3u8(?:\?[^\s'"`]*)?)['"`]/gi, severity: "info", category: "media", description: "HLS streaming playlist URL found." },
    { name: "HLS Playlist (relative)", pattern: /['"`](\/[^\s'"`]+\.m3u8(?:\?[^\s'"`]*)?)['"`]/gi, severity: "info", category: "media", description: "HLS playlist path found." },
    { name: "DASH Manifest (mpd)", pattern: /['"`](https?:\/\/[^\s'"`]+\.mpd(?:\?[^\s'"`]*)?)['"`]/gi, severity: "info", category: "media", description: "DASH streaming manifest found." },
    { name: "MPEG-TS Segment", pattern: /['"`](https?:\/\/[^\s'"`]+\.ts(?:\?[^\s'"`]*)?)['"`]/gi, severity: "info", category: "media", description: "MPEG-TS video segment URL found.", falsePositiveFilter: /\.(?:d\.ts|spec\.ts|test\.ts|types\.ts)['"`]?$/ },
    // Video files
    { name: "MP4 Video URL", pattern: /['"`](https?:\/\/[^\s'"`]+\.mp4(?:\?[^\s'"`]*)?)['"`]/gi, severity: "info", category: "media", description: "MP4 video URL found." },
    { name: "WebM Video URL", pattern: /['"`](https?:\/\/[^\s'"`]+\.webm(?:\?[^\s'"`]*)?)['"`]/gi, severity: "info", category: "media", description: "WebM video URL found." },
    { name: "FLV Video URL", pattern: /['"`](https?:\/\/[^\s'"`]+\.flv(?:\?[^\s'"`]*)?)['"`]/gi, severity: "info", category: "media", description: "FLV video URL found." },
    // Audio files
    { name: "MP3 Audio URL", pattern: /['"`](https?:\/\/[^\s'"`]+\.mp3(?:\?[^\s'"`]*)?)['"`]/gi, severity: "info", category: "media", description: "MP3 audio URL found." },
    { name: "AAC Audio URL", pattern: /['"`](https?:\/\/[^\s'"`]+\.aac(?:\?[^\s'"`]*)?)['"`]/gi, severity: "info", category: "media", description: "AAC audio URL found." },
    // CDN / Storage media patterns
    { name: "Cloudfront Media", pattern: /['"`](https?:\/\/[a-z0-9]+\.cloudfront\.net\/[^\s'"`]+(?:\.(?:m3u8|mp4|ts|webm|mp3|mpd))[^\s'"`]*)['"`]/gi, severity: "info", category: "media", description: "AWS CloudFront media URL found." },
    { name: "S3 Media Object", pattern: /['"`](https?:\/\/[^\s'"`]*s3[^\s'"`]*\.amazonaws\.com\/[^\s'"`]+(?:\.(?:m3u8|mp4|ts|webm|mp3|mpd|flv|mkv|avi))[^\s'"`]*)['"`]/gi, severity: "info", category: "media", description: "AWS S3 media object found." },
    // Generic streaming / CDN patterns
    { name: "Video.js Source", pattern: /(?:src|source|file|url|stream|video|media|manifest|playlist)\s*[:=]\s*['"`](https?:\/\/[^\s'"`]+\.(?:m3u8|mp4|mpd|webm|flv)(?:\?[^\s'"`]*)?)['"`]/gi, severity: "info", category: "media", description: "Video source URL in config." },
    { name: "RTMP Stream", pattern: /rtmps?:\/\/[^\s'"<>]+/g, severity: "info", category: "media", description: "RTMP stream URL found." },
    // Document / file URLs
    { name: "PDF Document URL", pattern: /['"`](https?:\/\/[^\s'"`]+\.pdf(?:\?[^\s'"`]*)?)['"`]/gi, severity: "info", category: "media", description: "PDF document URL found." },
    { name: "Excel/CSV Data URL", pattern: /['"`](https?:\/\/[^\s'"`]+\.(?:xlsx?|csv)(?:\?[^\s'"`]*)?)['"`]/gi, severity: "medium", category: "media", description: "Spreadsheet/data file URL found." },
    // Signed / token-protected URLs (common in streaming)
    { name: "Signed Media URL", pattern: /['"`](https?:\/\/[^\s'"`]+\.(?:m3u8|mp4|ts|mpd|webm|flv)\?[^\s'"`]*(?:token|sig|signature|key|auth|Policy|Signature|Key-Pair-Id)=[^\s'"`]+)['"`]/gi, severity: "medium", category: "media", description: "Signed/token-protected media URL found. Token may be replayable." }
  ],

  // ── Mixed Content & Transport ──
  transport: [
    { name: "Mixed Content (HTTP Resource)", pattern: /(?:src|href|action)\s*=\s*['"]http:\/\/[^'"]+['"]/gi, severity: "medium", category: "transport", description: "HTTP resource loaded on HTTPS page (mixed content)." },
    { name: "Insecure Form Action", pattern: /<form[^>]*action\s*=\s*['"]http:\/\//gi, severity: "high", category: "transport", description: "Form submits data over HTTP." }
  ]
};

if (typeof globalThis !== "undefined") {
  globalThis.SCAN_PATTERNS = SCAN_PATTERNS;
}
