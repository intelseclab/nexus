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
    { name: "OpenAI API Key", pattern: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/g, severity: "critical", category: "api-key", description: "OpenAI API Key found." },
    { name: "Anthropic API Key", pattern: /sk-ant-[A-Za-z0-9\-_]{80,}/g, severity: "critical", category: "api-key", description: "Anthropic API Key found." },
    { name: "Supabase Key", pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}/g, severity: "medium", category: "api-key", description: "Supabase anon/service key found." },
    { name: "Datadog API Key", pattern: /(?:dd|datadog)[_-]?(?:api[_-]?key|app[_-]?key)\s*[:=]\s*['"]([a-f0-9]{32,40})['"]/gi, severity: "high", category: "api-key", description: "Datadog API Key found." },
    { name: "New Relic Key", pattern: /NRAK-[A-Z0-9]{27}/g, severity: "high", category: "api-key", description: "New Relic API Key found." },
    { name: "Sentry DSN", pattern: /https:\/\/[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io\/\d+/g, severity: "medium", category: "api-key", description: "Sentry DSN found. Can be used to send fake error data." },
    { name: "Cloudflare API Key", pattern: /(?:cloudflare)[_-]?(?:api[_-]?key)\s*[:=]\s*['"]([a-f0-9]{37})['"]/gi, severity: "critical", category: "api-key", description: "Cloudflare API Key found." },
    { name: "DigitalOcean Token", pattern: /dop_v1_[a-f0-9]{64}/g, severity: "critical", category: "api-key", description: "DigitalOcean Personal Access Token found." },
    { name: "NPM Token", pattern: /npm_[A-Za-z0-9]{36}/g, severity: "critical", category: "api-key", description: "NPM access token found." },
    { name: "PyPI Token", pattern: /pypi-[A-Za-z0-9_-]{50,}/g, severity: "critical", category: "api-key", description: "PyPI API token found." },
    { name: "Vault Token", pattern: /hvs\.[A-Za-z0-9_-]{24,}/g, severity: "critical", category: "api-key", description: "HashiCorp Vault token found." }
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
    { name: "File Path Disclosure", pattern: /(?:\/home\/[a-z_][a-z0-9_-]*|\/var\/www|\/opt\/[a-z]+|C:\\\\(?:Users|inetpub|Program Files)\\\\[^\s'"<>]+|\/etc\/[a-z][a-z0-9_-]*)/g, severity: "low", category: "info-leak", description: "Server file path found." }
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
    { name: "REST API Endpoint", pattern: /['"`](\/api\/v?\d*\/[a-zA-Z0-9\/_-]+)['"`]/g, severity: "info", category: "endpoint", description: "REST API endpoint found." },
    { name: "GraphQL Endpoint", pattern: /['"`](\/graphql\b[^'"`]*)['"`]/g, severity: "info", category: "endpoint", description: "GraphQL endpoint reference." },
    { name: "WebSocket Endpoint", pattern: /wss?:\/\/[^\s'"<>]+/g, severity: "info", category: "endpoint", description: "WebSocket endpoint found." },
    { name: "API Base URL", pattern: /(?:baseURL|apiUrl|API_URL|api_base|API_BASE|API_ENDPOINT|apiEndpoint|backendUrl|BACKEND_URL)\s*[:=]\s*['"`](https?:\/\/[^'"`]+)['"`]/gi, severity: "medium", category: "endpoint", description: "API base URL configuration found." },
    { name: "Fetch/Axios Call", pattern: /(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*['"`](\/[a-zA-Z0-9\/_-]{3,})['"`]/g, severity: "info", category: "endpoint", description: "API call found in JavaScript." },
    { name: "XMLHttpRequest URL", pattern: /\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"`](\/[a-zA-Z0-9\/_-]{3,})['"`]/gi, severity: "info", category: "endpoint", description: "XHR API call found." }
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
    { name: "Open Redirect Parameter", pattern: /(?:redirect|return|next|url|goto|dest|destination|redir|redirect_uri|return_url|continue|forward)\s*=\s*https?/gi, severity: "medium", category: "dom-security", description: "Potential open redirect parameter in URL." }
  ],

  // ── Technology Fingerprinting ──
  technology: [
    { name: "WordPress", pattern: /\/wp-content\/|\/wp-includes\/|wp-json/g, severity: "info", category: "technology", description: "WordPress detected." },
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
    { name: "Cloudflare", pattern: /__cf_bm|cf-ray|cloudflare/gi, severity: "info", category: "technology", description: "Cloudflare detected." },
    { name: "Google Analytics", pattern: /(?:gtag|ga)\s*\(\s*['"](?:send|config|event)['"]|google-analytics\.com\/(?:analytics|ga|gtag)/g, severity: "info", category: "technology", description: "Google Analytics tracking detected." },
    { name: "Google Tag Manager", pattern: /googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]+/g, severity: "info", category: "technology", description: "Google Tag Manager detected." },
    { name: "Facebook Pixel", pattern: /fbq\s*\(\s*['"]init['"]|connect\.facebook\.net\/.*fbevents/g, severity: "info", category: "technology", description: "Facebook Pixel tracking detected." },
    { name: "Hotjar", pattern: /hotjar\.com|hj\s*\(\s*['"]identify['"]/g, severity: "info", category: "technology", description: "Hotjar analytics detected." },
    { name: "Segment", pattern: /analytics\.(?:identify|track|page)\s*\(|cdn\.segment\.com/g, severity: "info", category: "technology", description: "Segment analytics detected." },
    { name: "Intercom", pattern: /intercomSettings|widget\.intercom\.io|Intercom\s*\(/g, severity: "info", category: "technology", description: "Intercom widget detected." },
    { name: "Sentry Error Tracking", pattern: /sentry\.io|Sentry\.init|dsn:\s*['"]https:\/\/[^'"]*sentry/g, severity: "info", category: "technology", description: "Sentry error tracking detected." },
    { name: "PostHog Analytics", pattern: /posthog\.init|posthog\.capture|app\.posthog\.com/g, severity: "info", category: "technology", description: "PostHog analytics detected." }
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
