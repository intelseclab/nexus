/**
 * Sensitive paths to probe. Used by background.js path checker.
 */

const SENSITIVE_PATHS = [
  // ── Configuration Files ──
  { path: "/.env", severity: "critical", category: "config-file", title: ".env File Exposed", description: "Environment configuration file accessible. Likely contains secrets." },
  { path: "/.env.local", severity: "critical", category: "config-file", title: ".env.local Exposed", description: "Local environment file accessible." },
  { path: "/.env.production", severity: "critical", category: "config-file", title: ".env.production Exposed", description: "Production environment file accessible." },
  { path: "/.env.development", severity: "high", category: "config-file", title: ".env.development Exposed", description: "Development environment file accessible." },
  { path: "/.env.backup", severity: "critical", category: "config-file", title: ".env.backup Exposed", description: "Environment backup file accessible." },
  { path: "/config.json", severity: "high", category: "config-file", title: "config.json Exposed", description: "JSON configuration file accessible." },
  { path: "/config.yml", severity: "high", category: "config-file", title: "config.yml Exposed", description: "YAML configuration file accessible." },
  { path: "/config.yaml", severity: "high", category: "config-file", title: "config.yaml Exposed", description: "YAML configuration file accessible." },
  { path: "/config.xml", severity: "high", category: "config-file", title: "config.xml Exposed", description: "XML configuration file accessible." },
  { path: "/wp-config.php", severity: "critical", category: "config-file", title: "wp-config.php Exposed", description: "WordPress configuration with database credentials." },
  { path: "/web.config", severity: "high", category: "config-file", title: "web.config Exposed", description: "IIS/ASP.NET configuration file accessible." },
  { path: "/application.yml", severity: "high", category: "config-file", title: "application.yml Exposed", description: "Spring Boot configuration file." },
  { path: "/application.properties", severity: "high", category: "config-file", title: "application.properties Exposed", description: "Spring Boot properties file." },
  { path: "/appsettings.json", severity: "high", category: "config-file", title: "appsettings.json Exposed", description: ".NET application settings file." },
  { path: "/settings.py", severity: "high", category: "config-file", title: "Django settings.py Exposed", description: "Django settings file, may contain SECRET_KEY." },
  { path: "/database.yml", severity: "critical", category: "config-file", title: "database.yml Exposed", description: "Database configuration with credentials." },
  { path: "/docker-compose.yml", severity: "high", category: "config-file", title: "docker-compose.yml Exposed", description: "Docker Compose configuration." },
  { path: "/Dockerfile", severity: "medium", category: "config-file", title: "Dockerfile Exposed", description: "Docker build file accessible." },
  { path: "/package.json", severity: "low", category: "config-file", title: "package.json Exposed", description: "Node.js package manifest. Reveals dependencies." },
  { path: "/composer.json", severity: "low", category: "config-file", title: "composer.json Exposed", description: "PHP Composer manifest. Reveals dependencies." },
  { path: "/Gemfile", severity: "low", category: "config-file", title: "Gemfile Exposed", description: "Ruby dependency file." },
  { path: "/requirements.txt", severity: "low", category: "config-file", title: "requirements.txt Exposed", description: "Python dependency file." },

  // ── Version Control ──
  { path: "/.git/config", severity: "critical", category: "vcs", title: "Git Config Exposed", description: "Git configuration accessible. May reveal repo URLs and credentials." },
  { path: "/.git/HEAD", severity: "high", category: "vcs", title: "Git HEAD Exposed", description: "Git HEAD reference accessible. Confirms .git directory exposure." },
  { path: "/.git/logs/HEAD", severity: "high", category: "vcs", title: "Git Logs Exposed", description: "Git commit logs accessible." },
  { path: "/.gitignore", severity: "low", category: "vcs", title: ".gitignore Exposed", description: "Git ignore file reveals project structure." },
  { path: "/.svn/entries", severity: "high", category: "vcs", title: "SVN Entries Exposed", description: "SVN metadata accessible." },
  { path: "/.hg/store", severity: "high", category: "vcs", title: "Mercurial Store Exposed", description: "Mercurial repository data accessible." },
  { path: "/.bzr/README", severity: "high", category: "vcs", title: "Bazaar Repo Exposed", description: "Bazaar repository accessible." },

  // ── API Documentation ──
  { path: "/swagger.json", severity: "medium", category: "api-docs", title: "Swagger JSON Exposed", description: "API documentation accessible. Reveals all API endpoints." },
  { path: "/swagger.yaml", severity: "medium", category: "api-docs", title: "Swagger YAML Exposed", description: "API documentation accessible." },
  { path: "/swagger-ui.html", severity: "medium", category: "api-docs", title: "Swagger UI Accessible", description: "Interactive API documentation accessible." },
  { path: "/swagger-ui/", severity: "medium", category: "api-docs", title: "Swagger UI Directory", description: "Swagger UI directory accessible." },
  { path: "/api-docs", severity: "medium", category: "api-docs", title: "API Docs Endpoint", description: "API documentation endpoint accessible." },
  { path: "/api/docs", severity: "medium", category: "api-docs", title: "API Docs Accessible", description: "API documentation accessible." },
  { path: "/openapi.json", severity: "medium", category: "api-docs", title: "OpenAPI Spec Exposed", description: "OpenAPI specification accessible." },
  { path: "/graphql", severity: "medium", category: "api-docs", title: "GraphQL Endpoint", description: "GraphQL endpoint accessible. Introspection may be enabled." },
  { path: "/graphiql", severity: "medium", category: "api-docs", title: "GraphiQL Interface", description: "GraphQL IDE accessible." },
  { path: "/playground", severity: "medium", category: "api-docs", title: "API Playground", description: "API playground/explorer accessible." },
  { path: "/redoc", severity: "low", category: "api-docs", title: "ReDoc API Docs", description: "ReDoc API documentation accessible." },
  { path: "/v1/api-docs", severity: "medium", category: "api-docs", title: "V1 API Docs", description: "Versioned API documentation." },
  { path: "/v2/api-docs", severity: "medium", category: "api-docs", title: "V2 API Docs", description: "Versioned API documentation." },

  // ── Admin Panels ──
  { path: "/admin", severity: "high", category: "admin", title: "Admin Panel", description: "Admin panel accessible." },
  { path: "/admin/", severity: "high", category: "admin", title: "Admin Panel", description: "Admin panel accessible." },
  { path: "/administrator", severity: "high", category: "admin", title: "Administrator Panel", description: "Administrator panel accessible." },
  { path: "/wp-admin", severity: "high", category: "admin", title: "WordPress Admin", description: "WordPress admin panel." },
  { path: "/wp-login.php", severity: "medium", category: "admin", title: "WordPress Login", description: "WordPress login page." },
  { path: "/phpmyadmin", severity: "critical", category: "admin", title: "phpMyAdmin", description: "phpMyAdmin database management interface accessible." },
  { path: "/adminer.php", severity: "critical", category: "admin", title: "Adminer", description: "Adminer database management accessible." },
  { path: "/cpanel", severity: "high", category: "admin", title: "cPanel", description: "cPanel hosting management accessible." },
  { path: "/_admin", severity: "high", category: "admin", title: "Admin Panel", description: "Admin panel accessible." },
  { path: "/dashboard", severity: "medium", category: "admin", title: "Dashboard", description: "Dashboard endpoint accessible." },
  { path: "/console", severity: "high", category: "admin", title: "Console", description: "Application console accessible." },
  { path: "/manage", severity: "medium", category: "admin", title: "Management Interface", description: "Management interface accessible." },

  // ── Server Info & Diagnostics ──
  { path: "/phpinfo.php", severity: "high", category: "server-info", title: "phpinfo() Exposed", description: "PHP configuration information exposed." },
  { path: "/info.php", severity: "high", category: "server-info", title: "PHP Info Page", description: "PHP info page accessible." },
  { path: "/server-status", severity: "high", category: "server-info", title: "Apache Server Status", description: "Apache server status page accessible." },
  { path: "/server-info", severity: "high", category: "server-info", title: "Apache Server Info", description: "Apache server info page accessible." },
  { path: "/elmah.axd", severity: "high", category: "server-info", title: "ELMAH Error Log", description: "ASP.NET error logging module accessible." },
  { path: "/trace.axd", severity: "high", category: "server-info", title: "ASP.NET Trace", description: "ASP.NET tracing information accessible." },
  { path: "/health", severity: "info", category: "server-info", title: "Health Check", description: "Health check endpoint." },
  { path: "/healthz", severity: "info", category: "server-info", title: "Health Check", description: "Kubernetes-style health check." },
  { path: "/actuator", severity: "high", category: "server-info", title: "Spring Actuator", description: "Spring Boot Actuator endpoints accessible." },
  { path: "/actuator/env", severity: "critical", category: "server-info", title: "Spring Actuator Env", description: "Spring Actuator environment variables exposed." },
  { path: "/actuator/health", severity: "info", category: "server-info", title: "Spring Actuator Health", description: "Spring Actuator health check." },
  { path: "/actuator/configprops", severity: "high", category: "server-info", title: "Spring Config Props", description: "Spring configuration properties exposed." },
  { path: "/metrics", severity: "medium", category: "server-info", title: "Metrics Endpoint", description: "Application metrics accessible." },
  { path: "/debug", severity: "high", category: "server-info", title: "Debug Endpoint", description: "Debug endpoint accessible." },
  { path: "/debug/pprof", severity: "high", category: "server-info", title: "Go pprof", description: "Go profiling endpoint exposed." },
  { path: "/__debug__", severity: "high", category: "server-info", title: "Debug Panel", description: "Debug panel accessible." },
  { path: "/status", severity: "info", category: "server-info", title: "Status Page", description: "Status endpoint accessible." },
  { path: "/stats", severity: "medium", category: "server-info", title: "Statistics", description: "Statistics endpoint accessible." },

  // ── Standard Files ──
  { path: "/robots.txt", severity: "info", category: "standard", title: "robots.txt", description: "Robots.txt file reveals disallowed paths." },
  { path: "/sitemap.xml", severity: "info", category: "standard", title: "sitemap.xml", description: "Sitemap reveals site structure." },
  { path: "/crossdomain.xml", severity: "medium", category: "standard", title: "crossdomain.xml", description: "Flash cross-domain policy file." },
  { path: "/clientaccesspolicy.xml", severity: "medium", category: "standard", title: "clientaccesspolicy.xml", description: "Silverlight cross-domain policy file." },
  { path: "/.well-known/security.txt", severity: "info", category: "standard", title: "security.txt", description: "Security contact information file." },
  { path: "/security.txt", severity: "info", category: "standard", title: "security.txt", description: "Security contact information file." },
  { path: "/humans.txt", severity: "info", category: "standard", title: "humans.txt", description: "Humans.txt reveals team information." },
  { path: "/.well-known/openid-configuration", severity: "info", category: "standard", title: "OpenID Configuration", description: "OpenID Connect discovery document." },

  // ── Backup & Log Files ──
  { path: "/backup.sql", severity: "critical", category: "backup", title: "SQL Backup Exposed", description: "Database backup file accessible." },
  { path: "/backup.zip", severity: "critical", category: "backup", title: "Backup Archive Exposed", description: "Backup archive accessible." },
  { path: "/dump.sql", severity: "critical", category: "backup", title: "SQL Dump Exposed", description: "Database dump accessible." },
  { path: "/database.sql", severity: "critical", category: "backup", title: "Database SQL Exposed", description: "Database file accessible." },
  { path: "/error.log", severity: "high", category: "backup", title: "Error Log Exposed", description: "Error log accessible. May contain sensitive data." },
  { path: "/access.log", severity: "medium", category: "backup", title: "Access Log Exposed", description: "Access log accessible." },
  { path: "/debug.log", severity: "high", category: "backup", title: "Debug Log Exposed", description: "Debug log accessible." },
  { path: "/npm-debug.log", severity: "medium", category: "backup", title: "NPM Debug Log", description: "NPM debug log accessible." },

  // ── CI/CD & DevOps ──
  { path: "/.github/workflows", severity: "low", category: "cicd", title: "GitHub Workflows", description: "GitHub Actions workflow directory accessible." },
  { path: "/.gitlab-ci.yml", severity: "medium", category: "cicd", title: "GitLab CI Config", description: "GitLab CI configuration file accessible." },
  { path: "/Jenkinsfile", severity: "medium", category: "cicd", title: "Jenkinsfile Exposed", description: "Jenkins pipeline definition accessible." },
  { path: "/.circleci/config.yml", severity: "medium", category: "cicd", title: "CircleCI Config", description: "CircleCI configuration accessible." },
  { path: "/.travis.yml", severity: "low", category: "cicd", title: "Travis CI Config", description: "Travis CI configuration accessible." },

  // ── Cloud & Infrastructure ──
  { path: "/.aws/credentials", severity: "critical", category: "cloud", title: "AWS Credentials File", description: "AWS credentials file accessible." },
  { path: "/.aws/config", severity: "high", category: "cloud", title: "AWS Config File", description: "AWS configuration file accessible." },
  { path: "/terraform.tfstate", severity: "critical", category: "cloud", title: "Terraform State", description: "Terraform state file may contain secrets." },
  { path: "/terraform.tfvars", severity: "critical", category: "cloud", title: "Terraform Variables", description: "Terraform variables file may contain secrets." }
];

if (typeof globalThis !== "undefined") {
  globalThis.SENSITIVE_PATHS = SENSITIVE_PATHS;
}
