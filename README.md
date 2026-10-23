# Work 1 — Secure REST API + CI/CD + CVE-2018-11776

Educational security laboratory. Python 3.12 standard library API, SQLite, signed JWT, scrypt password hashes, parameterized SQL, HTML escaping, SAST and SCA CI.

## Installation and first run

```bash
export JWT_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
export DEMO_PASSWORD='Choose-A-Strong-Local-Password!'
python src/app.py
```

Requires Python 3.11+ and no runtime third-party packages. Default: `http://127.0.0.1:8000`. Environment variables: `APP_HOST`, `APP_PORT`, `APP_DB`, `JWT_SECRET` (minimum 32 bytes), `DEMO_PASSWORD` (required on initial database creation). Password never appears in database plaintext. Do not publish real secrets; local HTTP mode is for localhost only. Use TLS with a reverse proxy for any deployment.

## Endpoints

1. `POST /auth/login`: JSON `{"login":"demo","password":"..."}`; returns an HS256 JWT (30 minutes). Invalid credentials: HTTP 401.
2. `GET /api/data`: `Authorization: Bearer <JWT>`; returns at most 100 posts; no or invalid token: HTTP 401.
3. `POST /api/posts`: same Bearer token; JSON `{"text":"Hello"}`; creates a post (1–500 characters); returns HTTP 201.

Example commands after setting credentials and starting the application:

```bash
curl -i http://127.0.0.1:8000/api/data
curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"login":"demo","password":"Choose-A-Strong-Local-Password!"}'
# Copy the token value from the previous response:
curl -i http://127.0.0.1:8000/api/data -H 'Authorization: Bearer YOUR_JWT_HERE'
curl -i -X POST http://127.0.0.1:8000/api/posts -H 'Authorization: Bearer YOUR_JWT_HERE' \
  -H 'Content-Type: application/json' -d '{"text":"<script>alert(1)</script>"}'
```

## Security design

**SQLi**: every value in `SELECT` and `INSERT` queries uses `?` bound placeholders, never user-controlled SQL strings. **XSS**: all returned user-supplied text uses `html.escape(..., quote=True)` and responses have `application/json`, `nosniff`, and restrictive CSP headers. Client applications must still use safe DOM APIs and not `innerHTML`. **Authentication**: salted `hashlib.scrypt` stored in the database; JWT HS256 HMAC signature checked using `hmac.compare_digest`, a fixed accepted JWT header, issue time and expiry. Protected routes reject missing, invalid, or expired JWTs. HTTPS, throttling, key rotation and managed identity are required before any production use.

## Test and continuous integration

```bash
python -m unittest discover -s tests -v
```

`.github/workflows/ci.yml` runs on every push / pull request. It executes the six API tests, Bandit SAST, and OWASP Dependency-Check SCA in Docker; reports are uploaded as workflow artifacts. These scans cannot be claimed passed until GitHub Actions has actually run. Upload screenshots from its Actions artifacts into `evidence/`. Dependency-Check requires network access to vulnerability feeds and can fail if feed availability/rate limits cause errors.

## Selected vulnerability: CVE-2018-11776 (Apache Struts S2-057)

**Scope**: Only an isolated, permissioned local Docker test system. Apache Struts 2.3.x through 2.3.34 and 2.5.x through 2.5.16 can evaluate an attacker-controlled namespace as an OGNL expression in certain configurations (e.g. `alwaysSelectFullNamespace=true` and missing or wildcard action namespaces). This can permit remote code execution. See Apache advisory S2-057: https://cwiki.apache.org/confluence/display/WW/S2-057 and Vulhub README: https://github.com/vulhub/vulhub/tree/master/struts2/s2-057 .

### Reproduce in Vulhub (non-destructive arithmetic proof)

```bash
git clone https://github.com/vulhub/vulhub.git
cd vulhub/struts2/s2-057
docker compose up -d
docker compose ps
curl -i 'http://127.0.0.1:8080/showcase/'
curl -i 'http://127.0.0.1:8080/struts2-showcase/$%7B233*233%7D/actionChain1.action'
```

Per the original Vulhub README, the affected Location response contains `54289` (= 233×233). This is a safe indicator of evaluation, not command execution. Record HTTP response headers and screenshots in `evidence/`.

### Configuration mitigation / repeat the test

In the Vulhub `struts2/s2-057` directory:

```bash
docker compose down
cp /PATH/TO/work1_project/cve_fix/struts-actionchaining.xml ./struts-actionchaining.xml
docker compose up --build -d
curl -i 'http://127.0.0.1:8080/struts2-showcase/$%7B233*233%7D/actionChain1.action'
curl -i 'http://127.0.0.1:8080/showcase/'
```

The provided XML explicitly configures a fixed package namespace and redirect namespace rather than inheriting a user-derived namespace. The expected validation is that the Location header **does not** show `54289`; confirm the legitimate showcase endpoint still loads. This is **a limited configuration-level mitigation, not a comprehensive patch**. Upgrade the framework to fixed versions (2.3.35 / 2.5.17 or a currently supported version) and fully regression-test the application. Do not assume a different `vulhub/struts2` image tag exists without verifying its availability. Because Docker was unavailable in the authoring environment, neither pre-fix exploit nor post-mitigation behavior is represented as executed.

### Collected evidence to attach

- `evidence/01_api_unauthenticated.png`
- `evidence/02_api_authenticated.png`
- `evidence/03_bandit_action.png`
- `evidence/04_dependency_check_action.png`
- `evidence/05_cve_before_location.png`
- `evidence/06_cve_after_location.png`
- `evidence/07_regression_showcase.png`

## Submission items to complete in your account

1. Publish this folder to a **public** GitHub/GitLab repository; insert its real URL into your report.
2. Trigger workflow, fix any reported issues, attach authentic SAST/SCA screenshots, and insert the real link to the latest successful run.
3. Run the Docker CVE lab, collect authentic before/after/regression screenshots and preserve logs.
4. Fill in your lab variant, full name, and HDU number; submit the report and `cve_fix/` directory.

## Sources

- Work 1 assignment, *Labs Full Manual HDU IS(3).pdf*, pp. 1–5.
- Apache Struts security bulletin S2-057: https://cwiki.apache.org/confluence/display/WW/S2-057
- Vulhub Struts2 S2-057 laboratory: https://github.com/vulhub/vulhub/tree/master/struts2/s2-057
- NVD entry: https://nvd.nist.gov/vuln/detail/CVE-2018-11776
- OWASP: https://owasp.org/www-project-top-ten/
