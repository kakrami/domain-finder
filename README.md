# Domain Finder · v1.0.1

A single-file HTML interface with a small Cloudflare Worker for private API calls. No frontend libraries, database, separate API URL, or code edits are needed.

**Upload the extracted files, not the ZIP itself.** HTML alone previews the interface; live searches need the included Worker.

## Deploy from GitHub

1. Extract the ZIP. Upload these four files to the root of `kakrami/domain-finder` on `main`:
   - `index.html`
   - `worker.js`
   - `wrangler.jsonc`
   - `README.md`

2. In Cloudflare, open **Workers & Pages → Create application → Import a repository**. Connect GitHub, select `kakrami/domain-finder`, and use:

   | Setting | Value |
   | --- | --- |
   | Worker / project name | `domain-finder` |
   | Production branch | `main` |
   | Root directory | Repository root; leave the default |
   | Build command | Leave empty |
   | Deploy command | `npx wrangler deploy` |

   Select **Save and Deploy**. The project name must match `name` in `wrangler.jsonc`. This is a **Worker**, not a Pages project. You do not need a GitHub Actions workflow or GitHub secrets.

3. Open the deployed Worker → **Settings → Variables and Secrets → Add**. Add both entries as type **Secret**, then select **Deploy**:

   | Exact secret name | Value |
   | --- | --- |
   | `CF_ACCOUNT_ID` | Your 32-character Cloudflare account ID |
   | `CF_API_TOKEN` | Your Cloudflare API token, with Registrar write permissions for that account |

   These are **runtime secrets**, not Build variables. Do not put them in GitHub, the HTML, or this configuration file. Paste only the token value, without `Bearer`.

4. Open the `workers.dev` address Cloudflare supplies. Select **Check again** if the page was already open. Search a phrase, a full domain, or up to 20 full domains separated by commas.

The initial deployment can show “Setup needed” until the secrets are added. “Secrets configured” confirms the settings are present; the first search checks whether Cloudflare accepts the credentials.

## Account setup

To find your account ID, press Ctrl+K (Windows) or Cmd+K (Mac) in the Cloudflare dashboard and search **Copy account ID**. The Workers & Pages overview also has an Account Details section. Use the account ID, not a zone ID or a Worker address.

Cloudflare's Registrar API guide specifies Registrar **write** token permissions. Limit the token to the intended account. Its documented prerequisites also include a billing profile/default payment method, a default registrant contact, and acceptance of the Domain Registration Agreement. Follow the linked guide to complete that account setup.

**This app never calls the registration endpoint and cannot purchase, renew, or modify a domain.**

## Behavior and limits

Keyword searches return cached suggestions; the page then requests a fresh availability/pricing check. Only successful affirmative checks receive “Available.” Incomplete checks remain unverified. Unsupported extensions are not mislabeled as taken. Missing prices are shown as a dash.

The Registrar API is in beta and supports a subset of dashboard extensions. Prices and availability can change; confirm them at checkout. Search, filter, sort, recheck, stop, and copy controls are included.

The deployed search service is public by default. Anyone with its address can consume its search/API quota. Protect the deployment with authentication before using it as a private service. Secrets are never returned to the browser.

## v1.0.1 repair

The shared Registrar request now uses `redirect: 'manual'` and rejects redirects explicitly. It does not forward your token to a redirect destination. Request failures include the underlying error with both secrets redacted before truncation. HTTP errors include their response status. The initial status says “Secrets configured,” not “Ready to search”; credential acceptance is established only by a successful API request.

## Verification

44 local Worker-handler regression checks and 12 offline Chromium checks passed. These use simulated API responses; the request guard simulates the redirect validation published in Cloudflare workerd source. Browser navigation is restricted in the test environment, so interface tests use offline rendering. The actual workerd binary, Wrangler build, live Cloudflare deployment, account authentication, and current domain prices have not been tested against your account. The corrected files do not contain either secret value.

## Official references

Documentation checked September 29, 2026:

- Registrar API, permissions, prerequisites, and beta limits: https://developers.cloudflare.com/registrar/registrar-api/
- Workers Git deployment: https://developers.cloudflare.com/workers/ci-cd/builds/
- Runtime secrets: https://developers.cloudflare.com/workers/configuration/secrets/
- Account ID: https://developers.cloudflare.com/fundamentals/account/find-account-and-zone-ids/
- HTML module imports: https://developers.cloudflare.com/workers/wrangler/bundling/

- Workers runtime redirect validation: https://github.com/cloudflare/workerd/blob/ab1b3926727b2fdc1f104d99eef93a878a93f665/src/workerd/api/http.c++
