# Third-Party Notices

PayWarden is licensed under the [MIT License](LICENSE). It uses the open-source components below,
each under its own license. All are compatible with MIT. Packages are installed from PyPI at build
time and are not stored in this repository, except AG Grid, which is vendored (see below).

## Vendored in this repository

| Component | Version | License | Location |
|---|---|---|---|
| AG Grid Community | 33.3.2 | MIT | `static/vendor/ag-grid-community.min.js` · license text: [`static/vendor/AG-GRID-LICENSE.txt`](static/vendor/AG-GRID-LICENSE.txt) |

## Runtime dependencies (`requirements.txt`)

| Package | Version | License | Project |
|---|---|---|---|
| fastapi | 0.162.0 | MIT | https://github.com/fastapi/fastapi |
| starlette (via fastapi) | 1.10.0 | BSD-3-Clause | https://github.com/encode/starlette |
| uvicorn | 0.54.0 | BSD-3-Clause | https://github.com/encode/uvicorn |
| httpx | 0.28.1 | BSD-3-Clause | https://github.com/encode/httpx |
| pydantic | 2.13.5 | MIT | https://github.com/pydantic/pydantic |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| pyotp | 2.10.0 | MIT | https://github.com/pyauth/pyotp |
| anthropic | 2.3.0 | Apache-2.0 | https://github.com/anthropics/anthropic-sdk-python |
| python-dotenv | 1.2.3 | BSD-3-Clause | https://github.com/theskumar/python-dotenv |

The Docker image redistributes these packages. Each package's full license text is installed with
it (in its `*.dist-info` directory in the image's site-packages). Packages under Apache-2.0 are
used unmodified.

## MCP server (`requirements-mcp.txt`)

Installed on the agent's machine, not in the Docker image.

| Package | Version | License | Project |
|---|---|---|---|
| mcp | 2.3.0 | MIT | https://github.com/modelcontextprotocol/python-sdk |
| httpx | 0.28.1 | BSD-3-Clause | https://github.com/encode/httpx |

## Development and CI only (`requirements-dev.txt`)

pytest (MIT), bandit (Apache-2.0) and pip-audit (Apache-2.0) are used for testing and scanning.
They are not shipped in the Docker image. CI also runs the Postman collection with Newman
(Apache-2.0), fetched with `npx` at test time and not redistributed.

## Fonts

IBM Plex Sans and IBM Plex Mono are loaded at runtime from Google Fonts and are not redistributed.
They are licensed under the SIL Open Font License 1.1.

## Services and data

- **PayPal REST APIs (sandbox)** and **Anthropic Claude API** are used under their respective
  developer terms. No PayPal or Anthropic code is included.
- `data/watchlist.json` is a **synthetic** sanctions list written for this project and contains no
  real list data. `data/geo_risk.json` holds country codes summarised from public FATF and
  sanctions-program publications.
