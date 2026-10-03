import httpx

CA_BUNDLE = "/etc/ssl/certs/corp-ca.pem"


def get(url: str):
    return httpx.get(url, verify=CA_BUNDLE)


def get_local():
    # Local dev server with a self-signed certificate.
    return httpx.get("https://localhost:8443/health", verify=False)
