import httpx
import ssl

ctx = ssl._create_unverified_context()


def get(url: str):
    return httpx.get(url, verify=False)
