import base64
import json
import sys
from urllib.parse import parse_qsl, urlencode, urlparse
import aiohttp
import asyncio
import re
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

user_documents = os.path.expanduser("~") + "\\Documents"
dir = os.path.join(user_documents, "aniAPI")

gogoanime_url = "https://gogoanime.gg"


def parse_html(html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    info_body = soup.find("div", {"class": "anime_info_body_bg"})
    image_url = info_body.find("img")["src"]
    other_info = info_body.find_all("p", {"class": "type"})
    movie_id = soup.find("input", {"id": "movie_id"})["value"]
    info_dict = {
        "image_url": image_url,
        "type": other_info[0].text.replace("\n", "").replace("Type: ", ""),
        "synopsis": other_info[1].text.replace("\n", ""),
        "genres": [
            x["title"]
            for x in BeautifulSoup(str(other_info[2]), "html.parser").find_all("a")
        ],
        "release_year": other_info[3].text.replace("Released: ", ""),
        "status": other_info[4].text.replace("\n", "").replace("Status: ", ""),
        "movie_id": movie_id,
    }
    return info_dict


async def get_anime_info(category_url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(category_url) as response:
            html = await response.text()
            return parse_html(html)


def getWatchtime(args):
    with open(dir + "\\watchtime.json", "r") as f:
        try:
            watchtimeList = json.load(f)
        except:
            return 0
    link = args.get("link")
    ep = args.get("ep")
    try:
        showDict = watchtimeList[link]
    except:
        return 0
    try:
        return showDict[str(ep)]
    except:
        return 0


async def get_latest(show_link: str, movie_id: str) -> list:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://ajax.gogocdn.net/ajax/load-list-episode",
            params={"ep_start": 0, "ep_end": 9999, "id": movie_id},
        ) as response:
            res = await response.text()

    ep_list = [
        {
            "ep": i + 1,
            "link": gogoanime_url + x.find("a")["href"].strip(),
            "watchtime": getWatchtime(
                {
                    "link": show_link,
                    "ep": i + 1,
                }
            ),
        }
        for i, x in enumerate(
            reversed(BeautifulSoup(res, "html.parser").find_all("li"))
        )
    ]

    return ep_list


async def query(search_param) -> list:
    search_url = gogoanime_url + f"/search.html?keyword={search_param}"
    async with aiohttp.ClientSession() as session:
        async with session.get(search_url) as response:
            html = await response.text()
    soup = BeautifulSoup(html, "html.parser")
    pages = get_pages(soup)
    shows = parse_page(soup)
    promises = [get_page(search_url, i) for i in range(1, pages)]
    shows.extend(await asyncio.gather(*promises))
    return shows


async def get_page(search_url, index):
    req_link = search_url + f"&page={index + 1}"
    async with aiohttp.ClientSession() as session:
        async with session.get(req_link) as response:
            html = await response.text()
    soup = BeautifulSoup(html, "html.parser")
    return parse_page(soup)


def get_pages(soup):
    page_elements = soup.find_all("a", attrs={"data-page": re.compile(r"^ *\d[\d ]*$")})
    pages = [int(x.get("data-page")) for x in page_elements if x.get("data-page")]
    return pages[-1] if pages else 1


def parse_page(soup):
    shows = []
    for link in soup.find_all("p", attrs={"class": "name"}):
        a_tag = link.findChildren("a", recursive=False)
        shows.append(
            {"name": link.text.replace("\n", ""), "link": a_tag[0].get("href")}
        )
    return shows


async def get_stream_url(ep_url):
    async with aiohttp.ClientSession() as session:
        async with session.get(ep_url) as response:
            html = await response.text()
    soup = BeautifulSoup(html, "html.parser")
    link = soup.find("a", {"class": "active", "rel": "1"})
    uri = (
        f'https:{link["data-video"]}'
        if not link["data-video"].startswith("https:")
        else link["data-video"]
    )
    return await stream_url(uri)


# Padding for encryption/decryption using cryptography
def pad_data(data):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def unpad_data(padded_data):
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data


def aes_encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad_data(data.encode())
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("utf-8")


def aes_decrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decoded_data = base64.b64decode(data)
    decrypted_data = decryptor.update(decoded_data) + decryptor.finalize()
    return unpad_data(decrypted_data).decode("utf-8")


def get_enc_keys(html):

    keys = re.findall(r"(?:container|videocontent)-(\d+)", html)

    if not keys:
        return {}

    key, iv, second_key = keys

    return {
        "key": key.encode(),
        "second_key": second_key.encode(),
        "iv": iv.encode(),
    }


def get_data(soup):
    crypto = soup.find("script", {"data-name": "episode"})
    return crypto["data-value"]


async def stream_url(uri):
    async with aiohttp.ClientSession() as session:
        async with session.get(uri) as response:
            html = await response.text()
    soup = BeautifulSoup(html, "html.parser")
    enc_keys = get_enc_keys(html)

    parsed = urlparse(uri)
    ajax_url = parsed.scheme + "://" + parsed.netloc + "/encrypt-ajax.php?"

    data = aes_decrypt(get_data(soup), enc_keys["key"], enc_keys["iv"])
    data = dict(parse_qsl(data))

    id = urlparse(uri).query
    id = dict(parse_qsl(id))["id"]
    enc_id = aes_encrypt(id, enc_keys["key"], enc_keys["iv"])
    data.update(id=enc_id)

    headers = {
        "x-requested-with": "XMLHttpRequest",
        "referer": uri,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            ajax_url + urlencode(data) + f"&alias={id}",
            headers=headers,
        ) as response:
            json_obj = json.loads(await response.text())
            json_resp = json.loads(
                aes_decrypt(
                    (json_obj).get("data"),
                    enc_keys["second_key"],
                    enc_keys["iv"],
                )
            )
    files = [x["file"] for x in json_resp["source"]]
    files.extend([x["file"] for x in json_resp["source_bk"]])
    return files, json_resp["linkiframe"]


def output(data, recursive=True):
    json_data = json.dumps(data)
    print(json_data)
    sys.stdout.flush()


async def showsFromSeasonpage(page):
    async with aiohttp.ClientSession() as session:
        async with session.get(
            gogoanime_url + f"/new-season.html?page={page+1}"
        ) as response:
            html = await response.text()
    soup = BeautifulSoup(html, "html.parser")
    return showsFromSeasonSoup(soup)


async def recentFromSeasonpage(page):
    async with aiohttp.ClientSession() as session:
        async with session.get(gogoanime_url + f"/?page={page+1}") as response:
            html = await response.text()
    soup = BeautifulSoup(html, "html.parser")
    return showsFromSeasonSoup(soup)


def showsFromSeasonSoup(soup):
    shows = []
    for li in [
        x for x in soup.find("div", {"class": "last_episodes"}).ul if x.name == "li"
    ]:
        a = li.a
        img = a.img
        seasonal = {
            "name": a.get("title"),
            "link": a.get("href"),
            "image_url": img.get("src"),
        }
        shows.append(seasonal)
    return shows


async def fetch_seasonals():
    async with aiohttp.ClientSession() as session:
        async with session.get(gogoanime_url + "/new-season.html") as response:
            html = await response.text()
    soup = BeautifulSoup(html, "html.parser")
    pageCount = len(
        [x for x in soup.find("div", {"class": "pagination"}).ul if x.name == "li"]
    )
    seaonals = showsFromSeasonSoup(soup)
    promises = [showsFromSeasonpage(i) for i in range(1, pageCount)]
    for seasonalList in await asyncio.gather(*promises):
        seaonals.extend(seasonalList)
    return seaonals


async def fetch_recent_releases():
    async with aiohttp.ClientSession() as session:
        async with session.get(gogoanime_url) as response:
            html = await response.text()
    soup = BeautifulSoup(html, "html.parser")
    pageCount = len(
        [x for x in soup.find("div", {"class": "pagination"}).ul if x.name == "li"]
    )
    shows = showsFromSeasonSoup(soup)
    promises = [recentFromSeasonpage(i) for i in range(1, pageCount)]
    for showList in await asyncio.gather(*promises):
        shows.extend(showList)
    shows = [x["link"] for x in shows]
    shows = list(dict.fromkeys(shows))
    shows = ["/category" + re.sub(r"-episode.*", "", x) for x in shows]
    return shows
