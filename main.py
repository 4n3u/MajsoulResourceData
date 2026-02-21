import os
import json
import re
import time
import hashlib
import base64
import warnings
import threading
from glob import glob
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
from urllib3.exceptions import InsecureRequestWarning

CN_AES_KEY = "wrelupqezdfrqdsd".encode("utf-8")
CN_AES_IV = "sfaqweertfvfdxad".encode("utf-8")

REGION_CONFIG = {
    "jp": {
        "launcher_url": "https://launcher-pkg-jp.yo-star.com/pubplat/game_launcher/install_pkg/launcher/MajSoul_JP/latest.yml",
        "base_config_url": "https://api-launcher-jp.yo-star.com/api/launcher/base/config",
        "social_media_url": "https://api-launcher-jp.yo-star.com/api/launcher/social/media/resource",
        "game_config_url": "https://api-launcher-jp.yo-star.com/api/launcher/game/config",
        "game_config_json_url": "https://api-launcher-jp.yo-star.com/api/launcher/game/config/json",
        "operations_resource_url": "https://api-launcher-jp.yo-star.com/api/launcher/operations/resource",
        "game_tag": "MajSoul_JP",
        "resource_base_urls": [
            "https://appassets.mahjongsoul.com",
            "https://appassetsback.mahjongsoul.com",
        ],
    },
    "en": {
        "launcher_url": "https://launcher-pkg-en.yo-star.com/pubplat/game_launcher/install_pkg/launcher/MajSoul_EN/latest.yml",
        "base_config_url": "https://api-launcher-en.yo-star.com/api/launcher/base/config",
        "social_media_url": "https://api-launcher-en.yo-star.com/api/launcher/social/media/resource",
        "game_config_url": "https://api-launcher-en.yo-star.com/api/launcher/game/config",
        "game_config_json_url": "https://api-launcher-en.yo-star.com/api/launcher/game/config/json",
        "operations_resource_url": "https://api-launcher-en.yo-star.com/api/launcher/operations/resource",
        "game_tag": "MajSoul_EN",
        "resource_base_urls": [
            "https://appassets.mahjongsoul.com",
            "https://appassetsback.mahjongsoul.com",
        ],
    },
    "cn": {
        "launcher_config_url": "https://majsoul-hk-game.oss-accelerate.aliyuncs.com/app/misc/launcher_config_2.json",
        "client_bundle_settings_url": "https://app-update-1.catmajsoul.com/app/v3/release/clientBundleSettings/chs_t-release.json",
    },
    "kr": {
        "launcher_url": "https://launcher-pkg-kr.yo-star.com/pubplat/game_launcher/install_pkg/launcher/MajSoul_KR/latest.yml",
        "base_config_url": "https://api-launcher-kr.yo-star.com/api/launcher/base/config",
        "social_media_url": "https://api-launcher-kr.yo-star.com/api/launcher/social/media/resource",
        "game_config_url": "https://api-launcher-kr.yo-star.com/api/launcher/game/config",
        "game_config_json_url": "https://api-launcher-kr.yo-star.com/api/launcher/game/config/json",
        "operations_resource_url": "https://api-launcher-kr.yo-star.com/api/launcher/operations/resource",
        "game_tag": "MajSoul_KR",
        "resource_base_urls": [
            "https://appassets.mahjongsoul.com",
            "https://appassetsback.mahjongsoul.com",
        ],
    },
}

# Hide urllib3 warnings caused by SSL verify fallback (verify=False).
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Set VERBOSE_SSL_RETRY=1 to print retry logs when SSL verification fails.
VERBOSE_SSL_RETRY = os.getenv("VERBOSE_SSL_RETRY", "0") == "1"
DEFAULT_MAX_WORKERS = 4


def get_max_workers():
    raw = os.getenv("MAX_WORKERS", str(DEFAULT_MAX_WORKERS))
    try:
        return max(1, int(raw))
    except ValueError:
        return DEFAULT_MAX_WORKERS


MAX_WORKERS = get_max_workers()

THREAD_LOCAL = threading.local()


def get_http_session():
    session = getattr(THREAD_LOCAL, "http_session", None)
    if session is None:
        session = requests.Session()
        THREAD_LOCAL.http_session = session
    return session


def ensure_region_structure(region):
    os.makedirs(os.path.join(region, "game"), exist_ok=True)
    os.makedirs(os.path.join(region, "launcher"), exist_ok=True)
    os.makedirs(os.path.join(region, "resources"), exist_ok=True)


def save_file(directory, filename, content):
    os.makedirs(directory, exist_ok=True)
    output_path = os.path.join(directory, filename)
    if os.path.exists(output_path):
        with open(output_path, "rb") as f:
            if f.read() == content:
                return
    with open(output_path, "wb") as f:
        f.write(content)


def save_json(directory, filename, data):
    content = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    save_file(directory, filename, content)


def save_json_to_path(output_path, data):
    serialized = json.dumps(data, indent=2, ensure_ascii=False)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    if os.path.exists(output_path):
        with open(output_path, "r", encoding="utf-8") as f:
            if f.read() == serialized:
                return
    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(serialized)


def http_get(url, **kwargs):
    session = get_http_session()
    try:
        return session.get(url, **kwargs)
    except requests.exceptions.SSLError:
        if VERBOSE_SSL_RETRY:
            print(f"Warning: SSL verify failed for {url}, retrying without certificate verification.")
        retry_kwargs = dict(kwargs)
        retry_kwargs["verify"] = False
        return session.get(url, **retry_kwargs)


def extract_launcher_version(yml_text):
    match = re.search(r"^version:\s*(.+)\s*$", yml_text, re.MULTILINE)
    if not match:
        return None
    return match.group(1).strip().strip("'").strip('"')


def fetch_and_save_raw(url, output_directory):
    if not url:
        return

    filename = os.path.basename(urlparse(url).path) or "response.txt"
    response = http_get(url, timeout=30)
    response.raise_for_status()
    save_file(output_directory, filename, response.content)
    print(f"Saved {filename} to {output_directory}")


def fetch_and_save_launcher_latest(url, output_directory):
    if not url:
        return

    filename = os.path.basename(urlparse(url).path) or "latest.yml"
    response = http_get(url, timeout=30)
    response.raise_for_status()

    yml_text = response.content.decode("utf-8", errors="replace")
    version = extract_launcher_version(yml_text)
    version_directory = os.path.join(output_directory, version if version else "unknown")

    save_file(version_directory, filename, response.content)
    print(f"Saved {filename} to {version_directory}")
    return version, version_directory


def fetch_and_save_launcher_base_config(url, launcher_version, version_directory, game_tag):
    fetch_and_save_launcher_api_resource(
        url=url,
        launcher_version=launcher_version,
        version_directory=version_directory,
        game_tag=game_tag,
        filename="base_config.json",
        label="base_config",
    )


def build_authorization_header(game_tag, launcher_version):
    head = {
        "game_tag": game_tag,
        "time": int(time.time()),
        "version": launcher_version,
    }
    sign_secret = "DE7108E9B2842FD460F4777702727869"
    sign_str = f"{json.dumps(head, separators=(',', ':'))}{sign_secret}"
    sign = hashlib.md5(sign_str.encode("utf-8")).hexdigest()
    auth_payload = {"head": head, "sign": sign}
    return {"Authorization": json.dumps(auth_payload, separators=(",", ":"))}


def fetch_launcher_api_json(url, launcher_version, game_tag, label):
    if not url or not launcher_version or not game_tag:
        return None

    headers = build_authorization_header(game_tag, launcher_version)
    response = http_get(url, headers=headers, timeout=30)
    response.raise_for_status()

    data = response.json()
    if data.get("code") != 200:
        print(f"Failed {label} request: {data.get('msg', 'unknown error')}")
        return None
    return data


def fetch_and_save_launcher_api_resource(
    url,
    launcher_version,
    version_directory,
    game_tag,
    filename,
    label,
):
    data = fetch_launcher_api_json(url, launcher_version, game_tag, label)
    if data is None:
        return None

    save_json(version_directory, filename, data)
    print(f"Saved {filename} to {version_directory}")
    return data


def fetch_and_save_launcher_social_media(url, launcher_version, version_directory, game_tag):
    fetch_and_save_launcher_api_resource(
        url=url,
        launcher_version=launcher_version,
        version_directory=version_directory,
        game_tag=game_tag,
        filename="social_media_resource.json",
        label="social media",
    )


def fetch_and_save_launcher_game_config(url, launcher_version, version_directory, game_tag):
    return fetch_and_save_launcher_api_resource(
        url=url,
        launcher_version=launcher_version,
        version_directory=version_directory,
        game_tag=game_tag,
        filename="game_config.json",
        label="game config",
    )


def fetch_and_save_launcher_operations_resource(url, launcher_version, version_directory, game_tag):
    fetch_and_save_launcher_api_resource(
        url=url,
        launcher_version=launcher_version,
        version_directory=version_directory,
        game_tag=game_tag,
        filename="operations_resource.json",
        label="operations resource",
    )


def fetch_and_save_launcher_game_config_json(
    url,
    launcher_version,
    version_directory,
    game_tag,
    game_latest_version,
    game_latest_file_path,
):
    if (
        not url
        or not launcher_version
        or not game_tag
        or not game_latest_version
        or not game_latest_file_path
    ):
        return None

    headers = build_authorization_header(game_tag, launcher_version)
    params = {
        "version": game_latest_version,
        "file_path": game_latest_file_path,
    }
    response = http_get(url, headers=headers, params=params, timeout=30)
    response.raise_for_status()

    data = response.json()
    if data.get("code") != 200:
        print(f"Failed game config json request: {data.get('msg', 'unknown error')}")
        return None

    target_url = ((data.get("data") or {}).get("url") or "").strip()
    filename = os.path.basename(urlparse(target_url).path) if target_url else ""
    if not filename:
        filename = "game_config_json.json"

    save_json(version_directory, filename, data)
    print(f"Saved {filename} to {version_directory}")
    return target_url


def fetch_and_save_game_online_config(url, game_version, game_directory):
    if not url:
        return None

    filename = os.path.basename(urlparse(url).path) or "zip_online_config.json"
    target_directory = os.path.join(game_directory, game_version) if game_version else game_directory

    response = http_get(url, timeout=30)
    response.raise_for_status()
    try:
        parsed = response.json()
        save_json(target_directory, filename, parsed)
        result = parsed
    except ValueError:
        # Keep raw save behavior as a fallback if response is not JSON.
        save_file(target_directory, filename, response.content)
        result = None
    print(f"Saved {filename} to {target_directory}")
    return result


def extract_client_bundle_settings_filename(game_online_config):
    if not isinstance(game_online_config, dict):
        return None

    files = game_online_config.get("file") or []
    pattern = re.compile(r"^/WinPC64-[a-z]+-release-[^/]+\.json$")
    for item in files:
        path = (item or {}).get("path", "")
        if pattern.match(path):
            return os.path.basename(path)
    return None


def dedupe_preserve_order(items):
    seen = set()
    result = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def load_urls_from_json_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    urls = []
    warehouses = data.get("warehouses") or []
    if warehouses:
        urls.extend([x.get("url") for x in (warehouses[0].get("urls") or []) if x.get("url")])
    urls.extend([x.get("url") for x in (data.get("urls") or []) if x.get("url")])
    return urls


def collect_resource_base_urls_for_region(region):
    candidates = []

    pattern_client = os.path.join(region, "resources", "*", "client_bundle_settings.json")
    pattern_warehouse = os.path.join(region, "resources", "*", "warehouse_settings.json")

    # Prefer latest known URLs from existing local data first.
    client_files = sorted(glob(pattern_client), key=lambda p: os.path.getmtime(p), reverse=True)
    warehouse_files = sorted(glob(pattern_warehouse), key=lambda p: os.path.getmtime(p), reverse=True)

    for path in client_files:
        candidates.extend(load_urls_from_json_file(path))
    for path in warehouse_files:
        candidates.extend(load_urls_from_json_file(path))

    fallback_urls = (REGION_CONFIG.get(region) or {}).get("resource_base_urls") or []
    candidates.extend(fallback_urls)

    return dedupe_preserve_order(candidates)


def fetch_and_save_warehouse_settings(client_bundle_settings, target_directory):
    warehouses = (client_bundle_settings or {}).get("warehouses") or []
    if not warehouses:
        return None

    warehouse = warehouses[0]
    warehouse_path = warehouse.get("warehouseSettingPath")
    warehouse_bases = [x.get("url") for x in (warehouse.get("urls") or []) if x.get("url")]
    if not warehouse_path or not warehouse_bases:
        return None

    warehouse_url, warehouse_settings = fetch_json_with_base_candidates(
        warehouse_bases, warehouse_path
    )
    save_json(target_directory, "warehouse_settings.json", warehouse_settings)
    print(f"Saved warehouse_settings.json to {target_directory} (source: {warehouse_url})")
    return warehouse_settings


def fetch_client_bundle_settings_for_region(region, game_online_config):
    filename = extract_client_bundle_settings_filename(game_online_config)
    if not filename:
        print(f"Could not find WinPC64 client bundle settings filename for region={region}")
        return None

    settings_path = f"/v3/{region}/clientbundlesettings/{filename}"
    base_urls = collect_resource_base_urls_for_region(region)
    if not base_urls:
        print(
            f"No base URLs available for region={region}. "
            "Need existing resources data to bootstrap client bundle settings."
        )
        return None

    settings_url, client_bundle_settings = fetch_json_with_base_candidates(base_urls, settings_path)
    return settings_url, client_bundle_settings


def fetch_and_save_assetbundle_config(
    warehouse_settings, target_directory, platform_dirs=("StandaloneWindows64", "StandaloneWindows")
):
    if not warehouse_settings:
        return

    bundle_path = warehouse_settings.get("bundlePath")
    ab_bases = [x.get("url") for x in (warehouse_settings.get("urls") or []) if x.get("url")]
    if not bundle_path or not ab_bases:
        return

    ab_config_url = None
    ab_config_content = None
    last_error = None
    for platform_dir in platform_dirs:
        ab_config_path = f"{bundle_path.rstrip('/')}/{platform_dir}/AssetBundleConfig.json"
        try:
            ab_config_url, ab_config_content = fetch_content_with_base_candidates(
                ab_bases, ab_config_path
            )
            break
        except Exception as err:
            last_error = err

    if not ab_config_content:
        if last_error:
            raise last_error
        return

    # Most regions return encrypted AssetBundleConfig payloads; fall back to plain JSON if needed.
    try:
        decoded_bytes = decrypt_cn_assetbundle_config(ab_config_content)
    except Exception:
        decoded_bytes = ab_config_content

    pretty_config_obj = format_json_bytes(decoded_bytes)
    output_path = os.path.join(target_directory, "AssetBundleConfig.json")
    save_json_to_path(output_path, pretty_config_obj)
    print(f"Saved AssetBundleConfig.json to {target_directory} (source: {ab_config_url})")


def save_region_resources_from_client_bundle_settings(
    client_bundle_settings, game_version, resources_output_directory, source_url=None
):
    target_directory = (
        os.path.join(resources_output_directory, game_version)
        if game_version
        else resources_output_directory
    )
    save_json(target_directory, "client_bundle_settings.json", client_bundle_settings)
    source_suffix = f" (source: {source_url})" if source_url else ""
    print(f"Saved client_bundle_settings.json to {target_directory}{source_suffix}")

    warehouse_settings = fetch_and_save_warehouse_settings(client_bundle_settings, target_directory)
    if not warehouse_settings:
        return
    fetch_and_save_assetbundle_config(warehouse_settings, target_directory)


def fetch_and_save_cn_launcher_config(url, output_directory):
    if not url:
        return None

    response = http_get(url, timeout=30)
    response.raise_for_status()

    data = response.json()
    version = str(data.get("version") or "unknown")
    filename = os.path.basename(urlparse(url).path) or "launcher_config_2.json"
    target_directory = os.path.join(output_directory, version)
    save_json(target_directory, filename, data)
    print(f"Saved {filename} to {target_directory}")
    return data


def fetch_and_save_cn_bundle_json(launcher_config, game_output_directory):
    if not launcher_config:
        return

    bundle_path = (launcher_config.get("bundle_path") or "").strip()
    if not bundle_path:
        return

    bundle_json_url = f"{bundle_path.rstrip('/')}/StandaloneWindows/bundle.json"
    response = http_get(bundle_json_url, timeout=30)
    response.raise_for_status()

    game_version = str(launcher_config.get("minimum_version") or "unknown")
    target_directory = os.path.join(game_output_directory, game_version)
    parsed = json.loads(response.text)
    if isinstance(parsed, str):
        parsed = json.loads(parsed)
    output_path = os.path.join(target_directory, "bundle.json")
    save_json_to_path(output_path, parsed)
    print(f"Saved bundle.json to {target_directory}")


def fetch_and_save_cn_gameclient_bundle_index(launcher_config, game_output_directory):
    if not launcher_config:
        return

    game_client_source = (launcher_config.get("game_client_source") or "").strip()
    if not game_client_source:
        return

    gameclient_bundle_url = (
        f"{game_client_source.rstrip('/')}"
        "/GameClient/Jantama_MahjongSoul_Data/StreamingAssets/StandaloneWindows/bundle.json.majset"
    )
    response = http_get(gameclient_bundle_url, timeout=30)
    response.raise_for_status()

    game_version = str(launcher_config.get("minimum_version") or "unknown")
    target_directory = os.path.join(game_output_directory, game_version)
    save_file(target_directory, "bundle.json.majset", response.content)
    print(f"Saved bundle.json.majset to {target_directory}")


def build_url_from_base(base_url, path):
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def fetch_with_base_candidates(base_urls, path, *, parse_json=False):
    last_error = None
    for base_url in base_urls:
        full_url = build_url_from_base(base_url, path)
        try:
            response = http_get(full_url, timeout=30)
            response.raise_for_status()
            content = response.json() if parse_json else response.content
            return full_url, content
        except Exception as err:
            last_error = err
    if last_error:
        raise last_error
    raise RuntimeError("No base URLs available.")


def fetch_content_with_base_candidates(base_urls, path):
    return fetch_with_base_candidates(base_urls, path, parse_json=False)


def fetch_json_with_base_candidates(base_urls, path):
    return fetch_with_base_candidates(base_urls, path, parse_json=True)


def decrypt_cn_assetbundle_config(raw_content):
    try:
        from Crypto.Cipher import AES
    except ImportError as err:
        raise RuntimeError("pycryptodome is required for CN AssetBundleConfig decryption.") from err

    cipher_text = raw_content.decode("utf-8", errors="strict").strip()
    encrypted_bytes = base64.b64decode(cipher_text)
    decrypted = AES.new(CN_AES_KEY, AES.MODE_CBC, CN_AES_IV).decrypt(encrypted_bytes)

    pad_len = decrypted[-1]
    if 1 <= pad_len <= 16 and decrypted.endswith(bytes([pad_len]) * pad_len):
        decrypted = decrypted[:-pad_len]

    return decrypted


def format_json_bytes(raw_json_bytes):
    parsed = json.loads(raw_json_bytes.decode("utf-8"))
    return parsed


def fetch_and_save_cn_client_bundle_chain(
    client_bundle_settings_url, launcher_config, resources_output_directory
):
    if not client_bundle_settings_url or not launcher_config:
        return

    game_version = str(launcher_config.get("minimum_version") or "unknown")
    target_directory = os.path.join(resources_output_directory, game_version)

    response = http_get(client_bundle_settings_url, timeout=30)
    response.raise_for_status()
    client_bundle_settings = response.json()
    save_json(target_directory, "client_bundle_settings.json", client_bundle_settings)
    print(f"Saved client_bundle_settings.json to {target_directory}")

    warehouse_settings = fetch_and_save_warehouse_settings(client_bundle_settings, target_directory)
    if not warehouse_settings:
        return
    fetch_and_save_assetbundle_config(
        warehouse_settings, target_directory, platform_dirs=("StandaloneWindows", "StandaloneWindows64")
    )


def process_region(region, config):
    ensure_region_structure(region)

    if region == "cn":
        launcher_config = fetch_and_save_cn_launcher_config(
            config.get("launcher_config_url"),
            os.path.join(region, "launcher"),
        )
        fetch_and_save_cn_client_bundle_chain(
            config.get("client_bundle_settings_url"),
            launcher_config,
            os.path.join(region, "resources"),
        )
        fetch_and_save_cn_bundle_json(launcher_config, os.path.join(region, "game"))
        fetch_and_save_cn_gameclient_bundle_index(launcher_config, os.path.join(region, "game"))
        return

    launcher_url = config.get("launcher_url")
    if launcher_url:
        launcher_version, version_directory = fetch_and_save_launcher_latest(
            launcher_url, os.path.join(region, "launcher")
        )
        fetch_and_save_launcher_base_config(
            config.get("base_config_url"),
            launcher_version,
            version_directory,
            config.get("game_tag"),
        )
        fetch_and_save_launcher_social_media(
            config.get("social_media_url"),
            launcher_version,
            version_directory,
            config.get("game_tag"),
        )
        game_config_data = fetch_and_save_launcher_game_config(
            config.get("game_config_url"),
            launcher_version,
            version_directory,
            config.get("game_tag"),
        )
        game_config_payload = (game_config_data or {}).get("data", {})
        game_online_config_url = fetch_and_save_launcher_game_config_json(
            config.get("game_config_json_url"),
            launcher_version,
            version_directory,
            config.get("game_tag"),
            game_config_payload.get("game_latest_version"),
            game_config_payload.get("game_latest_file_path"),
        )
        game_online_config = fetch_and_save_game_online_config(
            game_online_config_url,
            game_config_payload.get("game_latest_version"),
            os.path.join(region, "game"),
        )
        client_bundle_settings_fetch = fetch_client_bundle_settings_for_region(region, game_online_config)
        if client_bundle_settings_fetch:
            settings_url, client_bundle_settings = client_bundle_settings_fetch
            save_region_resources_from_client_bundle_settings(
                client_bundle_settings=client_bundle_settings,
                game_version=game_config_payload.get("game_latest_version"),
                resources_output_directory=os.path.join(region, "resources"),
                source_url=settings_url,
            )
        fetch_and_save_launcher_operations_resource(
            config.get("operations_resource_url"),
            launcher_version,
            version_directory,
            config.get("game_tag"),
        )


def process_urls():
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(process_region, region, config): region
            for region, config in REGION_CONFIG.items()
        }
        for future in as_completed(future_map):
            region = future_map[future]
            future.result()
            print(f"Completed region: {region}")


if __name__ == "__main__":
    process_urls()
