import re
import sys
from urllib.parse import urlparse

# 推測候補
USERNAME_KEYS = ['username', 'user', 'email', 'login']
PASSWORD_KEYS = ['password', 'pass', 'pwd']

def extract_hydra_command(burp_request: str) -> str:
    burp_request = burp_request.replace("\r\n", "\n")

    # メソッドとパス
    method_path_match = re.search(r'^(POST|GET) (\S+) HTTP', burp_request, re.MULTILINE)
    method = method_path_match.group(1).lower() if method_path_match else 'post'
    path = method_path_match.group(2) if method_path_match else '/'

    # Host
    host_match = re.search(r'^Host:\s*(.+)$', burp_request, re.MULTILINE)
    host = host_match.group(1).strip() if host_match else 'example.com'

    # httpsかどうか
    is_https = '443' in host or 'https' in burp_request.lower()
    hydra_proto = f"https-{method}-form" if is_https else f"http-{method}-form"

    # ボディ取得
    body = ""
    if method == 'post':
        parts = burp_request.split("\n\n", 1)
        if len(parts) == 2:
            body = parts[1].strip()

    # パラメータ解析
    param_pairs = body.split("&")
    parsed_params = []
    user_found = pass_found = False

    for pair in param_pairs:
        key, sep, value = pair.partition("=")
        if not sep:
            continue
        key_lc = key.lower()

        if not user_found and any(k in key_lc for k in USERNAME_KEYS):
            parsed_params.append(f"{key}=^USER^")
            user_found = True
        elif not pass_found and any(k in key_lc for k in PASSWORD_KEYS):
            parsed_params.append(f"{key}=^PASS^")
            pass_found = True
        else:
            parsed_params.append(pair)

    data = "&".join(parsed_params) if parsed_params else "username=^USER^&password=^PASS^"
    fail_string = "Invalid"  # <-- 必要に応じて手動で置き換えてください

    # hydraコマンド構築
    command = (
        f"hydra -L users.txt -P passwords.txt {host} {hydra_proto} "
        f'"{path}:{data}:{fail_string}" -V'
    )

    return command

def main():
    if len(sys.argv) != 2:
        print("Usage: python burp2hydra.py <burp_request.txt>")
        sys.exit(1)

    filepath = sys.argv[1]
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            burp_request = f.read()
        command = extract_hydra_command(burp_request)
        print("\n[+] Generated hydra command:\n")
        print(command)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
