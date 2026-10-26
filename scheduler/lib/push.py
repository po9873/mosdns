#!/usr/bin/env python3
# 消息推送（纯标准库）：兼容企业微信 / 钉钉 / 飞书 机器人 Webhook
# 用法: python3 push.py <webhook_url> <title> <body...>
import json
import sys
import urllib.request


def shape(url, text):
    u = url.lower()
    if "feishu" in u or "larksuite" in u:
        return {"msg_type": "text", "content": {"text": text}}
    # 企业微信 / 钉钉 都是 msgtype=text
    return {"msgtype": "text", "text": {"content": text}}


def main():
    if len(sys.argv) < 4:
        return 1
    url = sys.argv[1]
    title = sys.argv[2]
    body = " ".join(sys.argv[3:])
    text = ("【MosDNS 优选】" + title + "\n" + body).strip()
    payload = json.dumps(shape(url, text), ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            r.read(512)
        return 0
    except Exception as e:
        sys.stderr.write("push failed: %s\n" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
