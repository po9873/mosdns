#!/usr/bin/env python3
# ============================================================
# 上游 DoH 配置读写（UI 与定时扫描共用一份实现）
#
# 之前替换 upstreams 段的正则只在 ui/server.py 里有一份；
# 定时扫描也要改配置，两处各写一份必然会漂，所以抽到这里。
#
# 用法（库）：
#   import doh_config as dc
#   dc.active()                     -> {"local": [...], "remote": [...]}
#   dc.apply_entries(local, remote) -> True/False（是否真的改了）
#   dc.reload_engine()              -> 让 mosdns 重载
# ============================================================
import os
import re
import subprocess

DATA_DIR = os.environ.get("PREF_DATA_DIR", "/data")
CFG = os.path.join(DATA_DIR, "config.yaml")
SCHEDULER = "/app/scheduler/scheduler.sh"

LOCAL_CUSTOM = os.path.join(DATA_DIR, "doh_local_custom.txt")
REMOTE_CUSTOM = os.path.join(DATA_DIR, "doh_remote_custom.txt")
SCAN_FILE = os.path.join(DATA_DIR, "doh_scan.json")

TAG_OF = {"local": "forward_local", "remote": "forward_remote"}


def _unq(s):
    s = str(s or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1]
    return s


def _strip_port(dial):
    """dial_addr 是 ip:port；IPv6 是 [::1]:443。取回纯 IP。"""
    d = _unq(dial)
    if not d:
        return ""
    if d.startswith("["):
        return d[1:d.find("]")] if "]" in d else d.strip("[]")
    if d.count(":") == 1:
        return d.split(":", 1)[0]
    return d  # 裸 IPv6


def yaml_block(entries):
    """entries: ["https://host/path"] 或 ["https://host/path 1.2.3.4"]，
    生成与 entrypoint 探测输出同格式的 YAML 片段（8 空格缩进）。"""
    out = []
    for e in entries:
        parts = str(e).split()
        if not parts:
            continue
        url = parts[0]
        boot = parts[1] if len(parts) > 1 else ""
        out.append('        - addr: "%s"' % url)
        if boot:
            out.append('          dial_addr: "%s:443"' % boot)
        out.append("          insecure_skip_verify: true")
    return ("\n".join(out) + "\n") if out else ""


def replace_block(text, tag, block):
    """把某个 forward 插件（forward_local/forward_remote）的 upstreams 段整段换掉。

    先统一换行：容器里的文件是 CRLF，正则里写死 \n 会整段匹配不上，
    表现出来就是「点了保存、提示成功、配置没变」。
    """
    text = text.replace("\r\n", "\n")
    nl = "\n"
    # 前半段要用 DOTALL 跨行找 upstreams，但条目行必须用 [^\n]*，
    # 否则 . 会把后面整份配置一起吃掉（remote 段会消失）。
    pat = re.compile("(?s)(- tag: " + re.escape(tag) + r"\b.*?upstreams:" + nl + ")((?:        [^\n]*" + nl + ")*)")
    if not pat.search(text):
        return text
    return pat.sub(lambda m: m.group(1) + block, text, count=1)


def read_cfg():
    try:
        with open(CFG, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def write_cfg(text):
    """整份配置写回（先写临时文件再换，避免写一半被 mosdns 读到）。"""
    tmp = CFG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, CFG)


def active(text=None):
    """读出此刻真正在用的上游，条目形式与候选文件一致：`url [ip]`。"""
    if text is None:
        text = read_cfg()
    out = {"local": [], "remote": []}
    cur_key = None
    cur = None
    for ln in text.replace("\r\n", "\n").splitlines():
        m = re.match(r"\s*-\s+tag:\s*(\S+)", ln)
        if m:
            cur_key = {v: k for k, v in TAG_OF.items()}.get(m.group(1))
            cur = None
            continue
        if not cur_key:
            continue
        m = re.search(r"-\s+addr:\s*\"?([^\"\s]+)\"?", ln)
        if m:
            cur = {"addr": m.group(1), "dial": ""}
            out[cur_key].append(cur)
            continue
        m = re.search(r"dial_addr:\s*\"?([^\"\s]+)\"?", ln)
        if m and cur:
            cur["dial"] = m.group(1)
    res = {}
    for k in ("local", "remote"):
        res[k] = []
        for u in out[k]:
            ip = _strip_port(u["dial"])
            res[k].append((u["addr"] + (" " + ip if ip else "")).strip())
    return res


def apply_entries(local, remote):
    """把上游写进 config.yaml。空列表 = 这一段不动。返回是否真的改了。"""
    text = read_cfg()
    if not text:
        return False
    new = text
    if local:
        new = replace_block(new, TAG_OF["local"], yaml_block(local))
    if remote:
        new = replace_block(new, TAG_OF["remote"], yaml_block(remote))
    # 上游换了，测速入口要跟着重建（端口集合按当前条数走）
    new = render_diag(new)
    if new == text:
        return False
    tmp = CFG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(new)
    os.replace(tmp, CFG)
    return True


def write_custom(local, remote):
    """落盘自定义清单，容器重启后 entrypoint 直接沿用（存在即视为手动模式）。"""
    for path, entries in ((LOCAL_CUSTOM, local or []), (REMOTE_CUSTOM, remote or [])):
        if entries:
            with open(path, "w", encoding="utf-8") as f:
                f.write(yaml_block(entries))
        else:
            try:
                os.remove(path)
            except Exception:
                pass


def is_manual():
    return os.path.exists(LOCAL_CUSTOM) or os.path.exists(REMOTE_CUSTOM)


def reload_engine(timeout=25):
    try:
        subprocess.run([SCHEDULER, "reload"], capture_output=True, timeout=timeout)
        return True
    except Exception:
        return False


# ============================================================
# 监测页测速入口
#
# 为什么不用外部脚本直连 DoH：用户要看的是「mosdns 此刻转发有多快」。
# 外部探测自己有 TLS、自己建连接、自己定并发，测出来的数和实际解析对不上
# （mosdns 有连接复用、并发取最快、还可能命中缓存）。
# 所以给每条在用上游开一个「只指向它」的 mosdns 入口，
# 问它一次，得到的就是 mosdns 内部真实的一次转发耗时。
# ============================================================
DIAG_MARK = "__DIAG_PLUGINS__"
DIAG_BASE = {"local": 16001, "remote": 16061}
DIAG_MAX = 60
DIAG_RE = re.compile(r"^\s*#\s*diag\s+(local|remote)\s+(\d+)\s+(.+?)\s*->\s*(\d+)\s*$")


# 老版本内置清单里写错的条目。
#
# 百度 DNS(180.76.76.76)、OneDNS(117.50.10.10) 只有 UDP/DoT，443 上根本没有
# DoH 服务；dns.pub 的 DoH 在 120.53.53.53 / 1.12.12.21，119.29.29.29 是它
# 普通 DNS 的地址。把这些当成 DoH 端点写进池子，测出来必然是「几秒没响应」——
# 看着像「连百度都打不开」，其实是地址填错了。
#
# 为什么要在这里再修一遍：/data 下的清单只在文件不存在时从镜像拷贝，
# 镜像升级不会覆盖它。老机器上那几行会一直留着，每次扫描、每次测速都白跑一趟，
# 界面上还挂着「不通」。所以读取时统一纠正。
POOL_FIX = {
    "https://dns.pub/dns-query 119.29.29.29": "https://dns.pub/dns-query 120.53.53.53",
}
POOL_DROP = (
    "https://180.76.76.76/dns-query 180.76.76.76",
    "https://117.50.10.10/dns-query 117.50.10.10",
)


def normalize_pool(lines):
    """把清单里的坏条目改掉/丢掉，同时按整行去重（保留顺序）。"""
    out, seen = [], set()
    for ln in lines:
        s = str(ln).split("#", 1)[0].strip()
        if not s:
            continue
        s = POOL_FIX.get(s, s)
        if s in POOL_DROP or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def normalize_file(path):
    """就地修 /data 下的候选清单：注释原样留着，条目按 normalize_pool 处理。

    返回 (改了几行, 现在几条)。改不动也不报错——解析能不能用不靠这个文件。
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            raw = f.read().splitlines()
    except Exception:
        return 0, 0
    keep, items = [], []
    for ln in raw:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            keep.append(s)
            continue
        items.append(s)
    fixed = normalize_pool(items)
    dropped = len(items) - len(fixed)
    # 只把注释保留在开头：条目可能被改写、顺序不变，混排没意义
    body = keep + fixed
    if body == [x.strip() for x in raw if x.strip()]:
        return 0, len(fixed)
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(body) + "\n")
        os.replace(tmp, path)
    except Exception:
        return 0, len(fixed)
    return dropped, len(fixed)


def _pool_lines(side):
    """读这一侧的候选池文件（/data 下的那份，含用户加的和内置种子补进来的）。"""
    path = os.path.join(DATA_DIR, "doh_%s_candidates.txt" % side)
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.split("#", 1)[0].strip()
                if ln:
                    out.append(ln)
    except Exception:
        pass
    return normalize_pool(out)


def full_set(text, side):
    """要测的全集 = 候选池全部 + 正在用但不在池里的（手动加的）。

    用户要看的是「有哪些上游、各自多快」，不是只看「现在用了哪几条」。
    所以测速入口按整池开，在用的排最前面。
    """
    act = active(text)[side]
    out, seen = [], set()
    for line in list(act) + _pool_lines(side):
        line = POOL_FIX.get(str(line).strip(), str(line).strip())
        if not line or line in POOL_DROP or line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def render_diag(text, local=None, remote=None):
    """把模板里的 __DIAG_PLUGINS__ 占位换成逐条上游的测速入口。

    默认按「整池」生成（在用的排最前），这样监测页能把所有候选都测一遍，
    而不是只测现在选中的那几条。
    每条上方留一行注释记录 side/序号/上游/端口，server 靠它反查，
    不用去猜 tag 命名规则（改过名也不会错位）。
    """
    text = text.replace("\r\n", "\n")
    if DIAG_MARK not in text:
        return text
    if local is None:
        local = full_set(text, "local")
    if remote is None:
        remote = full_set(text, "remote")

    out = []
    for side, entries, base in (("local", local or [], DIAG_BASE["local"]),
                                ("remote", remote or [], DIAG_BASE["remote"])):
        tag_side = "l" if side == "local" else "r"
        for i, line in enumerate(list(entries)[:DIAG_MAX], 1):
            parts = str(line).split()
            if not parts:
                continue
            url = parts[0]
            boot = parts[1].strip("[]") if len(parts) > 1 else ""
            port = base + i - 1
            out.append("  # diag %s %d %s%s -> %d"
                       % (side, i, url, (" " + boot) if boot else "", port))
            out.append("  - tag: diag_%s%d" % (tag_side, i))
            out.append("    type: forward")
            out.append("    args:")
            out.append("      upstreams:")
            out.append('        - addr: "%s"' % url)
            if boot:
                out.append('          dial_addr: "%s:443"' % boot)
            out.append("          insecure_skip_verify: true")
            out.append("  - tag: diag_srv_%s%d" % (tag_side, i))
            out.append("    type: udp_server")
            out.append("    args:")
            out.append("      entry: diag_%s%d" % (tag_side, i))
            out.append('      listen: "127.0.0.1:%d"' % port)
    block = "\n".join(out)
    return re.sub(r"^[ \t]*#\s*" + re.escape(DIAG_MARK) + r".*$", lambda m: block,
                  text, count=1, flags=re.M)


def diag_ports(text=None):
    """读出测速入口：每条在用的上游对应一个 127.0.0.1 端口。"""
    if text is None:
        text = read_cfg()
    out = []
    for ln in text.replace("\r\n", "\n").splitlines():
        m = DIAG_RE.match(ln)
        if m:
            out.append({"side": m.group(1), "idx": int(m.group(2)),
                        "line": m.group(3).strip(), "port": int(m.group(4))})
    return out


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "pool-fix":
        # 启动时把 /data 清单里的坏条目修掉（老机器的清单不会被镜像覆盖）
        for side in ("local", "remote"):
            p = os.path.join(DATA_DIR, "doh_%s_candidates.txt" % side)
            n, total = normalize_file(p)
            if n:
                print("%s 清单整理掉 %d 条（无效地址或重复），现在 %d 条" % (side, n, total))
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == "diag":
        t = read_cfg()
        n = render_diag(t)
        if n != t:
            tmp = CFG + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(n)
            os.replace(tmp, CFG)
            print("diag 入口已刷新：%d 条" % len(diag_ports(n)))
        else:
            print("diag 入口无变化")
    else:
        print("用法: doh_config.py diag", file=sys.stderr)
        sys.exit(2)
