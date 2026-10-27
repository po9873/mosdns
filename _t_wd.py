import sys, types
sys.path.insert(0, "scheduler/lib")
fp = types.ModuleType("https_probe")
# 模拟新版 5 元组返回
fp.check = lambda ip, dom, port, to: (ip, "ok", 123.0, 456.0, False)
sys.modules["https_probe"] = fp
import watchdog
r = watchdog.probe("1.2.3.4", "example.com")
print("probe ->", r, "len", len(r))
assert len(r) == 4, r
ip, st, ms, sp = r          # 与 run_once 里的解包方式一致
print("解包 OK:", ip, st, ms, sp)
# 老式 3 元组（异常兜底路径）也要能解
fp.check = lambda ip, dom, port, to: (_ for _ in ()).throw(RuntimeError("boom"))
r2 = watchdog.probe("1.2.3.4", "example.com")
print("异常路径 ->", r2)
ip, st, ms, sp = r2
print("异常路径解包 OK:", ip, st, ms)
