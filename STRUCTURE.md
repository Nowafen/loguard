# Loguard Source Structure (v2.1.0 — Session Monitor)

نقشه‌ی کامل پروژه بعد از اضافه شدن Session Monitor v2.

## 📋 فایل‌های اصلی (Source Files)

### لایه پایه (v1، بدون تغییر مفهومی)

| # | فایل | نقش |
|---|------|-----|
| 1 | `src/paths.hpp` | تمام مسیرهای فایل‌سیستمی + مسیرهای جدید sessions/geo cache |
| 2 | `src/util.hpp/cpp` | ابزارهای کمکی + **جدید:** `gen_session_id()`, `split()`, `trim_str()`, `format_duration()` |
| 3 | `src/config.hpp/cpp` | تنظیمات TOML + **جدید:** `process_poll_seconds`, `enable_geoip`, `high_risk_threshold` |
| 4 | `src/telegram.hpp/cpp` | ارسال HTML به Telegram (بدون تغییر) |
| 5 | `src/queue.hpp/cpp` | صف retry برای پیام‌های ساده (heartbeat/tamper) — بدون تغییر |
| 6 | `src/pam.hpp/cpp` | مدیریت خطوط PAM — بدون تغییر |
| 7 | `src/integrity.hpp/cpp` | SHA-256 checksum باینری‌ها — بدون تغییر |

### لایه Session Monitor (v2 — جدید)

| # | فایل | نقش |
|---|------|-----|
| 8  | `src/session.hpp/cpp` | Session Object: طبقه‌بندی، Timeline، ساخت پیام‌های HTML (Alert اولیه + Summary پایانی) |
| 9  | `src/session_queue.hpp/cpp` | خواندن رویدادهای `session_start`/`session_end` که PAM hook می‌نویسد |
| 10 | `src/geoip.hpp/cpp` | GeoIP واقعی (`ip-api.com` رایگان، بدون کلید) + کش دیسک + flag emoji |
| 11 | `src/risk_engine.hpp/cpp` | امتیازدهی ریسک طبق جدول Specification + ردیابی "new country" |
| 12 | `src/pattern_matcher.hpp/cpp` | تشخیص Suspicious Process / Reverse Shell / Privilege Escalation |
| 13 | `src/process_monitor.hpp/cpp` | پایش فرآیندهای session با `ps` (بدون eBPF/auditd) |

### هسته اجرایی

| # | فایل | نقش |
|---|------|-----|
| 14 | `src/pam_hook.c` | **بازنویسی کامل v3:** اجرا روی `open_session` و `close_session`، تولید Session ID، stack per-TTY برای nested sessions (sudo داخل ssh) |
| 15 | `src/main.cpp` | CLI + Daemon loop؛ شامل پایپ‌لاین کامل Session Monitor (`handle_session_events`, `poll_active_sessions`) + دستور جدید `loguard sessions` |

---

## 📦 Packaging & Installation

| # | فایل | تغییر |
|---|------|-------|
| 16 | `install.sh` | دستور build شامل ۶ فایل cpp جدید + نصب `procps` (برای `ps`) + ساخت دایرکتوری `sessions/` |
| 17 | `packaging/loguard.service` | بدون تغییر |
| 18 | `packaging/loguard-check.service` | بدون تغییر |
| 19 | `packaging/loguard-check.timer` | بدون تغییر |
| 20 | `packaging/openrc/loguard.init` | بدون تغییر |

---

## 📚 Documentation

| # | فایل |
|---|------|
| 21 | `README.md` — به‌روز شده با معماری v2 و نمونه پیام‌های واقعی |
| 22 | `STRUCTURE.md` — همین فایل |

---

## 🔨 Build Command (دقیقاً همانی که install.sh اجرا می‌کند)

```bash
g++ -std=c++17 -O2 -o loguard \
    src/main.cpp src/util.cpp src/config.cpp \
    src/telegram.cpp src/queue.cpp src/pam.cpp src/integrity.cpp \
    src/session.cpp src/session_queue.cpp \
    src/geoip.cpp src/risk_engine.cpp \
    src/pattern_matcher.cpp src/process_monitor.cpp

gcc -O2 -o loguard-notify src/pam_hook.c
```

✅ این build با موفقیت تست شد (بدون خطا، فقط warning بی‌ضرر).

### Dependency Graph (لایه v2)

```
main.cpp
  ├── session.hpp/cpp
  │     └── geoip.hpp (برای flag emoji در پیام‌ها)
  ├── session_queue.hpp/cpp
  │     └── paths.hpp, util.hpp
  ├── geoip.hpp/cpp
  │     └── util.hpp (run_capture → curl), paths.hpp (cache file)
  ├── risk_engine.hpp/cpp
  │     └── session.hpp, paths.hpp, util.hpp
  ├── pattern_matcher.hpp/cpp
  │     └── (بدون وابستگی خارجی)
  └── process_monitor.hpp/cpp
        └── util.hpp (run_capture → ps)

pam_hook.c (کاملاً مستقل، بدون وابستگی به فایل‌های C++)
```

---

## 🚀 جریان اجرا (Runtime Flow)

### هنگام لاگین (مثلاً SSH)
1. PAM اجرا می‌کند: `loguard-notify` با `PAM_TYPE=open_session`
2. `pam_hook.c`:
   - چک می‌کند سرویس در لیست نویز نیست (cron/systemd) → ادامه
   - Session ID تولید می‌کند و در stack مربوط به TTY فشار می‌دهد (push)
   - اطلاعات (UID, GID, shell, home, IP, ...) را جمع می‌کند
   - یک خط JSON `session_start` در `events.jsonl` می‌نویسد
3. Daemon (`handle_session_events`):
   - رویداد را می‌خواند → `session::classify()` نوع را تعیین می‌کند
   - اگر remote باشد: `geoip::lookup()` (کش‌شده) کشور/شهر/ISP را می‌گیرد
   - `risk::add()` امتیاز پایه (SSH Login +10, New Country +20, ...) را اضافه می‌کند
   - اگر `alertable=true`: پیام HTML اولیه به Telegram ارسال می‌شود

### در طول Session (هر چند ثانیه)
1. `poll_active_sessions()`:
   - یک‌بار `ps -eo pid,ppid,tty,user,args` اجرا می‌شود (برای همه sessionها مشترک)
   - برای هر session فعال: فرآیندهای جدید (همان TTY + همان user) پیدا می‌شوند
   - هر فرآیند جدید وارد `pattern_matcher::classify_command()` می‌شود
   - اگر Suspicious/ReverseShell/PrivEsc باشد: امتیاز اضافه + Alert جداگانه ارسال می‌شود
   - اگر امتیاز کل از threshold (پیش‌فرض ۱۰۰) رد شود: یک‌بار Alert "HIGH RISK" ارسال می‌شود

### هنگام Logout
1. PAM اجرا می‌کند: `loguard-notify` با `PAM_TYPE=close_session`
2. `pam_hook.c`: از stack همان TTY، آخرین Session ID را pop می‌کند (LIFO — درست منطبق با nested sessionها مثل sudo)
3. یک خط JSON `session_end` می‌نویسد
4. Daemon: Session را از حافظه فعال حذف می‌کند، `build_summary_html()` می‌سازد و ارسال می‌کند

---

## ⚠️ محدودیت‌های شناخته‌شده (عمدی، طبق تصمیم شما)

این دو مورد **پیاده‌سازی نشده‌اند** و در `risk_engine.hpp` فقط به‌عنوان ثابت‌های رزرو شده نگه داشته شده‌اند:

- ❌ **File Monitoring** (`/etc/passwd`, `authorized_keys`, `sshd_config`, ...)
- ❌ **Network Connection Monitoring** (شمارش اتصالات فعال شبکه)

همچنین:
- تشخیص "Login Method" (Public Key vs Password) به `SSH_AUTH_INFO_0` وابسته است که همه‌ی نسخه‌های sshd آن را ست نمی‌کنند — این فیلد اغلب "Unknown" خواهد بود مگر sshd شما آن را expose کند.
- پایش فرآیند بر پایه polling با `ps` است (نه eBPF/auditd)، بنابراین فرآیندهایی که سریع‌تر از `process_poll_seconds` اجرا و خاتمه یابند ممکن است دیده نشوند.

---

**Repository:** https://github.com/Nowafen/Loguard
