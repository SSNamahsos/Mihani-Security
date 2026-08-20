<div dir="rtl" lang="fa">

# MihaniSecurity

[English](README.md) · **فارسی**

ضد بدافزار متن‌باز ویندوز با محافظت بلادرنگ از **اعتبارنامه‌ها و توکن‌های ورود**
(Steam، Discord و کوکی‌ها/نشست‌های مرورگر)، اسکن درخواستی، تشخیص رفتار، قرنطینه،
ثبت در مرکز امنیت ویندوز و رابط گرافیکی مبتنی بر Wails — با پشتیبانی کامل از
فارسی (راست‌به‌چپ) و انگلیسی.

- **موتور**: Go، به‌صورت سرویس ویندوز اجرا می‌شود (`MihaniSecurity`، LocalSystem).
- **رابط گرافیکی**: Wails v2 (WebView2)، پنجره بدون قاب، ۹ تم، فارسی/انگلیسی با راست‌به‌چپ.
- **ارتباط**: named pipe با آدرس `\\.\pipe\MihaniSecurity` (دسترسی SDDL محدود به
  System/Administrators/کاربران تعاملی؛ کلاینت **احراز هویت می‌شود** — فقط
  باینری GUI پذیرفته می‌شود) با پیام‌های JSON جدیدخط‌دار.
- **امضاها**: پایگاه داده متنی همراه نصب‌کننده؛ کاربران می‌توانند از
  تنظیمات ← «درون‌ریزی به‌روزرسانی امضا» آن را گسترش دهند (بدون درخواست اینترنتی).

## امکانات

- **نگهبان توکن** — بر ذخیره‌گاه‌های اعتبار Steam، Discord و مرورگر نظارت دارد؛
  یک فرآیند فقط در صورتی می‌تواند آن‌ها را بخواند که **صاحب امضاشدهٔ همان
  برنامه** باشد (WinVerifyTrust + لیست سفید ناشر — تغییر نام یک بدافزار به
  `discord.exe` دیگر کارساز نیست)؛ در غیر این صورت حافظهٔ فرآیند بررسی شده،
  متخلف خاتمه می‌یابد و فایل آن قرنطینه می‌شود (با توجه به سیاست سطح شدت).
- **محافظت بلادرنگ** — اسکن فایل‌های جدید در پوشه‌های Downloads/Temp/محمافظت‌شده،
  نظارت بر فرآیندها و خط فرمان، نظارت بر ماندگاری رجیستری و تشخیص اتصالات خروجی
  غیرعادی (beaconing). هر مانیتور قابل خاموش/روشن کردن است.
- **تشخیص رفتار** — قوانین ماندگاری (کلیدهای Run/RunOnce، Winlogon shell،
  Debugger های IFEO، AppInit_DLLs، وظایف زمان‌بندی‌شده و پوشه‌های Startup)،
  نظارت بر تزریق DLL/فرآیند، خطوط فرمان مشکوک و اتصال‌های تکرارشونده.
  هر قانون یک راهنمای رفع مشکل در رابط کاربری دارد.
- **اسکن درخواستی** — اسکن سریع (Downloads، Desktop، Temp)، اسکن کامل و اسکن
  پوشه دلخواه؛ نتایج از همان موتور سیاست‌گذاری بلادرنگ عبور می‌کنند.
- **قرنطینه** — ذخیره **رمزنگاری‌شده** (AES-256-GCM به‌ازای هر فایل، تکه‌تکه،
  کلید با DPAPI بسته‌بندی و کنار ذخیره‌گاه نگهداری می‌شود؛ فایل‌های متنی قدیمی
  هنگام بازیابی شناسایی و تبدیل می‌شوند) با بازیابی/حذف و پاک‌سازی خودکار بر
  اساس عمر و حجم. پیش از نمایش، محتوای گزارش‌ها بازبینی و محو می‌شود (توکن‌های
  Discord/Steam، هدرهای Bearer، رمزها و payloadهای PowerShell `-enc`).
- **خودمحافظتی** — هنگام شروع سرویس، دسترسی پوشه داده سخت‌گیری می‌شود
  (SYSTEM/Administrators کامل، کاربران فقط خواندنی، Everyone حذف) و DACL
  سرویس طوری جایگزین می‌شود که کاربران غیرمدیر نتوانند سرویس را متوقف،
  بازپیکربندی یا حذف کنند.
- **مرکز امنیت ویندوز** — ثبت اختیاری به‌عنوان آنتی‌ویروس پیش‌فرض
  (تنظیمات ← «ثبت به‌عنوان آنتی‌ویروس پیش‌فرض»).
- **فایل‌های محافظت‌شده** — فایل‌هایی که هرگز نباید حذف یا قرنطینه شوند، پیش از
  اعمال هر سیاستی کنار گذاشته می‌شوند. فهرست داخلی از `onlinefix64.dll` و
  `onlinefix.dll` (فایل‌های پشتیبانی بازی‌های آفلاین/کرک‌شده) محافظت می‌کند تا
  یک مثبت کاذب هرگز آن‌ها را از بین نبرد. استثناهای کاربر و لیست سفید فرآیند/دامنه
  روی همین لایه کار می‌کنند.
- **تنظیمات** — ۹ تم، فارسی/انگلیسی (راست‌به‌چپ)، سطح هشدار، سیاست اقدام برای
  هر تهدید (فقط ثبت / اطلاع‌رسانی / قرنطینه خودکار / حذف خودکار)، اهداف نگهبان
  توکن، لیست سفید، استثناها، درون‌ریزی/بارگذاری مجدد امضا و ثبت در مرکز امنیت.

## مجوز

MIT — به [LICENSE](LICENSE) مراجعه کنید.

## معماری

```
cmd/mihanisecurity-service   باینری سرویس: -mode install|uninstall|run
main.go                      باینری GUI ویلز (جاسازی frontend/dist)
internal/service             پوسته سرویس + سرور IPC + مانیتورها
internal/app                 اتصالات ویلز (تنظیمات، اسکن، مدیریت پنجره)
internal/ipc                 پروتکل named pipe (انواع + سرور + کلاینت)
internal/detector            موتور: امضا، توکن، رفتار، beaconing
internal/monitor             مانیتور فایل‌سیستم و فرآیند/حافظه
internal/quarantine          قرنطینه رمزنگاری‌شده AES-256-GCM (کلید محافظت‌شده با DPAPI)
internal/config              ذخیره تنظیمات JSON (%ProgramData%)
internal/logger              فایل چرخشی zerolog + محو کردن گزارش
pkg/signatures               قالب پایگاه داده امضا + تطبیق‌گر (آگاه از جدول import)
pkg/tokens                   مسیرهای شناخته‌شده توکن/رمز (Discord، Steam و …)
pkg/winapi                   ابزارهای handle/حافظه + تأیید امضا + خودمحافظتی
```

داده‌ها در `%ProgramData%\MihaniSecurity\` نگهداری می‌شوند (config،
signatures.db، قرنطینه و گزارش‌ها).

### قالب پایگاه داده امضا

`signatures.db` یک فایل متنی خط‌به‌خط است:

```
# توضیحات
[HASH] <sha256>|<name>|<severity>|<family>
[PE-STRING] <substring>|<name>|<severity>|<family>
[PE-IMPORT] <dll>|<name>|<severity>|<family>
[YARA-LITE] <name>|<severity>|<family>|<substring>
```

سطح شدت: `low|medium|high|critical`. بسته همراه در
`assets/signatures/signatures.db` است؛ نصب‌کننده آن را در `{app}\signatures\signatures.db`
قرار می‌دهد و سرویس در اولین اجرا آن را در ProgramData بذر می‌کند. قوانین
`PE-IMPORT` با **جدول import تحلیل‌شدهٔ PE** مقایسه می‌شوند (هدر DOS/PE، نگاشت
بخش‌ها و توصیف‌گرهای import — نه اسکن بایت خام)؛ فایل‌های بزرگ‌تر از ۳۲ مگابایت
فقط با هش تطبیق داده می‌شوند.

## ساخت از سورس

پیش‌نیازها: Go ≥ 1.26، Node ≥ 20، CLI ویلز v2 و Inno Setup 6 (برای نصب‌کننده).

ساخت یک‌مرحله‌ای با `build.bat` از ریشه مخزن انجام می‌شود: اجرای vet و تست‌ها،
بازتولید آیکون برنامه (`icon.png` → `build/windows/icon.ico`)، ساخت فرانت‌اند،
کامپایل GUI با ویلز، کامپایل سرویس و نصب‌کننده:

```bat
build.bat
:: -> build\bin\MihaniSecurity.exe
:: -> build\bin\mihanisecurity-service.exe
:: -> dist\MihaniSecurity Setup.exe
```

همان مسیر، گام‌به‌گام:

```powershell
# 1. باندل فرانت‌اند (frontend/dist برای go:embed)
cd frontend; npm install; npm run build; cd ..

# 2. بررسی‌های بک‌اند
go vet ./...
go test ./...

# 3. آیکون برنامه (icon.png -> build\windows\icon.ico)
go run ./build/genicon

# 4. باینری‌های نهایی (GUI با ویلز، سرویس با go)
wails build -clean
go build -trimpath -ldflags "-s -w" -o build/bin/mihanisecurity-service.exe ./cmd/mihanisecurity-service

# 5. نصب‌کننده (Inno Setup)
ISCC installer\MihaniSecurity.iss    # -> dist\MihaniSecurity Setup.exe
```

## تست سریع (بدون نصب)

موتور را در پیش‌زمینه اجرا کنید و یک فایل تست EICAR را اسکن کنید:

```powershell
build\bin\mihanisecurity-service.exe -mode run
# در یک شل دیگر:
notepad test.txt   # جای‌گذاری: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
# در لاگ کنسول، رأی «EICAR Test String» را ببینید
```

## مدیریت سرویس

```powershell
mihanisecurity-service.exe -mode install      # ثبت + شروع (مدیر)
mihanisecurity-service.exe -mode uninstall    # توقف + حذف (مدیر)
mihanisecurity-service.exe -mode run          # حالت توسعه پیش‌زمینه
```

</div>