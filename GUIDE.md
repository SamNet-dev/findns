<div dir="rtl">

# راهنمای کامل findns - اسکنر DNS Resolver

**شروع سریع (فقط ۳ دستور):**

</div>

```bash
findns fetch -o resolvers.txt --local          # 1. دانلود لیست ریزالورها
findns scan -i resolvers.txt -o results.json --domain t.example.com   # 2. اسکن
# 3. اولین IP از لیست passed در results.json = بهترین ریزالور شما
```

<div dir="rtl">

> **مهم:** قبل از اسکن با `--domain`، حتماً [بخش ۳.۶ (تنظیم دامنه تانل)](#-تنظیم-دامنه-تانل-مهم--قبل-از-اسکن-بخوانید) را بخوانید. بدون NS delegation، مرحله resolve/tunnel همیشه 0% خواهد بود.

**فهرست مطالب:**

[1. findns چیست؟](#-findns-چیست-و-چه-کار-میکند) | [2. نصب](#-نصب-و-راهاندازی) | [🪟 ویندوز](#اجرا-روی-ویندوز-) | [3. دریافت لیست](#-دریافت-لیست-resolverها-fetch) | [3.5 ریزالورهای ایرانی](#-دستور-local---resolverهای-ایرانی-داخلی) | [3.6 تنظیم دامنه تانل](#-تنظیم-دامنه-تانل-مهم--قبل-از-اسکن-بخوانید) | [4. اسکن کامل](#-اسکن-کامل-scan---دستور-اصلی) | [5. دستورات جداگانه](#-دستورات-جداگانه) | [6. Chain](#-پایپلاین-سفارشی-chain) | [7. عیب‌یابی](#-عیبیابی-مراحل-اسکن) | [فلگ‌ها](#%EF%B8%8F-فلگهای-عمومی) | [8. ورودی/خروجی](#-فرمت-ورودی-و-خروجی) | [9. سناریوها](#-سناریوهای-عملی) | [10. نکات](#-نکات-و-ترفندها)

---

## 1. findns چیست و چه کار می‌کند؟

findns یک ابزار خط فرمان است که DNS resolverها را تست می‌کند تا بفهمد کدام‌ها برای DNS tunneling (تانل DNS) مناسب هستند.

### DNS tunneling چیست؟

وقتی اینترنت فیلتر یا محدود است، می‌توان از پروتکل DNS برای عبور ترافیک استفاده کرد. ابزارهایی مثل DNSTT و Slipstream این کار را انجام می‌دهند. اما برای کار کردن، به یک DNS resolver نیاز دارید که:

- قابل دسترس باشد (ping جواب بدهد)
- واقعاً DNS resolve کند
- جواب جعلی (hijack) برنگرداند
- payload بزرگ DNS را پشتیبانی کند (EDNS)
- دامنه تانل شما را ببیند و resolve کند

findns همه این‌ها را به صورت خودکار تست می‌کند.

### چه پروتکل‌هایی پشتیبانی می‌شود؟

- **UDP DNS** (پورت 53) - روش کلاسیک
- **DoH** یعنی DNS-over-HTTPS (پورت 443) - شبیه ترافیک عادی HTTPS

### آیا به نصب dnstt یا slipstream نیاز دارم؟

**خیر!** findns به تنهایی تمام تست‌های DNS را انجام می‌دهد. فقط اگر بخواهید تست واقعی تانل (e2e) انجام دهید، به dnstt-client یا slipstream-client نیاز دارید. بدون آن‌ها هم اسکنر کامل کار می‌کند.

### dnstt-client چیست و چطور نصبش کنم؟

`dnstt-client` برنامه کلاینت پروژه [DNSTT](https://www.bamsoftware.com/software/dnstt/) است. findns از این برنامه برای **تست واقعی تانل** (e2e) استفاده می‌کند — واقعاً یک تانل می‌سازد و بررسی می‌کند اتصال برقرار می‌شود یا نه.

#### روش 1: دانلود باینری آماده از صفحه findns (پیشنهادی — نیازی به نصب Go ندارد)

باینری‌های آماده `dnstt-client` در صفحه Release خود findns موجود است:

</div>

**ویندوز:**
```powershell
# دانلود از صفحه Release:
# https://github.com/SamNet-dev/findns/releases/latest/download/dnstt-client.exe
# فایل را کنار findns.exe بگذارید — همین!
```

<div dir="rtl">

ساختار پوشه روی ویندوز:

</div>

```
📁 C:\Users\you\findns\
├── findns.exe                    (یا findns-windows-amd64.exe)
├── dnstt-client.exe              ← دانلود از Release
└── resolvers.txt
```

<div dir="rtl">

</div>

**لینوکس:**
```bash
# دانلود
curl -LO https://github.com/SamNet-dev/findns/releases/latest/download/dnstt-client-linux
chmod +x dnstt-client-linux
mv dnstt-client-linux dnstt-client

# گذاشتن کنار findns (ساده‌ترین روش):
mv dnstt-client /path/to/findns/

# یا گذاشتن در PATH:
sudo mv dnstt-client /usr/local/bin/
```

<div dir="rtl">

#### روش 2: نصب با Go (اگر Go نصب دارید)

</div>

```bash
go install www.bamsoftware.com/git/dnstt.git/dnstt-client@latest
```

<div dir="rtl">

#### روش 3: دانلود از سایت اصلی DNSTT

از [صفحه پروژه DNSTT](https://www.bamsoftware.com/software/dnstt/) دانلود کنید. **نکته:** فایل دانلودی یک آرشیو حاوی سورس‌کد Go است، نه باینری آماده. برای استفاده باید با `go build` بیلد کنید.

> **findns به صورت خودکار** فایل کلاینت را در سه مسیر جستجو می‌کند: ۱) `PATH` سیستم ۲) پوشه فعلی ۳) کنار فایل findns. ساده‌ترین روش: فایل exe را کنار findns بگذارید.

### slipstream-client چیست و چطور نصبش کنم؟

`slipstream-client` کلاینت پروژه [Slipstream](https://github.com/Mygod/slipstream-rust) است. مشابه DNSTT ولی با پروتکل متفاوت.

**دانلود:** از [صفحه Release پروژه Slipstream](https://github.com/Mygod/slipstream-rust/releases) باینری مناسب سیستم خود را دانلود کنید (فایل `windows-x86_64` برای ویندوز، `linux-x86_64` برای لینوکس).

محل قرارگیری: مثل dnstt-client — فایل `slipstream-client.exe` (ویندوز) یا `slipstream-client` (لینوکس) را کنار findns بگذارید.

### کدام resolverها برای dnstt کار می‌کنند؟

بدون فلگ `--pubkey` هم findns بررسی می‌کند کدام resolverها **قابلیت** کار با تانل DNS را دارند:

- **resolve/tunnel**: بررسی می‌کند resolver می‌تواند NS record دامنه تانل شما را ببیند
- **edns**: بررسی می‌کند سایز payload بزرگ (1232 بایت) پشتیبانی می‌شود
- **nxdomain**: بررسی می‌کند resolver جواب جعلی نمی‌دهد

resolverهایی که همه این مراحل را پاس کنند، **با احتمال بالا** برای dnstt کار می‌کنند. فلگ `--pubkey` فقط تأیید نهایی (e2e) را اضافه می‌کند.

---

## 2. نصب و راه‌اندازی

### روش 1: دانلود باینری آماده (پیشنهادی)

</div>

**Linux (x64):**
```bash
curl -LO https://github.com/SamNet-dev/findns/releases/latest/download/findns-linux-amd64
chmod +x findns-linux-amd64
mv findns-linux-amd64 /usr/local/bin/findns
```

**Linux (ARM64):**
```bash
curl -LO https://github.com/SamNet-dev/findns/releases/latest/download/findns-linux-arm64
chmod +x findns-linux-arm64
mv findns-linux-arm64 /usr/local/bin/findns
```

**macOS (Intel):**
```bash
curl -LO https://github.com/SamNet-dev/findns/releases/latest/download/findns-darwin-amd64
chmod +x findns-darwin-amd64
mv findns-darwin-amd64 /usr/local/bin/findns
```

**macOS (Apple Silicon / M1/M2/M3):**
```bash
curl -LO https://github.com/SamNet-dev/findns/releases/latest/download/findns-darwin-arm64
chmod +x findns-darwin-arm64
mv findns-darwin-arm64 /usr/local/bin/findns
```

**Windows (x64):**

[findns-windows-amd64.exe](https://github.com/SamNet-dev/findns/releases/latest/download/findns-windows-amd64.exe)

<div dir="rtl">

بعد از نصب تست کنید:

</div>

```bash
findns --help
```

<div dir="rtl">

### روش 2: بیلد از سورس

نیازمند Go نسخه 1.24 یا بالاتر

</div>

```bash
git clone https://github.com/SamNet-dev/findns.git
cd findns
go build -o findns ./cmd
./findns --help
```

<div dir="rtl">

### روش 3: Go Install

</div>

```bash
go install github.com/SamNet-dev/findns/cmd@latest
```

<div dir="rtl">

### اجرا روی ویندوز 🪟

findns روی ویندوز **بدون نیاز به WSL یا لینوکس** کار می‌کند.

**دانلود مستقیم (بدون نصب چیزی):**

1. فایل [findns-windows-amd64.exe](https://github.com/SamNet-dev/findns/releases/latest/download/findns-windows-amd64.exe) را دانلود کنید
2. نام آن را به `findns.exe` تغییر دهید (اختیاری)
3. **cmd** یا **PowerShell** را در همان پوشه باز کنید (Shift + کلیک راست → Open PowerShell here)

**بیلد از سورس روی ویندوز:**

</div>

```powershell
git clone https://github.com/SamNet-dev/findns.git
cd findns
go build -o findns.exe ./cmd
```

<div dir="rtl">

**نحوه اجرا:** در تمام دستورات این راهنما به جای `findns` از `.\findns.exe` استفاده کنید:

</div>

```powershell
.\findns.exe fetch -o resolvers.txt
.\findns.exe scan -i resolvers.txt -o results.json --domain t.example.com
```

<div dir="rtl">

**نکات ویندوز:**
- **curl** از قبل در ویندوز 10/11 نصب است
- اگر ping فیل می‌شود → cmd را **Run as Administrator** باز کنید
- فایل‌های `dnstt-client.exe` و `slipstream-client.exe` را کنار `findns.exe` بگذارید
- در PowerShell برای ادامه دستورات طولانی از بک‌تیک `` ` `` استفاده کنید (به جای `\` در لینوکس)

---

## 3. دریافت لیست Resolverها (fetch)

قبل از اسکن، باید لیست resolver داشته باشید. دستور fetch به صورت خودکار از منابع عمومی دانلود می‌کند.

### دانلود resolverهای UDP جهانی

</div>

```bash
findns fetch -o resolvers.txt
```

<div dir="rtl">

این دستور از منبع trickest/resolvers حدود **17,000+** آی‌پی resolver عمومی را دانلود می‌کند.

### دانلود با resolverهای ایرانی (--local)

</div>

```bash
findns fetch -o resolvers.txt --local
```

<div dir="rtl">

این دستور علاوه بر resolverهای جهانی، **7,800+ resolver شناخته‌شده ایرانی** را هم به لیست اضافه می‌کند. این resolverها از قبل تأیید شده‌اند (منبع: ir-resolvers) و نرخ موفقیت بالایی در اسکن دارند.

> **نکته مهم:** فلگ `--local` به هیچ سرور خارجی وصل نمی‌شود. لیست resolverهای ایرانی **داخل خود برنامه** ذخیره شده‌اند (embedded). حتی اگر GitHub فیلتر باشد، این فلگ کار می‌کند.

> **چرا resolverهای ایرانی مهم هستند؟** در شبکه ایران، resolverهای داخلی معمولاً سریع‌تر جواب می‌دهند و ممکن است محدودیت کمتری داشته باشند.

> **برای پیدا کردن resolverهای جدید** که در لیست شناخته‌شده نیستند، از دستور [`findns local --discover`](#دستور-local---resolverهای-ایرانی-داخلی) استفاده کنید.

### دانلود resolverهای DoH

</div>

```bash
findns fetch -o doh-resolvers.txt --doh
```

<div dir="rtl">

این دستور آدرس‌های DoH (DNS-over-HTTPS) را جمع‌آوری می‌کند: 19 سرویس معروف (Google, Cloudflare, Quad9, AdGuard و ...) + لیست‌های عمومی از GitHub.

> فایل خروجی به صورت خودکار deduplicate می‌شود (تکراری‌ها حذف می‌شوند).

---

## 3.5. دستور local - resolverهای ایرانی داخلی

دستور `local` داده‌های ایرانی **داخل خود برنامه** را خروجی می‌دهد — نیازی به اینترنت ندارد. دو حالت دارد:

### حالت 1: resolverهای شناخته‌شده (پیش‌فرض — پیشنهادی)

بدون هیچ فلگ اضافه، **7,800+ resolver ایرانی از قبل تأیید‌شده** را خروجی می‌دهد (منبع: ir-resolvers). این resolverها قبلاً بررسی شده‌اند و نرخ موفقیت بالایی دارند.

</div>

```bash
# خروجی resolverهای شناخته‌شده (پیشنهادی — سریع‌ترین راه)
findns local -o resolvers.txt

# اسکن کنید:
findns scan -i resolvers.txt -o results.json --domain t.mysite.com
```

<div dir="rtl">

> **این بهترین نقطه شروع است.** چون این آی‌پی‌ها واقعاً DNS resolver هستند، اکثرشان در اسکن پاس می‌شوند.

### حالت 2: کشف resolver جدید (--discover)

اگر می‌خواهید resolverهایی پیدا کنید که در لیست شناخته‌شده **نیستند**، از `--discover` استفاده کنید. این حالت از **1,919 رنج CIDR ایرانی** (منبع: RIPE NCC، ~10.8 میلیون آی‌پی) استفاده می‌کند.

> **مهم:** این آی‌پی‌ها **resolver نیستند!** فقط کاندید هستند. اکثرشان DNS server نیستند و در اسکن فیل می‌شوند. این حالت برای **کشف** resolverهای جدید است.

#### نمونه‌گیری — Sample (پیش‌فرض discover)

از هر subnet تعدادی آی‌پی **تصادفی** انتخاب می‌کند. سریع است و پوشش خوبی می‌دهد.

</div>

```bash
# پیش‌فرض: 10 آی‌پی تصادفی از هر subnet (~19,000 آی‌پی)
findns local -o candidates.txt --discover

# 5 آی‌پی از هر subnet (سریع‌تر، ~9,500 آی‌پی)
findns local -o candidates.txt --discover --sample 5

# 50 آی‌پی از هر subnet (کندتر، ~95,000 آی‌پی)
findns local -o candidates.txt --discover --sample 50

# بعد از تولید لیست، اسکن کنید:
findns scan -i candidates.txt -o results.json --domain t.mysite.com
```

<div dir="rtl">

#### دسته‌ای — Batch (اسکن تدریجی)

اگر می‌خواهید **همه** آی‌پی‌ها را اسکن کنید ولی یکجا نه — مثلاً هر بار 1 میلیون آی‌پی — از batch استفاده کنید.

**هر دسته رنج متفاوتی دارد و هیچ آی‌پی تکراری بین دسته‌ها وجود ندارد.** برنامه بعد از هر دسته دقیقاً می‌گوید دستور بعدی چیست.

</div>

```bash
# دسته اول: آی‌پی شماره 1 تا 1,000,000
findns local -o batch1.txt --discover --batch 1000000

# برنامه در خروجی می‌گوید:
#   next batch command:
#     findns local -o <next-file>.txt --discover --batch 1000000 --offset 1000000
#   remaining: 9,815,490 IPs

# دسته دوم: آی‌پی شماره 1,000,001 تا 2,000,000
findns local -o batch2.txt --discover --batch 1000000 --offset 1000000

# هر دسته را جداگانه اسکن کنید:
findns scan -i batch1.txt -o results1.json --domain t.mysite.com
findns scan -i batch2.txt -o results2.json --domain t.mysite.com
```

<div dir="rtl">

> **نکته:** هر دسته آی‌پی‌های **جدید و متفاوت** تولید می‌کند. لازم نیست نگران اسکن مجدد باشید — `--offset` تضمین می‌کند هیچ آی‌پی دو بار اسکن نشود.

#### حالت کامل — Full

تمام ~10.8 میلیون آی‌پی ایرانی را یکجا خروجی می‌دهد.

</div>

```bash
findns local -o all-iran.txt --discover --full
```

<div dir="rtl">

> **هشدار:** اسکن 10.8 میلیون آی‌پی **روزها** طول می‌کشد! پیشنهاد: به جای `--full` از `--batch 1000000` استفاده کنید.

#### نمایش رنج‌ها (بدون تولید فایل)

فقط لیست رنج‌های CIDR را ببینید. نیازی به `-o` ندارد:

</div>

```bash
findns local --list-ranges
```

<div dir="rtl">

### توضیح فلگ‌ها

| فلگ | توضیح | پیش‌فرض |
|-----|-------|---------|
| `-o, --output` | مسیر فایل خروجی برای لیست آی‌پی‌ها. در تمام حالت‌ها **الزامی** است به جز `--list-ranges`. | — |
| `--discover` | حالت کشف resolver جدید. بدون این فلگ، resolverهای شناخته‌شده خروجی داده می‌شوند. | `false` |
| `--sample N` | **[discover]** از هر subnet چند آی‌پی تصادفی انتخاب شود. عدد بزرگ‌تر = پوشش بیشتر ولی اسکن کندتر. عدد `0` مثل `--full` عمل می‌کند. | `10` |
| `--full` | **[discover]** تمام ~10.8 میلیون آی‌پی را خروجی بده. این فلگ `--sample` را نادیده می‌گیرد. | `false` |
| `--batch N` | **[discover]** دقیقاً N آی‌پی خروجی بده. هر بار اجرا با `--offset` متفاوت، رنج جدیدی می‌دهد. هیچ آی‌پی تکراری نیست. | `0` (غیرفعال) |
| `--offset N` | **[discover]** با `--batch` استفاده می‌شود. از آی‌پی شماره N شروع کن (0-indexed). برنامه بعد از هر دسته `--offset` بعدی را نشان می‌دهد. | `0` |
| `--list-ranges` | فقط لیست رنج‌های CIDR ایرانی را چاپ کن و خارج شو. نیازی به `-o` ندارد. | `false` |

### اولویت فلگ‌ها

- بدون `--discover` → resolverهای شناخته‌شده (7,800+)
- اگر `--list-ranges` داده شود → فقط رنج‌ها چاپ می‌شود، بقیه فلگ‌ها نادیده گرفته می‌شوند
- اگر `--discover --batch` > 0 باشد → حالت دسته‌ای فعال می‌شود (`--sample` و `--full` نادیده گرفته می‌شوند)
- اگر `--discover --full` داده شود → تمام آی‌پی‌ها (`--sample` نادیده گرفته می‌شود)
- اگر `--discover` بدون فلگ دیگر → حالت نمونه‌گیری با `--sample N`

---

## 3.6. تنظیم دامنه تانل (مهم — قبل از اسکن بخوانید)

فلگ `--domain` در findns یک دامنه معمولی نیست — باید یک **ساب‌دامین با NS delegation** به سرور DNSTT/Slipstream شما باشد. بدون این تنظیم، مرحله `resolve/tunnel` همیشه 0% خواهد بود.

### پیش‌نیازها

1. یک دامنه که **Nameserver آن به Cloudflare تغییر کرده باشد** (در پنل registrar). اگر دامنه را به Cloudflare اضافه کرده‌اید ولی Nameserver را تغییر نداده‌اید، رکوردها سرو نمی‌شوند.
2. **DNSSEC خاموش باشد** — در Cloudflare: DNS → Settings → Disable DNSSEC. اگر روشن باشد، delegation بدون امضا می‌شود و بعضی resolverها NXDOMAIN برمی‌گردانند.
3. سرور DNSTT/Slipstream **مستقیماً روی پورت 53** گوش بدهد. اگر DNS router یا سرویس دیگری (مثل systemd-resolved) روی پورت 53 نشسته، query ها به dnstt-server نمی‌رسد.

### چطور تنظیم کنیم؟

فرض کنید دامنه شما `example.com` است و سرور DNSTT روی آی‌پی `1.2.3.4` اجرا می‌شود. باید دو رکورد DNS بسازید:

</div>

```
نوع      نام                مقدار
──────    ──────────────     ──────────────
NS        t.example.com      ns.example.com
A         ns.example.com     1.2.3.4
```

<div dir="rtl">

**توضیح:**
- رکورد **NS**: می‌گوید "برای هر چیزی درباره `t.example.com`، از سرور `ns.example.com` بپرس"
- رکورد **A**: می‌گوید "`ns.example.com` روی آی‌پی `1.2.3.4` است"

بعد از تنظیم، سرور DNSTT شما تمام کوئری‌های DNS برای `t.example.com` را دریافت می‌کند و ترافیک تانل از آن عبور می‌کند.

### تنظیم در Cloudflare (قدم به قدم)

1. وارد داشبورد Cloudflare شوید → سایت خود را انتخاب کنید → DNS → Records
2. **رکورد A بسازید:**
   - Type: `A`
   - Name: `ns`
   - IPv4 address: آی‌پی سرور شما (مثلاً `1.2.3.4`)
   - Proxy status: **DNS only** (ابر خاکستری) ← بسیار مهم! اگر Proxied (ابر نارنجی) باشد پورت 53 بلاک می‌شود
   - Save
3. **رکورد NS بسازید:**
   - Type: `NS`
   - Name: `t` (فقط نام ساب‌دامین، نه کل دامنه)
   - Nameserver: `ns.example.com` (کل آدرس با دامنه شما)
   - Save
4. **DNSSEC را خاموش کنید:** DNS → Settings → Disable DNSSEC

### تنظیم سرور

قبل از تست، مطمئن شوید dnstt-server مستقیماً روی پورت 53 اجرا شده:

</div>

```bash
# چک کنید چه پروسه‌ای روی پورت 53 نشسته:
ss -ulnp | grep :53

# باید dnstt-server یا slipstream-server ببینید.
# اگر systemd-resolved هست، اول خاموشش کنید:
systemctl stop systemd-resolved
systemctl disable systemd-resolved

# دامنه در دستور dnstt باید دقیقاً با NS record مچ باشد:
# ✅ dnstt-server ... -domain t.example.com    (اگر NS برای t ساخته‌اید)
# ❌ dnstt-server ... -domain t2.example.com   (نام متفاوت = کار نمی‌کند)
```

<div dir="rtl">

### تست صحت تنظیم

**روش پیشنهادی (از داخل ایران هم کار می‌کند):**

</div>

```bash
# از Google DoH بپرسید (ISP پورت 53 را intercept نمی‌تواند):
curl -s "https://dns.google/resolve?name=t.example.com&type=NS"

# جواب صحیح: "Status":0 و NS record در جواب
# اگر "Status":3 = NXDOMAIN — تنظیم اشتباه است (بخش عیب‌یابی را ببینید)
```

<div dir="rtl">

**روش جایگزین (ممکن است در ایران intercept شود):**

</div>

```bash
# تست با dig (از خارج ایران یا VPS):
dig t.example.com NS @8.8.8.8

# جواب صحیح باید شامل ns.example.com باشد.
```

<div dir="rtl">

### اشتباهات رایج

| اشتباه | نتیجه |
|--------|-------|
| استفاده از دامنه اصلی (`--domain example.com`) به جای ساب‌دامین | resolve/tunnel فیل می‌شود چون NS دامنه اصلی به registrar اشاره می‌کند نه سرور شما |
| فقط A record برای `t.example.com` بدون NS delegation | resolve/tunnel فیل می‌شود چون NS وجود ندارد |
| NS تنظیم شده ولی سرور DNSTT روشن نیست | resolve/tunnel ممکن است پاس شود (NS وجود دارد) ولی e2e فیل می‌شود |
| استفاده از `t.example.com` به صورت واقعی (دامنه تست) | resolve/tunnel فیل می‌شود — باید دامنه خودتان باشد |
| DNSSEC روشن است در Cloudflare | delegation بدون امضا می‌شود و بعضی resolverها NXDOMAIN برمی‌گردانند |
| رکورد A برای `ns` روی Proxied (ابر نارنجی) | پورت 53 به سرور نمی‌رسد — باید DNS only (ابر خاکستری) باشد |
| Nameserver دامنه در registrar به Cloudflare تغییر نکرده | رکوردها در Cloudflare وجود دارد ولی سرو نمی‌شود — NXDOMAIN برای همه چیز |
| DNS router (مثل dnstm) روی پورت 53 نشسته به جای dnstt-server | router دامنه تانل را نمی‌شناسد و NXDOMAIN برمی‌گرداند |
| سرویس دیگر (systemd-resolved, bind, dnsmasq) پورت 53 را گرفته | query ها به dnstt-server نمی‌رسد |

> **اگر resolve/tunnel برای تمام resolverها فیل شد (0%):** مشکل از resolverها نیست — مشکل از تنظیم DNS دامنه شماست. تنظیم NS delegation را بررسی کنید.

> **اگر سرور DNSTT ندارید:** بدون `--domain` اسکن کنید. فقط مراحل ping/resolve/nxdomain اجرا می‌شود و resolverهای سالم را پیدا می‌کنید.

### عیب‌یابی: NXDOMAIN با وجود تنظیم صحیح

اگر رکوردها درست به نظر می‌رسند ولی هنوز NXDOMAIN می‌گیرید، مرحله به مرحله چک کنید:

**مرحله ۱: آیا Cloudflare واقعاً سرو می‌کند؟**

</div>

```bash
# از ISP رد شوید — مستقیم از Google DoH بپرسید:
curl -s "https://dns.google/resolve?name=t.example.com&type=NS"
```

<div dir="rtl">

- اگر `"Status":0` و NS record برگشت → Cloudflare درست کار می‌کند ✅
- اگر `"Status":3` (NXDOMAIN) → ادامه دهید:
  - فیلد `"Comment"` را بخوانید — نشان می‌دهد جواب از کجا آمده

**مرحله ۲: آیا NXDOMAIN از سرور شماست یا Cloudflare؟**

اگر Comment نوشته `"Response from [IP سرور شما]"`:
- ✅ Cloudflare delegation درست کار می‌کند
- ❌ مشکل از سرور شماست — چیزی روی پورت 53 دامنه را نمی‌شناسد

اگر Comment نوشته `"Response from [IP دیگر]"` یا اصلاً Comment نداشت:
- ❌ Cloudflare دامنه را سرو نمی‌کند — Nameserver registrar را چک کنید

**مرحله ۳: چک کنید چه پروسه‌ای روی پورت 53 سرور نشسته**

</div>

```bash
ss -ulnp | grep :53
```

<div dir="rtl">

- اگر `dnstt-server` مستقیماً روی پورت 53 → تنظیم درست است
- اگر `dnstm` یا DNS router دیگر → config آن را چک کنید که دامنه تانل تعریف شده و به پورت درست forward می‌شود
- اگر `systemd-resolved` یا `named` یا `dnsmasq` → آن سرویس را خاموش کنید:

</div>

```bash
# خاموش کردن systemd-resolved:
systemctl stop systemd-resolved
systemctl disable systemd-resolved

# بعد dnstt-server را دوباره اجرا کنید
```

<div dir="rtl">

**مرحله ۴: تست نهایی**

</div>

```bash
# دوباره تست کنید:
curl -s "https://dns.google/resolve?name=t.example.com&type=A"

# اگر Status 0 برگشت = حل شد ✅
```

<div dir="rtl">

> **نکته:** اگر از داخل ایران `dig` می‌زنید و NXDOMAIN می‌گیرید ولی تست DoH بالا جواب درست داد — مشکل از ISP شماست که پورت 53 را intercept می‌کند. این روی عملکرد تانل تأثیر ندارد چون ترافیک تانل رمزنگاری شده است.

> **برای عیب‌یابی سایر مراحل اسکن** (ping، resolve، e2e، DoH) → [بخش ۷: عیب‌یابی مراحل اسکن](#-عیبیابی-مراحل-اسکن)

---

## 4. اسکن کامل (scan) - دستور اصلی

دستور scan مهم‌ترین و پیشنهادی‌ترین دستور است. تمام مراحل تست را به ترتیب اجرا می‌کند و فقط resolverهایی که همه مراحل را پاس کنند در خروجی نهایی می‌آیند.

### اسکن ساده (بدون دامنه تانل)

</div>

```bash
findns scan -i resolvers.txt -o results.json
```

<div dir="rtl">

مراحل: `ping -> resolve -> nxdomain`

این حالت بررسی می‌کند resolver زنده، فعال و بدون هایجک است. (برای رد کردن nxdomain از `--skip-nxdomain` استفاده کنید)

### اسکن کامل با دامنه تانل (پیشنهادی)

</div>

```bash
findns scan -i resolvers.txt -o results.json --domain t.example.com
```

<div dir="rtl">

مراحل: `ping -> resolve -> nxdomain -> resolve/tunnel`

> **نکته:** برای اضافه کردن تست EDNS payload size از فلگ `--edns` استفاده کنید. با این فلگ: `ping -> resolve -> nxdomain -> edns -> resolve/tunnel`

### توضیح هر مرحله

**1. ping** — آیا سرور resolver از نظر شبکه قابل دسترس است؟ یک ICMP ping ارسال می‌کند و زمان پاسخ را اندازه می‌گیرد.
- متریک: `ping_ms` (میلی‌ثانیه)

**2. resolve** — آیا resolver واقعاً DNS resolve می‌کند؟ یک کوئری A record برای google.com ارسال می‌کند.
- متریک: `resolve_ms` (میلی‌ثانیه)

**3. nxdomain** — آیا resolver جواب جعلی می‌دهد (hijack)؟ یک دامنه تصادفی غیرموجود (مثل `nxd-abc123.invalid`) را کوئری می‌کند. resolver سالم باید NXDOMAIN برگرداند. resolver هایجک‌شده جواب NOERROR با آی‌پی جعلی برمی‌گرداند.
- متریک: `nxdomain_ok` (تعداد جواب‌های صحیح), `hijack` (0=سالم)

**4. edns** — resolver چه سایز payload DNS را پشتیبانی می‌کند؟ سایزهای 512, 900 و 1232 بایت تست می‌شود. هرچه بزرگ‌تر = تانل سریع‌تر.
- متریک: `edns_max` (بزرگ‌ترین سایز: 512, 900, یا 1232)

**5. resolve/tunnel** — آیا resolver دامنه تانل شما را می‌بیند؟ NS record و glue A record دامنه تانل را بررسی می‌کند. اگر resolver نتواند دامنه تانل را resolve کند، تانل کار نمی‌کند.
- متریک: `resolve_ms` (میلی‌ثانیه)

### اسکن با تست واقعی تانل DNSTT (اختیاری)

</div>

```bash
findns scan -i resolvers.txt -o results.json \
  --domain t.example.com --pubkey abc123def456...
```

<div dir="rtl">

مراحل: `ping -> resolve -> nxdomain -> resolve/tunnel -> e2e/dnstt`

> با `--edns`: `ping -> resolve -> nxdomain -> edns -> resolve/tunnel -> e2e/dnstt`

نیازمند: `dnstt-client` و `curl` در PATH. این مرحله واقعاً dnstt-client را اجرا می‌کند، یک تانل SOCKS می‌سازد و با curl از طریق آن تانل یک صفحه وب را باز می‌کند.
- متریک: `e2e_ms` (کل زمان از شروع تا اتصال موفق)

### اسکن با تست واقعی Slipstream (اختیاری)

</div>

```bash
findns scan -i resolvers.txt -o results.json \
  --domain s.example.com --cert /path/to/cert.pem
```

<div dir="rtl">

نیازمند: `slipstream-client` و `curl` در PATH

### اسکن DoH

</div>

```bash
findns scan -i doh-resolvers.txt -o results.json --domain t.example.com --doh
```

<div dir="rtl">

مراحل: `doh/resolve -> doh/resolve/tunnel`

اسکن DoH با تست e2e:

</div>

```bash
findns scan -i doh-resolvers.txt -o results.json \
  --domain t.example.com --pubkey abc123... --doh
```

<div dir="rtl">

مراحل: `doh/resolve -> doh/resolve/tunnel -> doh/e2e`

### فلگ‌های دستور scan

| فلگ | توضیح | پیش‌فرض |
|-----|-------|---------|
| `--domain` | دامنه تانل (فعال‌سازی تست tunnel/edns) | — |
| `--pubkey` | کلید عمومی سرور DNSTT (فعال‌سازی تست e2e) | — |
| `--cert` | مسیر فایل گواهی Slipstream | — |
| `--test-url` | آدرسی که از طریق تانل تست شود | `https://httpbin.org/ip` |
| `--proxy-auth` | احراز هویت پروکسی SOCKS به صورت `user:pass` (برای تست e2e) | — |
| `--doh` | حالت DoH به جای UDP | `false` |
| `--skip-ping` | رد کردن مرحله ping (مفید اگر ICMP مسدود باشد) | `false` |
| `--edns` | فعال‌سازی تست سایز EDNS payload (اختیاری) | `false` |
| `--skip-nxdomain` | رد کردن بررسی هایجک | `false` |
| `--top` | تعداد نتایج برتر در خروجی ترمینال | `10` |

---

## 5. دستورات جداگانه

هر مرحله از اسکن را می‌توانید به تنهایی هم اجرا کنید:

### ping - بررسی دسترسی‌پذیری

</div>

```bash
findns ping -i resolvers.txt -o ping-results.json
findns ping -i resolvers.txt -o ping-results.json -c 5 -t 2
```

<div dir="rtl">

`-c 5` = پنج بار ping بزن (پیش‌فرض: 3) | `-t 2` = تایم‌اوت 2 ثانیه (پیش‌فرض: 3)

### resolve - تست DNS Resolution

</div>

```bash
findns resolve -i resolvers.txt -o resolve-results.json --domain google.com
```

<div dir="rtl">

### resolve tunnel - بررسی NS Delegation

</div>

```bash
findns resolve tunnel -i resolvers.txt -o tunnel-results.json --domain t.example.com
```

<div dir="rtl">

بررسی می‌کند آیا resolver می‌تواند NS record دامنه تانل و glue A record آن را ببیند.

### nxdomain - تشخیص هایجک DNS

</div>

```bash
findns nxdomain -i resolvers.txt -o nxd-results.json
```

<div dir="rtl">

دامنه‌های تصادفی غیرموجود را کوئری می‌کند. resolver سالم: NXDOMAIN برمی‌گرداند. resolver هایجک‌شده: NOERROR با آی‌پی جعلی برمی‌گرداند.

### edns - تست سایز Payload

</div>

```bash
findns edns -i resolvers.txt -o edns-results.json --domain t.example.com
```

<div dir="rtl">

سایزهای 512, 900 و 1232 بایت را تست می‌کند.

---

### پیش‌نیازهای تست E2E (مهم - حتماً بخوانید)

تست e2e فقط بررسی DNS نیست — **واقعاً یک تانل باز می‌کند و ترافیک رد می‌کند.** برای این کار به دو چیز نیاز دارید:

**۱. سرور تانل فعال:** شما باید یک سرور DNSTT یا Slipstream **از قبل راه‌اندازی کرده باشید** روی یک VPS. بدون سرور، تست e2e نمی‌تواند کار کند چون باید واقعاً به سرور وصل شود.

**۲. باینری کلاینت:** فایل `dnstt-client` یا `slipstream-client` باید روی سیستم شما موجود باشد. (نحوه نصب: [بخش ۱ - dnstt-client چیست؟](#dnstt-client-چیست-و-چطور-نصبش-کنم))

> **اگر سرور تانل ندارید:** فقط تا مرحله `tunnel` (بررسی NS record) می‌توانید تست کنید. این مرحله بررسی می‌کند resolver **قابلیت** ساپورت تانل را دارد، ولی تضمین واقعی نمی‌دهد. برای تضمین واقعی باید e2e بزنید.

---

### e2e dnstt - تست واقعی تانل DNSTT

</div>

```bash
findns e2e dnstt -i resolvers.txt -o e2e-results.json \
  --domain t.example.com --pubkey abc123...
```

<div dir="rtl">

این دستور برای هر ریزالور:
1. `dnstt-client` را اجرا می‌کند
2. یک پروکسی SOCKS لوکال باز می‌کند
3. با `curl` از طریق پروکسی یک درخواست HTTP ارسال می‌کند
4. اگر جواب آمد = ریزالور واقعاً کار می‌کند

نیازمند: `dnstt-client` و `curl` و سرور DNSTT فعال

### e2e slipstream - تست واقعی تانل Slipstream

</div>

```bash
findns e2e slipstream -i resolvers.txt -o e2e-results.json \
  --domain s.example.com --cert /path/to/cert.pem
```

<div dir="rtl">

نیازمند: `slipstream-client` و `curl` و سرور Slipstream فعال

### doh resolve - تست DoH Resolution

</div>

```bash
findns doh resolve -i doh-resolvers.txt -o doh-results.json --domain google.com
```

<div dir="rtl">

### doh resolve tunnel - تست DoH NS Delegation

</div>

```bash
findns doh resolve tunnel -i doh-resolvers.txt -o doh-tunnel-results.json \
  --domain t.example.com
```

<div dir="rtl">

### doh e2e - تست واقعی تانل از طریق DoH

</div>

```bash
findns doh e2e -i doh-resolvers.txt -o doh-e2e-results.json \
  --domain t.example.com --pubkey abc123...
```

<div dir="rtl">

نیازمند: `dnstt-client` و `curl`

---

## 6. پایپلاین سفارشی (chain)

دستور chain به شما اجازه می‌دهد مراحل دلخواه را ترکیب کنید. فقط resolverهایی که هر مرحله را پاس کنند به مرحله بعد می‌روند.

**مثال ساده:**

</div>

```bash
findns chain -i resolvers.txt -o results.json \
  --step "ping" \
  --step "resolve:domain=google.com"
```

<div dir="rtl">

**مثال کامل:**

</div>

```bash
findns chain -i resolvers.txt -o results.json \
  --step "ping:count=1" \
  --step "resolve:domain=google.com,count=1" \
  --step "nxdomain:count=2" \
  --step "edns:domain=t.example.com" \
  --step "resolve/tunnel:domain=t.example.com" \
  --step "e2e/dnstt:domain=t.example.com,pubkey=abc123,timeout=10"
```

<div dir="rtl">

فرمت هر step: `type:key=val,key=val`

**پارامترهای مشترک:**
- `count=N` — تعداد تلاش (پیش‌فرض: مقدار فلگ `-c`)
- `timeout=N` — تایم‌اوت به ثانیه (پیش‌فرض: مقدار فلگ `-t`)

### لیست تمام stepها

| Step | پارامترهای لازم | متریک خروجی |
|------|----------------|-------------|
| `ping` | — | `ping_ms` |
| `resolve` | `domain` | `resolve_ms` |
| `resolve/tunnel` | `domain` | `resolve_ms` |
| `nxdomain` | — | `hijack`, `nxdomain_ok` |
| `edns` | `domain` | `edns_max` |
| `e2e/dnstt` | `domain`, `pubkey` | `e2e_ms` |
| `e2e/slipstream` | `domain`, `cert` | `e2e_ms` |
| `doh/resolve` | `domain` | `resolve_ms` |
| `doh/resolve/tunnel` | `domain` | `resolve_ms` |
| `doh/e2e` | `domain`, `pubkey` | `e2e_ms` |

**مثال DoH chain:**

</div>

```bash
findns chain -i doh-resolvers.txt -o results.json \
  --step "doh/resolve:domain=google.com" \
  --step "doh/resolve/tunnel:domain=t.example.com" \
  --step "doh/e2e:domain=t.example.com,pubkey=abc123"
```

<div dir="rtl">

---

## 7. عیب‌یابی مراحل اسکن

> اگر هر مرحله‌ای pass rate خیلی پایین (نزدیک 0%) دارد، **مشکل از resolverها نیست** — مشکل از تنظیمات شماست. ابتدا [جدول خلاصه (7.6)](#76-خلاصه-سریع-عیبیابی) را ببینید، سپس بخش مربوطه را بخوانید.

---

### 7.1. ping - همه فیل شدند (0%)

> **علامت:** مرحله ping گزارش 0% pass rate می‌دهد

**علت‌های رایج:**
- **ICMP بلاک شده:** ISP یا فایروال سرور شما پینگ را مسدود کرده
- **فایروال VPS:** بعضی VPSها ICMP خروجی را بلاک می‌کنند

**راه‌حل:**

</div>

```bash
# مرحله ping را رد کنید:
findns scan -i resolvers.txt -o results.json --skip-ping

# یا از chain بدون ping استفاده کنید:
findns chain -i resolvers.txt -o results.json \
  --step "resolve:domain=google.com"
```

<div dir="rtl">

> **نکته:** رد کردن ping به معنی این نیست که resolverها بد هستند — فقط ICMP بلاک شده. resolve و بقیه مراحل هنوز کار می‌کنند.

---

### 7.2. resolve - همه فیل شدند (0%)

> **علامت:** مرحله resolve گزارش 0% pass rate می‌دهد

**علت‌های رایج:**
- **لیست resolver خراب:** فایل ورودی حاوی IPهای اشتباه یا منقضی‌شده
- **پورت 53 بلاک شده:** ISP یا فایروال پورت 53 خروجی را مسدود کرده
- **تایم‌اوت کم:** resolverهای ایرانی ممکن است کند باشند

**راه‌حل:**

</div>

```bash
# اول لیست جدید بگیرید:
findns fetch -o resolvers.txt --local

# یا با resolverهای داخلی:
findns local -o resolvers.txt

# تایم‌اوت بیشتر بدید:
findns scan -i resolvers.txt -o results.json -t 5

# تست دستی یک resolver:
dig google.com @8.8.8.8

# اگر dig هم جواب نداد = پورت 53 بلاک شده
# → از DoH استفاده کنید (بخش 7.5)
```

<div dir="rtl">

---

### 7.3. nxdomain - خیلی‌ها فیل شدند

> **علامت:** تعداد زیادی resolver در مرحله nxdomain فیل می‌شوند

**معنی:** resolverهایی که nxdomain فیل می‌شوند، DNS hijacking انجام می‌دهند — برای دامنه‌های ناموجود جواب جعلی برمی‌گردانند. این resolverها **واقعاً مشکل‌دار هستند** و باید فیلتر شوند.

**اگر نمی‌خواهید فیلتر شوند:**

</div>

```bash
# رد کردن مرحله nxdomain:
findns scan -i resolvers.txt -o results.json --skip-nxdomain
```

<div dir="rtl">

> **هشدار:** resolverهایی که hijack می‌کنند ممکن است ترافیک تانل را هم دستکاری کنند. فقط اگر واقعاً مطمئنید رد کنید.

---

### 7.4. e2e - تست واقعی تانل فیل شد (0%)

> **علامت:** مرحله e2e/dnstt یا e2e/slipstream گزارش 0% pass rate می‌دهد

این مرحله واقعاً یک تانل باز می‌کند، پس نیاز به تنظیمات بیشتری دارد. **هر ۷ مورد زیر را به ترتیب چک کنید:**

**۱. باینری پیدا نشد؟**

</div>

```bash
# بررسی:
which dnstt-client       # برای DNSTT
which slipstream-client  # برای Slipstream
which curl               # برای هر دو

# اگر نیست، نصب کنید (بخش 1 را ببینید)
# یا باینری را در همان فولدر findns بگذارید
```

<div dir="rtl">

**۲. اشتباه گرفتن pubkey و cert:**

</div>

```bash
# ❌ اشتباه: استفاده از pubkey برای Slipstream
findns e2e slipstream --domain s.example.com --pubkey abc123...

# ✅ درست: DNSTT از --pubkey استفاده می‌کند
findns e2e dnstt --domain t.example.com --pubkey abc123...

# ✅ درست: Slipstream از --cert استفاده می‌کند
findns e2e slipstream --domain s.example.com --cert /path/to/cert.pem
```

<div dir="rtl">

**۳. سرور تانل روشن نیست:**

</div>

```bash
# روی سرور چک کنید:
ss -ulnp | grep :53

# باید dnstt-server یا slipstream-server را ببینید
# اگر پروسه دیگری (مثل dnstm, systemd-resolved, bind) هست:
# → بخش 3.6 عیب‌یابی را بخوانید
```

<div dir="rtl">

**۴. تایم‌اوت e2e کم است:**

</div>

```bash
# پیش‌فرض 10 ثانیه — برای شبکه کند بیشتر کنید:
findns scan -i resolvers.txt -o results.json \
  --domain t.example.com --pubkey abc123... --e2e-timeout 20
```

<div dir="rtl">

**۵. pubkey اشتباه:**
- pubkey باید دقیقاً همان کلیدی باشد که سرور DNSTT با آن اجرا شده
- اگر pubkey اشتباه باشد، dnstt-client بدون پیام خطا فیل می‌شود

**۶. تست دستی:**

</div>

```bash
# یک resolver را دستی تست کنید:
dnstt-client -udp 8.8.8.8:53 -pubkey YOUR_KEY t.example.com 127.0.0.1:1080 &

# صبر کنید 3 ثانیه، بعد:
curl -x socks5h://127.0.0.1:1080 https://httpbin.org/ip

# اگر جواب آمد = تانل کار می‌کند
# اگر timeout شد = مشکل از سرور یا resolver
kill %1
```

<div dir="rtl">

**۷. پورت‌ها در تداخل:**
- findns از پورت‌های 30000 به بالا برای تست استفاده می‌کند
- اگر سرویس دیگری این پورت‌ها را گرفته، تست فیل می‌شود
- با `--port-base` پورت شروع را تغییر دهید (فقط در chain)

---

### 7.5. DoH - اسکن DoH resolver ها

> **DoH چیست؟** DNS over HTTPS — از پورت 443 (HTTPS) استفاده می‌کند نه پورت 53. ISP نمی‌تواند آن را intercept کند.

> **چه وقت DoH لازم است؟** وقتی اسکن معمولی (UDP) کار نمی‌کند چون ISP پورت 53 را بلاک کرده. اگر `dig @8.8.8.8 google.com` جواب نمی‌دهد ولی `curl https://google.com` کار می‌کند → از DoH استفاده کنید.

**سه تفاوت مهم با اسکن عادی:**

| | اسکن عادی (UDP) | اسکن DoH |
|---|---|---|
| **ورودی** | فایل آی‌پی: `8.8.8.8` | فایل URL: `https://dns.google/dns-query` |
| **فلگ اضافی** | ندارد | `--doh` الزامی |
| **دریافت لیست** | `findns fetch -o list.txt` | `findns fetch -o list.txt --doh` |

**شروع سریع:**

</div>

```bash
# لیست resolver DoH بگیرید:
findns fetch -o doh-resolvers.txt --doh

# اسکن ساده:
findns scan -i doh-resolvers.txt -o doh-results.json --doh

# اسکن با دامنه تانل:
findns scan -i doh-resolvers.txt -o doh-results.json --doh \
  --domain t.example.com

# اسکن کامل با e2e:
findns scan -i doh-resolvers.txt -o doh-results.json --doh \
  --domain t.example.com --pubkey abc123...
```

<div dir="rtl">

**عیب‌یابی DoH:**

| مشکل | علت | راه‌حل |
|------|-----|--------|
| doh/resolve همه فیل شد (0%) | لیست resolver خراب | `findns fetch -o doh.txt --doh` دوباره بگیرید |
| doh/resolve/tunnel همه فیل شد (0%) | NS delegation اشتباه | بخش 3.6 را بخوانید — همان تنظیمات DNS لازم است |
| doh/e2e همه فیل شد (0%) | سرور تانل خاموش | `ss -ulnp \| grep :53` روی سرور چک کنید |
| فایل ورودی قبول نمی‌شود | فرمت اشتباه | هر خط باید URL کامل باشد: `https://dns.google/dns-query` |
| `--doh` فراموش شده | findns فکر می‌کند URLها آی‌پی هستند و skip می‌کند | حتماً `--doh` اضافه کنید |

> **مهم:** تنظیمات DNS (بخش 3.6) برای DoH هم لازم است! فرقی نمی‌کند resolver UDP باشد یا DoH — NS delegation و سرور تانل باید درست تنظیم شده باشند.

**فرمت فایل ورودی DoH:**

</div>

```
# هر خط یک URL DoH resolver:
https://dns.google/dns-query
https://cloudflare-dns.com/dns-query
https://dns.quad9.net/dns-query
```

<div dir="rtl">

> **چه وقت DoH بهتر است؟**
> - وقتی ISP پورت 53 را intercept می‌کند (رایج در ایران)
> - وقتی resolve معمولی 0% می‌دهد ولی اینترنت کار می‌کند
> - وقتی `dig @8.8.8.8 google.com` جواب نمی‌دهد ولی `curl https://google.com` کار می‌کند

---

### 7.6. خلاصه سریع عیب‌یابی

> **ابتدا اینجا نگاه کنید** — مرحله‌ای که فیل شده را پیدا کنید و راهنمای سریع را دنبال کنید:

| مرحله | 0% شد؟ چرا؟ | اولین قدم | بخش راهنما |
|-------|-------------|-----------|-----------|
| ping | ICMP بلاک شده | `--skip-ping` استفاده کنید | [7.1](#71-ping---همه-فیل-شدند-0) |
| resolve | پورت 53 بلاک یا لیست خراب | `dig google.com @8.8.8.8` تست کنید | [7.2](#72-resolve---همه-فیل-شدند-0) |
| nxdomain | resolverها hijack می‌کنند | طبیعی‌ست — فیلتر درست کار می‌کند | [7.3](#73-nxdomain---خیلیها-فیل-شدند) |
| edns | resolver قدیمی | طبیعی‌ست — EDNS پشتیبانی نمی‌شود | — |
| resolve/tunnel | DNS delegation اشتباه | `curl` تست DoH بخش 3.6 | [3.6 عیب‌یابی](#عیبیابی-nxdomain-با-وجود-تنظیم-صحیح) |
| e2e/dnstt | سرور یا باینری یا pubkey | چک‌لیست ۷ مرحله‌ای | [7.4](#74-e2e---تست-واقعی-تانل-فیل-شد-0) |
| e2e/slipstream | سرور یا باینری یا cert | چک‌لیست ۷ مرحله‌ای | [7.4](#74-e2e---تست-واقعی-تانل-فیل-شد-0) |
| doh/resolve | لیست DoH خراب یا `--doh` فراموش شده | `findns fetch --doh` دوباره بگیرید | [7.5](#75-doh---اسکن-doh-resolver-ها) |
| doh/e2e | ترکیب مشکلات DoH + e2e | هر دو بخش را چک کنید | [7.4](#74-e2e---تست-واقعی-تانل-فیل-شد-0) + [7.5](#75-doh---اسکن-doh-resolver-ها) |

---

## ⚙️ فلگ‌های عمومی

این فلگ‌ها روی همه دستورات کار می‌کنند:

| فلگ | مخفف | توضیح | پیش‌فرض |
|-----|------|-------|---------|
| `--input` | `-i` | فایل ورودی (متنی یا JSON) | الزامی |
| `--output` | `-o` | فایل خروجی JSON | الزامی |
| `--timeout` | `-t` | تایم‌اوت هر تلاش (ثانیه) | `3` |
| `--count` | `-c` | تعداد تلاش برای هر IP | `3` |
| `--workers` | — | تعداد workerهای موازی | `50` |
| `--e2e-timeout` | — | تایم‌اوت تست‌های e2e (ثانیه) | `10` |
| `--include-failed` | — | IPهای فیل‌شده از ورودی JSON را هم اسکن کن | `false` |

**تنظیم workers:**
- سرور ضعیف یا اینترنت کند: `--workers 20`
- سرور قوی: `--workers 100`
- پیش‌فرض 50 برای اکثر سرورها مناسب است

**تنظیم timeout:**
- شبکه ایران (resolverهای کند): `-t 5`
- سرور خارجی (پاسخ سریع): `-t 2`

---

## 8. فرمت ورودی و خروجی

### ورودی (Input)

**حالت 1: فایل متنی ساده** (یک آی‌پی، رنج CIDR، یا URL در هر خط)

</div>

```
8.8.8.8
1.1.1.1
9.9.9.9
8.8.8.8           # تکراری — به صورت خودکار حذف می‌شود
1.1.1.1 # کامنت اینلاین — حذف می‌شود و فقط آی‌پی استفاده می‌شود
# این یک کامنت است (نادیده گرفته می‌شود)

# رنج CIDR (به صورت خودکار باز می‌شود)
185.51.200.0/24
10.202.10.0/28
```

<div dir="rtl">

**حذف تکراری‌ها:** آی‌پی‌های تکراری به صورت خودکار حذف می‌شوند و تعداد تکراری‌ها در stderr گزارش می‌شود. **کامنت اینلاین:** هر چیزی بعد از ` #` (فاصله + #) از انتهای خط حذف می‌شود.

**پشتیبانی از CIDR:** رنج‌هایی مثل `1.2.3.0/24` به صورت خودکار به آی‌پی‌های تکی تبدیل می‌شوند (آدرس شبکه و broadcast حذف می‌شوند). این قابلیت برای اسکن بلوک‌های آی‌پی منطقه‌ای (مثل فایل‌های `iran-ipv4.cidrs`) بسیار مفید است. اگر تعداد آی‌پی‌ها بیش از 100,000 باشد هشدار نمایش داده می‌شود.

برای DoH:

</div>

```
https://dns.google/dns-query
https://cloudflare-dns.com/dns-query
```

<div dir="rtl">

**حالت 2: خروجی JSON از اسکن قبلی**

خروجی هر اسکن می‌تواند ورودی اسکن بعدی باشد! به صورت پیش‌فرض فقط IPهای passed (موفق) استفاده می‌شوند. با فلگ `--include-failed` همه IPها دوباره تست می‌شوند.

</div>

```bash
findns ping -i resolvers.txt -o step1.json
findns resolve -i step1.json -o step2.json --domain google.com
```

<div dir="rtl">

### خروجی (Output)

فایل JSON با این ساختار:

</div>

```json
{
  "steps": [
    {
      "name": "ping",
      "tested": 25616,
      "passed": 20480,
      "failed": 5136,
      "duration_secs": 45.2
    }
  ],
  "passed": [
    {
      "ip": "1.1.1.1",
      "metrics": {
        "ping_ms": 4.2,
        "resolve_ms": 15.3,
        "edns_max": 1232,
        "nxdomain_ok": 3,
        "hijack": 0
      }
    }
  ],
  "failed": [
    {"ip": "9.9.9.9"}
  ]
}
```

<div dir="rtl">

- **steps:** خلاصه هر مرحله (چند تا تست شد، چند تا پاس شد)
- **passed:** لیست resolverهای موفق با متریک‌ها (مرتب شده بر اساس عملکرد)
- **failed:** لیست resolverهای ناموفق

---

## 9. سناریوهای عملی

### سناریو 1: پیدا کردن بهترین resolver UDP برای DNSTT

</div>

```bash
# مرحله 1 - دانلود resolverها (با لیست ایران)
findns fetch -o resolvers.txt --local

# مرحله 2 - اسکن کامل
findns scan -i resolvers.txt -o results.json --domain t.mysite.com

# مرحله 3 - استفاده در dnstt-client
dnstt-client -udp BEST_IP:53 -pubkey-file server.pub t.mysite.com 127.0.0.1:1080
```

<div dir="rtl">

نتایج به صورت TUI نمایش داده می‌شود و در results.json ذخیره می‌شود. اولین IP در لیست passed بهترین resolver است.

### سناریو 2: پیدا کردن resolver DoH برای DNSTT

</div>

```bash
# مرحله 1 - دانلود لیست DoH
findns fetch -o doh.txt --doh

# مرحله 2 - اسکن DoH
findns scan -i doh.txt -o doh-results.json --domain t.mysite.com --doh

# مرحله 3 - استفاده
dnstt-client -doh BEST_URL -pubkey-file server.pub t.mysite.com 127.0.0.1:1080
```

<div dir="rtl">

### سناریو 3: اسکن سریع (فقط ping + resolve)

</div>

```bash
findns scan -i resolvers.txt -o results.json --skip-nxdomain
```

<div dir="rtl">

### سناریو 4: اسکن وقتی ICMP مسدود است

</div>

```bash
findns scan -i resolvers.txt -o results.json \
  --domain t.mysite.com --skip-ping
```

<div dir="rtl">

### سناریو 5: فیلتر چندمرحله‌ای با chain

</div>

```bash
findns chain -i resolvers.txt -o results.json \
  --step "ping:count=1" \
  --step "resolve:domain=google.com,count=1" \
  --step "nxdomain:count=2" \
  --step "edns:domain=t.mysite.com" \
  --step "resolve/tunnel:domain=t.mysite.com"
```

<div dir="rtl">

مزیت: مرحله اول (`ping:count=1`) خیلی سریع فیلتر می‌کند و مراحل بعدی فقط روی resolverهای زنده اجرا می‌شوند.

### سناریو 6: استفاده از خروجی یک اسکن در اسکن بعدی

</div>

```bash
# مرحله 1 - فقط ping
findns ping -i resolvers.txt -o alive.json

# مرحله 2 - resolve فقط روی resolverهای زنده
findns resolve -i alive.json -o resolved.json --domain google.com

# مرحله 3 - nxdomain فقط روی resolverهای کارآمد
findns nxdomain -i resolved.json -o clean.json
```

<div dir="rtl">

هر مرحله فقط IPهای "passed" از مرحله قبل را تست می‌کند.

### سناریو 7: اسکن با فایل CIDR (مثل iran-ipv4.cidrs)

اگر فایلی دارید که رنج آی‌پی‌ها را به صورت CIDR دارد (مثل `iran-ipv4.cidrs`)، findns مستقیم آن را می‌خواند — نیازی به تبدیل نیست.

**نمونه فایل CIDR:**

</div>

```
# iran-ipv4.cidrs
5.22.0.0/17
5.34.192.0/20
5.42.217.0/24
5.52.0.0/16
185.51.200.0/22
```

<div dir="rtl">

**اسکن مستقیم:**

</div>

```bash
findns scan -i iran-ipv4.cidrs -o results.json --domain t.mysite.com
```

<div dir="rtl">

findns به صورت خودکار:
1. هر رنج CIDR را به آی‌پی‌های تکی تبدیل می‌کند (مثلاً `/24` = 254 آی‌پی)
2. آدرس شبکه و broadcast را حذف می‌کند
3. تعداد رنج‌ها و آی‌پی‌های expand شده را نشان می‌دهد
4. اگر بیش از 100,000 آی‌پی باشد هشدار می‌دهد

**ترکیب CIDR با آی‌پی‌های تکی:** می‌توانید در یک فایل هم رنج CIDR و هم آی‌پی تکی داشته باشید:

</div>

```
# آی‌پی‌های تکی
8.8.8.8
1.1.1.1

# رنج‌های CIDR
185.51.200.0/24
10.202.10.0/28
```

<div dir="rtl">

> **نکته:** فایل‌های `.cidrs` فرمت خاصی ندارند — همان فایل متنی ساده هستند. findns هر خطی که `/` داشته باشد را به عنوان CIDR تشخیص می‌دهد. خطوط خالی و خطوطی که با `#` شروع شوند نادیده گرفته می‌شوند.

### سناریو 8: تست فقط resolverهای ایرانی

</div>

```bash
echo "10.202.10.10" > my-resolvers.txt
echo "10.202.10.11" >> my-resolvers.txt
echo "85.15.1.14" >> my-resolvers.txt

findns scan -i my-resolvers.txt -o results.json --domain t.mysite.com
```

<div dir="rtl">

### سناریو 9: تست با تعداد worker کمتر (سرور ضعیف)

</div>

```bash
findns scan -i resolvers.txt -o results.json \
  --domain t.mysite.com --workers 10 -t 5
```

<div dir="rtl">

---

## 10. نکات و ترفندها

**نکته 1: سرعت اسکن**
25,000 resolver با 50 worker حدود 5-15 دقیقه طول می‌کشد (بسته به شبکه). با `--workers 100` سریع‌تر می‌شود اما بار بیشتری روی سرور می‌گذارد.

**نکته 2: مرتب‌سازی نتایج**
نتایج بر اساس آخرین مرحله مرتب می‌شوند:
- اگر آخرین مرحله edns باشد: بر اساس `edns_max`
- اگر آخرین مرحله resolve/tunnel باشد: بر اساس `resolve_ms`
- اگر آخرین مرحله e2e باشد: بر اساس `e2e_ms`

**نکته 3: کجا اجرا کنیم؟**
بهترین جا یک سرور VPS است (نه کامپیوتر شخصی). چون سرور اینترنت پایدار و سریع دارد. می‌توانید روی همان سروری که DNSTT server دارید اجرا کنید.

**نکته 4: --top**
به صورت پیش‌فرض 10 نتیجه برتر در ترمینال نمایش داده می‌شود. برای دیدن بیشتر: `findns scan ... --top 50`. تمام نتایج همیشه در فایل JSON ذخیره می‌شوند.

**نکته 5: edns_max چقدر مهم است؟**
- `512`: حداقل (تانل کند)
- `900`: خوب
- `1232`: عالی (سریع‌ترین تانل)

resolverهایی با `edns_max=1232` بهترین انتخاب هستند.

**نکته 6: هایجک چیست و چرا مهم است؟**
بعضی ISPها و resolverها وقتی دامنه‌ای وجود ندارد، به جای NXDOMAIN شما را به صفحه تبلیغاتی یا صفحه خطای خودشان هدایت می‌کنند. این resolverها ممکن است تانل DNS را خراب کنند.

**نکته 7: فرق scan و chain**
- `scan`: خودکار مراحل را تنظیم می‌کند. ساده‌تر است.
- `chain`: شما مراحل را دستی تعریف می‌کنید. انعطاف بیشتر.

برای اکثر کاربران scan کافی است.

**نکته 8: اگر خطای "permission denied" گرفتید**
ping نیاز به دسترسی خاص دارد: `sudo findns scan ...` یا از `--skip-ping` استفاده کنید.

**نکته 9: اگر هیچ resolver پاس نشد**
- timeout را افزایش دهید: `-t 5` یا `-t 10`
- count را کم کنید: `-c 1`
- `--skip-nxdomain` امتحان کنید
- `--skip-ping` امتحان کنید
- مطمئن شوید دامنه تانل درست تنظیم شده (NS record)

**نکته 10: DoH یا UDP؟**

| | UDP (پورت 53) | DoH (پورت 443) |
|---|---|---|
| سرعت | سریع‌تر | کندتر |
| تعداد resolver | بیشتر | کمتر |
| قابل شناسایی | بله (DPI) | سخت (شبیه HTTPS) |
| مسدود شدن | ممکن | سخت‌تر |

> پیشنهاد: اول UDP امتحان کنید. اگر کار نکرد، DoH بزنید.

</div>
