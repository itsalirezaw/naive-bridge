# نگهداری NaiveBridge

## فرمان‌ها

```bash
naive-bridge status
naive-bridge doctor
naive-bridge panel
naive-bridge export fi1
naive-bridge add --file /root/fi1.code
naive-bridge add --replace --file /root/fi1.code
naive-bridge remove fi1
```

`export` فقط روی خارج است و کد محرمانه چاپ می‌کند. `add --replace` کد جدید همان نود را با حفظ اولویت و پورت محلی جایگزین می‌کند. فایل کد را با مجوز `600` نگه دارید. `remove` فقط نود را از ایران حذف می‌کند؛ سرویس خارج همچنان وجود دارد. پس از حذف نود، outbound و قوانین وابسته به آن را در پنل هم اصلاح کنید.

```bash
naive-bridge restart
naive-bridge stop
naive-bridge start
```

این فرمان‌ها فقط سرویس‌های پیکربندی‌شدهٔ NaiveBridge همین میزبان را کنترل می‌کنند. `stop` اتصال‌های فعال را قطع می‌کند و توقف موقت است؛ سرویس‌های enabled پس از reboot دوباره اجرا می‌شوند.

## نام سرویس‌ها

ایران: `naive-bridge-router`، `naive-bridge-watch` و `naive-bridge-naive-fi1` برای هر نود.

خارج: `naive-bridge-https-fi1` و `naive-bridge-exit-fi1`؛ به‌جای `fi1` نام واقعی نود را بگذارید.

```bash
journalctl -u naive-bridge-router -u naive-bridge-watch -n 50 --no-pager
journalctl -u naive-bridge-https-fi1 -u naive-bridge-exit-fi1 -n 50 --no-pager
```

هیچ فایل JSON تنظیمات، کد اتصال یا log حاوی اطلاعات شخصی را در issue عمومی کپی نکنید. گزارش مفید شامل نسخه، توزیع Linux، خطای بدون اطلاعات محرمانه و نتیجهٔ `doctor` است.

## پورت اشغال یا وب‌سرور موجود

نصب ساده به پورت HTTPS آزاد نیاز دارد. منو از ۴۴۳ شروع می‌کند و اولین پورت آزاد را پیشنهاد می‌دهد؛ Enter آن را می‌پذیرد. پورت XHTTP داخلی نیز از بازهٔ `20300–20399` خودکار انتخاب می‌شود؛ در فرمان پیشرفته با `--backend` قابل‌تغییر است. اشغال پورت داخلی ۲۰۳۰۰ دیگر به‌تنهایی باعث توقف نصب نمی‌شود. پورت‌های ایران: `20080` و `20085`، بازهٔ `20100–20163` و `20200–20231`.

اگر nginx شما از قبل TLS را با **stream و ssl_preread** تقسیم می‌کند، می‌توانید نود را پشت آن بسازید:

```bash
naive-bridge outside --id fi1 --address 203.0.113.5 \
  --domain node.example.com --port 443 --listen-port 24444 \
  --backend 20300 --proxy-protocol \
  --cert /etc/letsencrypt/live/node.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/node.example.com/privkey.pem
```

این یک نمونه با مقادیر جایگزین است. در **map موجود** nginx، دامنه را به `127.0.0.1:24444` متصل کنید؛ listener عمومی nginx باید `proxy_protocol on` داشته باشد. listener خصوصی فقط loopback و PROXY header معتبر از loopback می‌پذیرد. از تنظیمات nginx پشتیبان بگیرید، `nginx -t` بزنید و سپس reload کنید.

این روش با reverse proxy معمولی HTTP nginx یکسان نیست: Naive به عبور صحیح CONNECT نیاز دارد. فایل nginx به‌طور خودکار بازنویسی نمی‌شود. `--listen-port` به‌تنهایی listener را خصوصی نمی‌کند؛ برای این الگو `--proxy-protocol` هم لازم است.

## گواهی

منو گواهی‌های موجود در `/etc/letsencrypt/live` را از نظر نام دامنه، باقی‌ماندن حداقل ۲۴ ساعت اعتبار و تطبیق کلید بررسی می‌کند و مسیر منطبق را پیش‌فرض قرار می‌دهد. Enter مسیر پیشنهادی را می‌پذیرد. اگر گواهی پیدا نشد، پیش‌فرض `auto` است؛ مسیر فایل گواهی دیگر را هم می‌توان دستی وارد کرد. گواهی دارای کلید رمزدار یا مسیر داخل `/root`، `/home` و `/run/user` برای این سرویس پذیرفته نمی‌شود.

گزینهٔ `auto` با certbot standalone گواهی می‌گیرد و پورت ۸۰ باید برای تمدید هم قابل‌دسترسی باقی بماند. نصب‌کنندهٔ بستهٔ certbot توزیع معمولاً زمان‌بندی تمدید را فراهم می‌کند؛ وضعیت timer/cron را روی میزبان بررسی کنید. با `certbot renew --dry-run` اعتبار تمدید را بررسی کنید.

برای مسیرهای `/etc/letsencrypt/`، hook تمدید متعلق به نود ایجاد می‌شود و پس از تمدید، سرویس HTTPS آن نود را restart می‌کند. مسیر `live` حفظ می‌شود تا گواهی جدید خوانده شود. restart اتصال‌های فعال همان نود را قطع می‌کند. برای صادرکنندهٔ دیگری، hook معادل لازم است.

## توقف دائمی و بازگشت

ابتدا قانون کاربران در پنل را به خروجی موردنظر قبلی برگردانید؛ سپس روی ایران:

```bash
systemctl disable --now naive-bridge-watch naive-bridge-router naive-bridge-naive-fi1
```

برای هر نود اضافی سرویس Naive آن را هم غیرفعال کنید. روی خارج:

```bash
systemctl disable --now naive-bridge-https-fi1 naive-bridge-exit-fi1
```

اگر hook گواهی `/etc/letsencrypt/renewal-hooks/deploy/naive-bridge-fi1` وجود دارد، برای توقف دائمی آن را نیز غیرفعال کنید تا تمدید گواهی سرویس را دوباره روشن نکند. گواهی‌ها، پشتیبان پنل و دادهٔ کاربران به‌صورت خودکار حذف نمی‌شوند. نسخهٔ اول حذف کامل خودکار ندارد.

## نصب مجدد و نسخهٔ آزمایشی قبلی

نصب مجدد با همان موتورهای انتقال، تنظیمات را حفظ می‌کند. جایگزینی خودکار موتور با نسخهٔ متفاوت فعلاً انجام نمی‌شود؛ قبل از تغییر نسخه، پنجرهٔ نگهداری و نسخهٔ پشتیبان لازم است. نصب مجدد مدیر، سرویس در حال اجرا را خودکار restart نمی‌کند؛ برای اعمال تغییرات مدیر، از `naive-bridge restart` استفاده کنید.

نسخهٔ داخلی قدیمی با نام `web-bridge` مسیرها و سرویس‌های جدا دارد. نصب NaiveBridge آن را مهاجرت یا متوقف نمی‌کند، اما پورت‌های مسیریاب هر دو مشترک‌اند؛ آن‌ها را هم‌زمان روی ایران راه‌اندازی نکنید. مهاجرت عملی نیازمند توقف مدیر/مسیریاب قبلی، افزودن کد نود و به‌روزرسانی تگ خروجی پنل در زمان نگهداری است. گواهی و تنظیمات قبلی را حفظ کنید.

[راهنمای نصب](../README.fa.md) · [راهنمای پنل](panels.fa.md)
