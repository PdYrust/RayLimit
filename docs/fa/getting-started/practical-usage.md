# استفادهٔ عملی

مدل کاری RayLimit ساده است: اول inspect، بعد preview، و فقط در صورت concrete بودن مسیر، اجرای واقعی.

## ترتیب پیشنهادی

1. runtime را پیدا کنید
2. runtime انتخاب‌شده را inspect کنید
3. speed limiter مورد نظر را در حالت dry-run اجرا کنید
4. observation و decision را بخوانید
5. فقط در صورت concrete بودن مسیر، `--execute` را اضافه کنید

## معنی `--direction`

RayLimit در هر بار اجرا فقط یک سمت از policy را اعمال می‌کند:

- `upload`
- `download`

اگر هر دو سمت را می‌خواهید، دو فرمان جدا اجرا کنید.

## مسیر نصب‌شده در برابر مسیر سورس

رفتار محصول یکی است. تفاوت فقط در نحوهٔ اجرای فرمان است:

- مسیر نصب‌شده: `raylimit`
- سورس مستقیم: `go run ./cmd/raylimit`
- بیلد محلی: `./bin/raylimit`

## چه چیزهایی امروز concrete هستند؟

- IP وقتی مسیر direct client-IP قابل استفاده باشد
- inbound وقتی یک TCP listener مشخص و خوانا برای tag انتخاب‌شده اثبات شود
- outbound وقتی یک socket mark یکتای غیرصفر و بدون proxy indirection اثبات شود
- UUID وقتی membership زنده با client IP یا socket tuple های exact-user قابل attach باشد

connection هنوز به‌صورت گسترده برای apply واقعی توسعه پیدا نکرده است. پایهٔ آن وجود دارد و توسعهٔ گسترده‌تر برای release های آینده برنامه‌ریزی شده است.

## blocked یعنی چه؟

blocked نتیجهٔ ایمنی است، نه صرفاً خطا. RayLimit وقتی evidence کافی و قابل‌اعتماد برای attach کردن ترافیک نداشته باشد، اجرای واقعی را متوقف می‌کند.
