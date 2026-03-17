# فرمان‌های رایج

این صفحه کوتاه‌ترین مسیر برای کار روزمره با RayLimit را نشان می‌دهد.

## انتخاب پیشوند فرمان

اگر RayLimit را نصب کرده‌اید:

```bash
raylimit ...
```

اگر از سورس اجرا می‌کنید:

```bash
go run ./cmd/raylimit ...
./bin/raylimit ...
```

## کشف runtime ها

```bash
sudo raylimit discover
sudo raylimit discover --format json
```

## بررسی یک runtime

```bash
sudo raylimit inspect --pid 1234
sudo raylimit inspect --pid 1234 --format json
```

## پیش‌نمایش یک speed limiter

```bash
sudo raylimit limit --pid 1234 --uuid user-a --device eth0 --direction upload --rate 2048
```

حالت پیش‌فرض dry-run است. فقط وقتی `--execute` اضافه کنید که خروجی، مسیر concrete را نشان دهد.

## حذف محافظه‌کارانهٔ state

```bash
sudo raylimit limit --pid 1234 --ip 203.0.113.10 --device eth0 --direction upload --remove --execute
```

## نسخه و متادیتا

```bash
raylimit version
```

برای ادامه، از نوار کناری به بخش استفادهٔ عملی بروید.
