⚠️ للأغراض التعليمية فقط: استخدم الأداة على ترافيك حسابك وجهازك أنت. ممنوع الغش أو مخالفة شروط اللعبة. / Educational use only, on your own account and device.

# Packet Analyzer (Android / Kivy)

**حالة المشروع: لم يتم بناؤه أو تجربته على Kivy أو جهاز أندرويد حقيقي.** المنطق (الـ proxy، الخدمة، قراءة الملف) اتجرّب على الكمبيوتر بس. الواجهة ومشروع البناء ممكن يحتاجوا تعديلات بعد أول بناء.

## البناء (أسهل طريقة: GitHub Actions)
1. اعمل repo خاص على GitHub وارفع محتويات المجلد ده (فيه `.github/workflows/build.yml`).
2. تاب **Actions** ← **Build APK** ← Run workflow (أول بناء ~20-40 دقيقة).
3. نزّل الـ artifact `packet-analyzer-apk` وثبّت الـ APK (فعّل "تثبيت من مصادر غير معروفة").

أو على Linux: `pip install buildozer cython==0.29.36` ثم `buildozer -v android debug`.

لو البناء فشل ابعتلي آخر ~50 سطر من اللوج.

## الاستخدام
- Start يشغّل الخدمة (إشعار دائم). الـ proxy بيسمع على `127.0.0.1:1081` فقط.
- **لازم** توجّه ترافيك اللعبة للـ proxy ده بتطبيق تاني (التطبيق نفسه مش VPN).
- Settings: البورت، only/skip ports، KEY/IV يدوي (اختياري، بيتخزن في مجلد التطبيق الخاص).
- استثناء الـ battery optimization للتطبيق عشان الخدمة ما تتقتلش.
- كل الملفات في مجلد التطبيق الخاص (live.jsonl بيتدوّر عند 150MB).
- خط Kivy الافتراضي مبيعرضش حروف عربية، فالواجهة إنجليزي.
- AES مكتوب Pure-Python (أبطأ من pycryptodome لكن من غير مكتبات native).

## اختبار منطق الخدمة على الكمبيوتر
`python tests/test_logic.py`
