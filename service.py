"""نقطة دخول الـ foreground service (python-for-android بيشغّل الملف ده في process منفصل).

الملف بيشتغل مباشرة (من غير `if __name__ == "__main__"`) لأن p4a بيشغّله كسكربت.
"""
import service_core

service_core.run()
