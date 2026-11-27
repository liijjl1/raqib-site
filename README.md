# رقيب — الموقع الكامل (Python + Flask)

موقع ويب لبحث التخرج **Machine Learning-Based Anomaly Detection in IoT**.

- **صفحات تعريفية:** الرئيسية، وعن البحث، والفريق والمشرف، والمراجع.
- **حسابات:** تسجيل وتسجيل دخول، وكلمات المرور محفوظة مشفّرة. أول حساب يُنشأ يصبح **مدير** الموقع، وما بعده **محلل**.
- **قاعدة بيانات SQLite:** فيها المستخدمون، وكل حادثة تُغلق في المراقبة الحية، وتقارير الملفات التي تحللها، ومعلومات المشروع.
- **النظام:**
  - المراقبة الحية لاثني عشر جهازاً مع محاكي هجمات.
  - المختبر.
  - تحليل ملفات CSV حقيقية.
  - سجل الحوادث.
  - التقارير المحفوظة.
  - صفحة الإدارة.

---

## 1) التشغيل على حاسوبك (ويندوز)

```
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

بعدها افتح المتصفح على **http://127.0.0.1:5000**.

- في أول تشغيل يدرّب الموقع النماذج الثلاثة ويحفظها في المجلد `instance`، ويأخذ ذلك نحو 20 ثانية.
- في المرات التالية يبدأ خلال ثوانٍ.
- بعد التشغيل اضغط **حساب جديد**، فيصبح حسابك هو المدير.

---

## 2) النشر على الإنترنت مجاناً (PythonAnywhere)

ستحصل على رابط مثل `https://اسمك.pythonanywhere.com`.

1. **أنشئ حساباً مجانياً** في موقع pythonanywhere.com (خطة Beginner). اسم المستخدم سيكون جزءاً من الرابط.

2. **ارفع المشروع:**
   - من تبويب **Files** ارفع الملف `raqib-site.zip`.
   - افتح **Bash console** من تبويب Consoles، واكتب:

   ```
   unzip raqib-site.zip
   cd raqib-site
   python3.12 -c "import flask, sklearn, pandas, matplotlib, joblib; print('OK')"
   ```

   إذا ظهرت `OK` فالمكتبات موجودة أصلاً، ولا تحتاج تثبيت شيء.
   إذا ظهر خطأ فثبّت المكتبات الناقصة بهذا الأمر:

   ```
   pip3.12 install --user -r requirements.txt
   ```

3. **أنشئ تطبيق الويب:**
   - من تبويب **Web** اضغط **Add a new web app**، ثم **Next**.
   - اختر **Manual configuration**، وليس Flask.
   - اختر نفس إصدار بايثون الذي جربته في الخطوة 2 (مثل Python 3.12).

4. **اربط الملفات** في صفحة تطبيق الويب:
   - في **Source code** و **Working directory** اكتب `/home/اسمك/raqib-site`.
   - في قسم **Static files** أضف سطراً جديداً:
     - URL: `/static/`
     - Directory: `/home/اسمك/raqib-site/static`

5. **عدّل ملف WSGI:**
   - اضغط رابط **WSGI configuration file**.
   - امسح كل ما فيه، وضع محتوى الملف `wsgi_pythonanywhere.py` الموجود في المشروع.
   - غيّر `YOUR_USERNAME` إلى اسم المستخدم في PythonAnywhere.
   - اضغط Save.

6. **شغّل الموقع:**
   - اضغط زر **Reload** الأخضر، ثم افتح الرابط.
   - أول فتح يأخذ نحو دقيقة، لأن الموقع يدرّب النماذج مرة واحدة ثم يحفظها.

7. **أنشئ حسابك أولاً** حتى تكون أنت المدير. بعدها:
   - من صفحة **الإدارة** اكتب اسم المشرف وأسماء الفريق.
   - شارك الرابط مع المشرف واللجنة.

### ملاحظات عن الخطة المجانية

- تطبيق الويب المجاني يتوقف بعد شهر. لتمديده، ادخل إلى تبويب **Web** واضغط الزر الذي يمدّد التشغيل شهراً آخر، قبل المناقشة بوقت كافٍ.
- PythonAnywhere لا يسمح بتشغيل خيوط (threads) داخل مواقع الويب. لذلك:
  - المراقبة الحية في هذا الإصدار تتقدم مع كل تحديث للصفحة، ولا تعمل في الخلفية.
  - النماذج تعمل على نواة واحدة.
- إذا ظهر خطأ، افتح **Error log** من تبويب Web، وستجد فيه سبب المشكلة.
- البيانات كلها في المجلد `instance`:
  - `raqib.db` قاعدة البيانات.
  - `lab_models.joblib` النماذج المدرَّبة.
  - `secret_key` مفتاح الجلسات. لا تشاركه مع أحد.
- لإعادة تدريب النماذج: احذف `instance/lab_models.joblib` ثم اضغط Reload.

---

## هيكل المشروع

```
app.py                     الصفحات والعناوين والحسابات (Flask)
wsgi_pythonanywhere.py     ملف الربط مع PythonAnywhere
raqib/traffic.py           محاكي حركة الأجهزة والهجمات
raqib/models.py            تجهيز البيانات والنماذج الثلاثة ودرجة الخطر
raqib/experiment.py        التدريب والتقييم والأشكال وقراءة CSV وحفظ النماذج
raqib/monitor.py           المراقبة الحية والحوادث (بدون خيوط)
raqib/database.py          قاعدة البيانات SQLite: المستخدمون والحوادث والتقارير والإعدادات
raqib/auth.py              تسجيل الدخول والصلاحيات وحماية النماذج (CSRF)
raqib/content.py           معلومات المشروع الافتراضية والمراجع
templates/                 صفحات HTML
static/                    التنسيق وملف JavaScript الصغير، والأشكال في static/reports
docs/                      النموذج التجريبي الذي يعمل داخل المتصفح (GitHub Pages)
.gitignore                 الملفات التي لا تُرفع على GitHub
```

لطباعة جدول النتائج في الطرفية: `python -m raqib.experiment`

---

## 3) رفع المشروع على GitHub

الملف `.gitignore` يمنع رفع المجلد `instance` (مفتاح الجلسات وقاعدة البيانات والنماذج المدرّبة) والمجلد `static/reports` والبيئة `.venv`. لا تحذفه.

**مرة واحدة فقط:**

1. ثبّت Git for Windows من git-scm.com واترك الخيارات الافتراضية، ثم أعد فتح VS Code.
2. عرّف Git باسمك وبريدك (نفس بريد حساب GitHub):

   ```
   git config --global user.name "Your Name"
   git config --global user.email "you@example.com"
   ```

3. في github.com اضغط **+** ثم **New repository**:
   - Repository name: `raqib-site`
   - اختر **Public** (ضروري لـ GitHub Pages في الحساب المجاني).
   - لا تضع علامة على Add a README ولا .gitignore ولا license، لأنها موجودة في المشروع.
   - اضغط **Create repository**.

**الرفع:** افتح في VS Code المجلد الذي فيه `app.py` (File ثم Open Folder)، ثم افتح Terminal واكتب:

```
git init
git add .
git status
git commit -m "Raqib: IoT anomaly detection website"
git branch -M main
git remote add origin https://github.com/USERNAME/raqib-site.git
git push -u origin main
```

- غيّر `USERNAME` إلى اسم حسابك في GitHub.
- تأكد في نتيجة `git status` أن `instance/` غير موجود في القائمة.
- أول `git push` يفتح نافذة تسجيل دخول GitHub في المتصفح. وافق عليها مرة واحدة.

**كل تعديل بعد ذلك:**

```
git add .
git commit -m "Describe your change"
git push
```

### النموذج التجريبي على GitHub Pages

المجلد `docs` فيه النسخة التجريبية التي تعمل داخل المتصفح. لتحصل على رابط عام يفتح من أي موبايل:

1. في صفحة المستودع: **Settings** ثم **Pages**.
2. في **Source** اختر **Deploy from a branch**.
3. في **Branch** اختر `main` والمجلد `/docs`، ثم **Save**.
4. بعد دقائق يصبح الرابط: `https://USERNAME.github.io/raqib-site/` (اسم الحساب بحروف صغيرة).

### الرفع من الموبايل (بدون حاسبة)

صفحة GitHub في متصفح الموبايل ترفع ملفات منفردة فقط، ولا ترفع المجلدات. لذلك ترفع الملف المضغوط كما هو، والملف `.github/workflows/unzip.yml` يفكّه داخل المستودع تلقائياً:

1. أنشئ المستودع `raqib-site` (Public، بدون README).
2. في صفحة المستودع الفارغ اضغط **creating a new file**، واكتب في اسم الملف `.github/workflows/unzip.yml`، والصق محتوى الملف نفسه من هذا المشروع، ثم **Commit changes**.
3. **Add file** ثم **Upload files**، واختر `raqib-site.zip`، ثم **Commit changes**.
4. من تبويب **Actions** انتظر العلامة الخضراء على التشغيل الجديد، ثم ارجع إلى **Code**: ستجد الملفات بدل الملف المضغوط.
5. فعّل GitHub Pages كما في القسم السابق.

لتحديث المشروع لاحقاً من الموبايل: ارفع ملفاً مضغوطاً جديداً بالطريقة نفسها، فيُفك فوق الملفات القديمة، ويُعاد بناء GitHub Pages تلقائياً.

### PythonAnywhere من GitHub (بدل رفع الملف المضغوط)

في **Bash console** على PythonAnywhere:

```
git clone https://github.com/USERNAME/raqib-site.git
```

ثم نفّذ أمر فحص المكتبات من الخطوة 2 في القسم 2 (بعد `cd raqib-site`)، وأكمل من الخطوة 3. وعندما تعدّل الكود وترفعه على GitHub، حدّث الموقع هكذا:

```
cd ~/raqib-site
git pull
```

ثم اضغط **Reload** من تبويب Web. قاعدة البيانات لا تتأثر، لأن `instance` خارج Git.
