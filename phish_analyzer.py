#!/usr/bin/env python3
"""
Tafila Technical University (TTU) - Faculty of ICT
Graduation Project: Adaptive Heuristic Behavioral Detection Engine (V2 - Live URL Scan)
Author: Mostafa Alkhwaja
"""

import os
import re
import requests  # المكتبة الجديدة لسحب الصفحات الحية من الإنترنت
from bs4 import BeautifulSoup

class HeuristicPhishAnalyzer:
    def __init__(self, target_source):
        self.target = target_source
        self.risk_score = 0
        self.alerts = []
        self.html_content = ""
        self.soup = None

    def load_document(self):
        # التحقق إذا كان الهدف رابط إنترنت يبدأ بـ http أو https
        if self.target.startswith("http://") or self.target.startswith("https://"):
            try:
                print(f"[*] جاري الاتصال بالرابط الحي وسحب كود الـ HTML: {self.target}")
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                response = requests.get(self.target, headers=headers, timeout=10)
                self.html_content = response.text
                self.soup = BeautifulSoup(self.html_content, 'html.parser')
                return True
            except Exception as e:
                print(f"[X] فشل الاتصال بالرابط: {e}")
                return False
        else:
            # إذا لم يكن رابطاً، يتعامل معه كملف محلي
            if not os.path.exists(self.target):
                return False
            with open(self.target, 'r', encoding='utf-8') as f:
                self.html_content = f.read()
            self.soup = BeautifulSoup(self.html_content, 'html.parser')
            return True

    def analyze_form_actions(self):
        """
        المعيار الأول: فحص وجهة البيانات (Form Destination)
        موقع فيسبوك الأصلي يرسل البيانات إلى رابط كامل يطابق النطاق الرسمي ومحمي بـ HTTPS.
        """
        forms = self.soup.find_all('form')
        for form in forms:
            action = form.get('action', '').strip()
            
            # إذا كان الرابط محلي أو نسبي في الأداة المزيفة (مثل login.php)
            if not action:
                self.risk_score += 20
                self.alerts.append("[!] وسم Form بدون وجهة محددة - سلوك مشبوه لجمع البيانات محلياً.")
            elif action.endswith('.php') or (not action.startswith('http') and '.php' in action):
                self.risk_score += 40
                self.alerts.append(f"[!] توجيه مباشر إلى ملف معالجة محلي: ({action}) - مؤشر عالي الخطورة.")
            
            # إذا كان الرابط خارجي، نتحقق هل يطابق نطاق فيسبوك الرسمي؟
            elif "http" in action:
                # إذا كانت الصفحة تدعي أنها فيسبوك ولكن الـ action يذهب لموقع غريب أو نفق Ngrok
                if "facebook.com" not in action and self.is_brand_impersonated():
                    self.risk_score += 50
                    self.alerts.append(f"[CRITICAL] تعارض صارخ! الصفحة تنتحل صفحة فيسبوك لكنها ترسل البيانات إلى موقع خارجي غريب: ({action})")

    def is_brand_impersonated(self):
        """دالة مساعدة للتحقق من وجود علامات فيسبوك في النص"""
        page_text = self.soup.get_text().lower()
        return 'facebook' in page_text or 'تسجيل الدخول إلى فيسبوك' in page_text

    def analyze_brand_mismatch(self):
        """المعيار الثاني: فحص تعارض النطاق الحقيقي مع المحتوى البصري"""
        page_text = self.soup.get_text().lower()
        target_keywords = ['facebook', 'تسجيل الدخول إلى فيسبوك', 'password']
        
        found_keywords = [kw for kw in target_keywords if kw in page_text]
        
        # إذا كنا نفحص رابط إنترنت حي
        if self.target.startswith("http"):
            # إذا كانت الكلمات موجودة ولكن رابط الموقع ليس facebook.com الحقيقي
            if found_keywords and "facebook.com" not in self.target:
                self.risk_score += 35
                self.alerts.append(f"[!] انتحال هوية بصرية: الرابط الحي لا يحتوي على نطاق فيسبوك الرسمي ولكن الصفحة تستخدم كلماتها المفتاحية: {found_keywords}.")
        else:
            # للملفات المحلية (مثل zphisher)
            if found_keywords:
                self.risk_score += 20
                self.alerts.append(f"[!] الملف المحلي يحتوي على كلمات دلالية لعلامة تجارية محمية: {found_keywords}.")

    def analyze_input_fields(self):
        """المعيار الثالث: وجود حقول محمية"""
        password_inputs = self.soup.find_all('input', {'type': 'password'})
        if password_inputs:
            self.risk_score += 15
            self.alerts.append(f"[!] العثور على حقل إدخال كلمات مرور حساس داخل الصفحة.")

    def evaluate(self):
        if not self.load_document():
            print(f"[X] Error: Target {self.target} could not be loaded.")
            return

        self.analyze_form_actions()
        self.analyze_brand_mismatch()
        self.analyze_input_fields()

        self.risk_score = min(self.risk_score, 100)
        
        print("="*60)
        print(f" تقرير الفحص السلوكي للهدف: {self.target}")
        print("="*60)
        print(f" معدل الخطورة الإجمالي: {self.risk_score}/100")
        print(f" التصنيف: {'خطير جداً / Phishing قاطع' if self.risk_score >= 60 else 'مشبوه / يتطلب مراجعة' if self.risk_score >= 30 else 'آمن / نطاق رسمي موثوق'}")
        print("-"*60)
        print(" المؤشرات السلوكية المكتشفة:")
        if not self.alerts:
            print("[+] لا يوجد مؤشرات مشبوهة، البنية متطابقة مع النطاق الرسمي.")
        for alert in self.alerts:
            print(alert)
        print("="*60)

if __name__ == "__main__":
    # لتشغيل الفحص وتوجيهه، اختر أحد الخيارين بالأسفل:
    
    # 1. فحص صفحة فيسبوك الأصلية عبر الإنترنت:
    target_to_scan = "zphisher/.sites/facebook/login.html"
    
    # 2. أو فحص ملف الأداة المزيفة المحلي (قم بإلغاء التعليق لتفعيله):
    # target_to_scan = "login.html"
    
    analyzer = HeuristicPhishAnalyzer(target_to_scan)
    analyzer.evaluate()
