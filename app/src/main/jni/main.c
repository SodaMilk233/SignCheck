#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "binder/pkginfo.h"
#include "crypto/sha256.h"
#include <android/api-level.h>

static const unsigned char app_sha256[32] = {
    0xC7, 0xD6, 0x01, 0xDD, 0x41, 0x0A, 0x9B, 0xB6,
    0x71, 0x39, 0xD2, 0x32, 0x5F, 0x36, 0x94, 0xB1,
    0xCC, 0xEE, 0x98, 0x3C, 0x43, 0x16, 0x33, 0xBC,
    0x1F, 0x7C, 0x6F, 0x68, 0x78, 0x63, 0x98, 0xEE,
};

jobject createTextView(JNIEnv* env, jobject context, const char* text, float textSize, int color, int gravity, int paddingBottom, int isBold) {
    jclass textViewClass = (*env)->FindClass(env, "android/widget/TextView");
    if (!textViewClass) return NULL;
    jmethodID ctor = (*env)->GetMethodID(env, textViewClass, "<init>", "(Landroid/content/Context;)V");
    if (!ctor) {
        (*env)->DeleteLocalRef(env, textViewClass);
        return NULL;
    }
    jobject textView = (*env)->NewObject(env, textViewClass, ctor, context);
    if (!textView) {
        (*env)->DeleteLocalRef(env, textViewClass);
        return NULL;
    }
    jclass tvClass = (*env)->GetObjectClass(env, textView);
    if (!tvClass) {
        (*env)->DeleteLocalRef(env, textView);
        (*env)->DeleteLocalRef(env, textViewClass);
        return NULL;
    }
    if (text) {
        jmethodID setText = (*env)->GetMethodID(env, tvClass, "setText", "(Ljava/lang/CharSequence;)V");
        if (setText) {
            jstring jtext = (*env)->NewStringUTF(env, text);
            (*env)->CallVoidMethod(env, textView, setText, jtext);
            (*env)->DeleteLocalRef(env, jtext);
        }
    }
    jmethodID setTextSize = (*env)->GetMethodID(env, tvClass, "setTextSize", "(F)V");
    if (setTextSize) (*env)->CallVoidMethod(env, textView, setTextSize, textSize);
    jmethodID setTextColor = (*env)->GetMethodID(env, tvClass, "setTextColor", "(I)V");
    if (setTextColor) (*env)->CallVoidMethod(env, textView, setTextColor, color);
    jmethodID setGravity = (*env)->GetMethodID(env, tvClass, "setGravity", "(I)V");
    if (setGravity) (*env)->CallVoidMethod(env, textView, setGravity, gravity);
    jmethodID setPadding = (*env)->GetMethodID(env, tvClass, "setPadding", "(IIII)V");
    if (setPadding) (*env)->CallVoidMethod(env, textView, setPadding, 0, 0, 0, paddingBottom);
    if (isBold) {
        jmethodID setTypeface = (*env)->GetMethodID(env, tvClass, "setTypeface", "(Landroid/graphics/Typeface;)V");
        jclass typefaceClass = (*env)->FindClass(env, "android/graphics/Typeface");
        if (typefaceClass && setTypeface) {
            jfieldID boldField = (*env)->GetStaticFieldID(env, typefaceClass, "DEFAULT_BOLD", "Landroid/graphics/Typeface;");
            if (boldField) {
                jobject boldTypeface = (*env)->GetStaticObjectField(env, typefaceClass, boldField);
                (*env)->CallVoidMethod(env, textView, setTypeface, boldTypeface);
            }
        }
        if (typefaceClass) (*env)->DeleteLocalRef(env, typefaceClass);
    }
    (*env)->DeleteLocalRef(env, tvClass);
    (*env)->DeleteLocalRef(env, textViewClass);
    return textView;
}

void addView(JNIEnv* env, jobject parent, jobject child) {
    if (!child) return;
    jclass parentClass = (*env)->GetObjectClass(env, parent);
    if (!parentClass) return;
    jmethodID addView = (*env)->GetMethodID(env, parentClass, "addView", "(Landroid/view/View;)V");
    if (addView) (*env)->CallVoidMethod(env, parent, addView, child);
    (*env)->DeleteLocalRef(env, parentClass);
}

void bytesToHexString(const unsigned char* bytes, int len, char* hex) {
    for (int i = 0; i < len; i++) {
        sprintf(&hex[i * 2], "%02X", bytes[i]);
    }
    hex[len * 2] = '\0';
}

JNIEXPORT void JNICALL NativeOnCreate(JNIEnv* env, jobject thiz, jobject savedInstanceState) {
    jclass activityClass = (*env)->GetObjectClass(env, thiz);
    jclass superClass = (*env)->GetSuperclass(env, activityClass);
    jmethodID superOnCreate = (*env)->GetMethodID(env, superClass, "onCreate", "(Landroid/os/Bundle;)V");
    if (superOnCreate) (*env)->CallNonvirtualVoidMethod(env, thiz, superClass, superOnCreate, savedInstanceState);
    (*env)->DeleteLocalRef(env, superClass);
    jmethodID getWindow = (*env)->GetMethodID(env, activityClass, "getWindow", "()Landroid/view/Window;");
    jobject window = getWindow ? (*env)->CallObjectMethod(env, thiz, getWindow) : NULL;
    if (window) {
        jclass windowClass = (*env)->FindClass(env, "android/view/Window");
        if (windowClass) {
            jmethodID setStatusBarColor = (*env)->GetMethodID(env, windowClass, "setStatusBarColor", "(I)V");
            jmethodID setNavigationBarColor = (*env)->GetMethodID(env, windowClass, "setNavigationBarColor", "(I)V");
            if (setStatusBarColor) (*env)->CallVoidMethod(env, window, setStatusBarColor, 0xFF1A1A2E);
            if (setNavigationBarColor) (*env)->CallVoidMethod(env, window, setNavigationBarColor, 0xFF1A1A2E);
            (*env)->DeleteLocalRef(env, windowClass);
        }
        (*env)->DeleteLocalRef(env, window);
    }
    jclass linearLayoutClass = (*env)->FindClass(env, "android/widget/LinearLayout");
    jmethodID llCtor = (*env)->GetMethodID(env, linearLayoutClass, "<init>", "(Landroid/content/Context;)V");
    jobject rootLayout = (*env)->NewObject(env, linearLayoutClass, llCtor, thiz);
    if (rootLayout) {
        jclass llClass = (*env)->GetObjectClass(env, rootLayout);
        jmethodID setOrientation = (*env)->GetMethodID(env, llClass, "setOrientation", "(I)V");
        jmethodID setGravity = (*env)->GetMethodID(env, llClass, "setGravity", "(I)V");
        jmethodID setPadding = (*env)->GetMethodID(env, llClass, "setPadding", "(IIII)V");
        if (setOrientation) (*env)->CallVoidMethod(env, rootLayout, setOrientation, 1);
        if (setGravity) (*env)->CallVoidMethod(env, rootLayout, setGravity, 17);
        if (setPadding) (*env)->CallVoidMethod(env, rootLayout, setPadding, 40, 48, 40, 48);
        jclass viewClass = (*env)->FindClass(env, "android/view/View");
        if (viewClass) {
            jmethodID setBackgroundColor = (*env)->GetMethodID(env, viewClass, "setBackgroundColor", "(I)V");
            if (setBackgroundColor) (*env)->CallVoidMethod(env, rootLayout, setBackgroundColor, 0xFF1A1A2E);
            (*env)->DeleteLocalRef(env, viewClass);
        }

        unsigned char expected[32];
        for (int i = 0; i < 32; i++) {
            expected[i] = app_sha256[i] ^ 0x37;
        }
        unsigned char* cert = NULL;
        size_t cert_len = 0;
        char hex_buf[65];
        char actual_hash_str[65] = "N/A";
        int match = 0;
        cert = get_signature_from_binder("littlewhitebear.signverification", &cert_len);
        if (cert && cert_len > 0) {
            unsigned char hash[32];
            sha256(cert, cert_len, hash);
            bytesToHexString(hash, 32, actual_hash_str);
            unsigned int fail = 0;
            for (int i = 0; i < 32; i++) {
                fail |= (unsigned int)(hash[i] ^ expected[i]);
            }
            match = (fail == 0);
            memset(cert, 0, cert_len);
            free(cert);
            memset(hash, 0, sizeof(hash));
        }
        bytesToHexString(expected, 32, hex_buf);
        memset(expected, 0, sizeof(expected));
        int sdk_ver = android_get_device_api_level();
        char sdk_value[16];
        snprintf(sdk_value, sizeof(sdk_value), "API %d", sdk_ver);
        char title_text[64];
        char status_text[64];
        int status_color;
        snprintf(title_text, sizeof(title_text), "签名验证");
        snprintf(status_text, sizeof(status_text), match ? "验证成功" : "验证失败");
        status_color = match ? 0xFF4CAF50 : 0xFFFF5252;
        jobject views[9];
        views[0] = createTextView(env, thiz, title_text, 24.0f, 0xFFFFFFFF, 17, 24, 1);
        views[1] = createTextView(env, thiz, "系统版本", 14.0f, 0xFFFFFFFF, 17, 8, 0);
        views[2] = createTextView(env, thiz, sdk_value, 14.0f, 0xFFA0A0A0, 17, 24, 0);
        views[3] = createTextView(env, thiz, "预期签名", 14.0f, 0xFFFFFFFF, 17, 8, 0);
        views[4] = createTextView(env, thiz, hex_buf, 14.0f, 0xFFA0A0A0, 17, 24, 0);
        views[5] = createTextView(env, thiz, "实际签名", 14.0f, 0xFFFFFFFF, 17, 8, 0);
        views[6] = createTextView(env, thiz, actual_hash_str, 14.0f, match ? 0xFFA0A0A0 : 0xFFFF5252, 17, 24, 0);
        views[7] = createTextView(env, thiz, "验证状态", 14.0f, 0xFFFFFFFF, 17, 8, 0);
        views[8] = createTextView(env, thiz, status_text, 18.0f, status_color, 17, 16, 1);
        for (int i = 0; i < 9; i++) {
            addView(env, rootLayout, views[i]);
        }
        for (int i = 0; i < 9; i++) {
            if (views[i]) (*env)->DeleteLocalRef(env, views[i]);
        }
        memset(hex_buf, 0, sizeof(hex_buf));
        memset(actual_hash_str, 0, sizeof(actual_hash_str));
        jmethodID setContentView = (*env)->GetMethodID(env, activityClass, "setContentView", "(Landroid/view/View;)V");
        if (setContentView) (*env)->CallVoidMethod(env, thiz, setContentView, rootLayout);
        (*env)->DeleteLocalRef(env, rootLayout);
    }
    (*env)->DeleteLocalRef(env, linearLayoutClass);
    (*env)->DeleteLocalRef(env, activityClass);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved __attribute__((unused))) {
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass cls = (*env)->FindClass(env, "littlewhitebear/signverification/MainActivity");
    if (!cls) return JNI_ERR;
    JNINativeMethod methods[] = {
        {"onCreate", "(Landroid/os/Bundle;)V", (void*)NativeOnCreate}
    };
    if ((*env)->RegisterNatives(env, cls, methods, sizeof(methods)/sizeof(methods[0])) < 0) return JNI_ERR;
    return JNI_VERSION_1_6;
}