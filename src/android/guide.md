# Android Studio Setup Guide

This documentation provides step-by-step instructions for downloading, installing, and configuring **Android Studio**. It is tailored for projects involving both **Java** and **C++/NDK integration** (e.g., Certifier Framework Android integration).

---

## 1. Prerequisites

Before starting, ensure you have:

- A computer with at least:
  - **8 GB RAM** (16 GB recommended)
  - **4 GB free disk space** (SSD preferred)
  - **64-bit OS**: Windows 10/11, macOS (Intel or Apple Silicon), Linux (Ubuntu 20.04+)
- **Java Development Kit (JDK 11 or higher)** installed  
  - Android Studio bundles OpenJDK, so you typically don’t need a separate installation.

---

## 2. Download Android Studio

1. Visit the official site: [https://developer.android.com/studio](https://developer.android.com/studio)  
2. Download the installer for your OS:
   - **Windows**: `.exe`
   - **Mac**: `.dmg`
   - **Linux**: `.tar.gz`
3. Follow the installer prompts:
   - Accept the license
   - Choose installation location
   - Keep default components checked (**Android SDK, Android Virtual Device, Android SDK Platform-Tools**)

---

## 3. First-Time Setup

1. Launch **Android Studio**.
2. On the **Welcome Screen**:
   - Choose **Standard Installation** (recommended)
   - Select a theme (e.g., Darcula or Light)
3. Android Studio will download additional components:
   - **Android SDK**
   - **Emulator**
   - **Build tools**

> This step can take 10–30 minutes depending on internet speed.

---

## 4. Configure SDK and NDK

Since your project involves **JNI (Java Native Interface)** and **C++ libraries**, ensure NDK support is enabled.

1. Open **Android Studio** → `File` → `Settings` (or `Preferences` on macOS).
2. Navigate to:
   - `Appearance & Behavior > System Settings > Android SDK`
   - Install the following:
     - **Android SDK Platform** (latest stable, e.g., Android 14 or 13)
     - **Android SDK Tools**
     - **NDK (Side by side)**
     - **CMake**
3. Note the installation paths:
   - SDK: `.../Android/Sdk/`
   - NDK: `.../Android/Sdk/ndk/<version>`

---

## 5. Environment Variables (Optional but Recommended)

Add these to your system environment variables:

- **Windows**:
  - `ANDROID_HOME=C:\Users\<your-user>\AppData\Local\Android\Sdk`
  - Add `%ANDROID_HOME%\tools` and `%ANDROID_HOME%\platform-tools` to `PATH`

- **macOS/Linux**:
  ```bash
  export ANDROID_HOME=$HOME/Android/Sdk
  export PATH=$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools:$PATH
