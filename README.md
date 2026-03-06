# YARA-X Android Sample

このサンプルアプリは、YARA-X ライブラリを Android で使用する方法を示します。

## 前提条件

1. **JDK**: Java 17 以上で、`jlink` ツールを含む JDK が必要です（最小 JRE では不足）。
   - `jlink` エラーが出る場合: `gradle.properties` の `org.gradle.java.home` を `jlink` 入りの JDK パスに設定してください。

2. **yara-x (サブモジュール)**: [FoxRefire/yara-x](https://github.com/FoxRefire/yara-x) を Git サブモジュールとして取得しています（プリビルド済み `jniLibs` 付き）。

   初回クローン後はサブモジュールの初期化が必要です:

   ```bash
   git submodule update --init --recursive
   ```

3. **Android Studio** または **Android SDK** (API 34)

4. **16KB ページサイズ対応**: Android 15+ および 16KB ページサイズデバイス向けに、ネイティブライブラリは 16KB ELF アライメントでビルドされます。サブモジュールのプリビルド済み `jniLibs` を使用する場合、16KB 対応版を再ビルドするには `yara-x/build-android.sh` を実行してください。

## ビルドと実行

1. このディレクトリを Android Studio で開く
2. デバイスまたはエミュレータを接続
3. Run ボタンでビルド・インストール・起動

またはコマンドラインから:

```bash
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## アプリの使い方

1. **YARA Rules**: 上部のテキストエリアに YARA ルールを入力
2. **Text to Scan**: スキャン対象のテキストを入力
3. **Scan** ボタンでスキャン実行
4. **Matching Rules**: マッチしたルール名が一覧表示される

## サンプルルール

デフォルトで以下のルールが入力されています:

```yara
rule example_string {
    strings:
        $hello = "Hello"
        $world = "World"
        $malicious = "malware"
    condition:
        any of them
}
```

「Hello World」などと入力して Scan を押すと、`example_string` にマッチします。

## プロジェクト構成

- `app/src/main/cpp/` - JNI ブリッジ（yara-x C API のラッパー）
- `app/src/main/java/.../YaraX.kt` - Kotlin ラッパークラス
- `app/src/main/java/.../MainActivity.kt` - メイン UI
- `yara-x/` - Git サブモジュール（FoxRefire/yara-x、プリビルド `jniLibs` 含む）
