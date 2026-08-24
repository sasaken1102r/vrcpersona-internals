# Security Policy

## 日本語

### 脆弱性を見つけた場合

**公開の Issue には書かないでください。**

このリポジトリは認証情報の暗号化・保存を扱うコードです。悪用できる不具合の内容が公開の場に書かれると、修正が行き渡るまでの間、利用者が危険にさらされます。

次のいずれかでご連絡ください。

- <strong>GitHub の Report a vulnerability</strong>（このリポジトリの Security タブ）— 非公開でやり取りできます
- **メール: sasakenforpal@gmail.com**

### 報告に含めていただきたいこと

- 影響を受ける箇所（ファイル名・関数名など、分かる範囲で）
- 何ができてしまうか（例: 暗号化を回避して認証情報を読み取れる）
- 再現の手順、または再現できるコード
- 影響すると思われる VRCPersona のバージョン

断片的でも構いません。分かる範囲で送っていただければ、こちらで追跡します。

### 対応の流れ

- <strong>14日以内</strong>に一次返信をします（内容の確認と、脆弱性として扱うかの判断）
- 修正の見通しが立った段階で、時期の目安をお伝えします
- 修正の公開後、ご希望があればお名前・ハンドルを謝辞に記載します（不要な場合はその旨をお知らせください）

個人開発のため、対応にお時間をいただく場合があります。

### 対象範囲

- <strong>このリポジトリのコード</strong>（認証情報の保存・暗号化）
- <strong>VRCPersona 本体・サーバー・公式サイト</strong>についても、同じ窓口で受け付けます

次のものは脆弱性として扱いません。

- このリポジトリのコードがビルドできないこと（読むためのリポジトリのため、意図した状態です）
- 「同一ユーザー権限で動くマルウェアには無力である」という、[README に明記している既知の制約](./README.md#防げない範囲)
- VRChat 本体・VRChat API の問題（VRChat 社へご報告ください）

---

## English

### Reporting a vulnerability

**Please do not open a public issue.**

This repository contains the code that encrypts and stores credentials. Publishing an exploitable flaw in the open puts users at risk until a fix has propagated.

Please use one of the following instead:

- **GitHub's "Report a vulnerability"** (the Security tab of this repository) — handled privately
- **Email: sasakenforpal@gmail.com**

### What to include

- The affected location (file and function name, as far as you can tell)
- What it allows (e.g. reading credentials by bypassing the encryption)
- Steps to reproduce, or reproducing code
- Which VRCPersona versions you believe are affected

Partial reports are fine. Send what you have and it will be followed up.

### What happens next

- You will get a first response **within 14 days** (confirming the report and whether it is treated as a vulnerability)
- Once a fix is planned, you will be told the expected timing
- After the fix ships, you will be credited by name or handle if you want to be (just say if you would rather not be)

This is a solo project, so a fix may take some time.

### Scope

- **The code in this repository** (credential storage and encryption)
- **The VRCPersona app, server and website** are also covered by this contact point

The following are not treated as vulnerabilities:

- That the code here does not build (this is a read-only repository by design)
- The [documented limitation](./README.en.md#what-this-does-not-protect-against) that malware running under the same user account is not prevented
- Issues in VRChat itself or the VRChat API (please report those to VRChat)
