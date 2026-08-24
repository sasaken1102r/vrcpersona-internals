# VRCPersona Internals

[English](./README.en.md)

VRCPersona の内部実装のうち、外部から読めるようにしている部分のソースコードです。

<strong>ここにあるのは VRCPersona v1.0.0 のコードです。</strong>認証情報の暗号化は v1.0.0 で追加されたもので、v0.7.6 以前には入っていません（→[対象バージョン](#対象バージョン)）。

---

## 収録している範囲

| 領域 | 内容 | ソース |
|---|---|---|
| credential-storage | VRChat の認証情報の保存と暗号化 | [`src/credential-storage/`](./src/credential-storage/) |

**ここに無いものは、このリポジトリからは検証できません。** アプリ全体のソースではなく、上の表にある範囲に限られます。たとえば、認証情報を使って何を通信しているかは分かりません。

また、これらのファイルは<strong>ビルドできません</strong>。アプリとして動作するものではなく、読むためのリポジトリです。

---

# credential-storage

VRChat の認証情報をどこに、どうやって保存しているか。

## 対象バージョン

このリポジトリのファイルは **VRCPersona v1.0.0** のものです。

認証情報の暗号化は v1.0.0 で追加されました。v0.7.6 以前は、これらのファイルを平文のJSONで保存していました。v1.0.0 へアップデートすると、既存の平文ファイルは読み込み時に暗号化して保存し直されます（`decode_or_migrate`）。

## 保存しているもの

保存先はすべて利用者のPC内です。VRCPersona のサーバーへは送信していません。

Windows では次のフォルダに置かれます。

```
%APPDATA%\com.sasaken1102s.vrcpersona\
```

| ファイル | 内容 | 暗号化 |
|---|---|---|
| `cookies.json` | VRChat の認証 Cookie（`auth` / `twoFactorAuth`） | あり |
| `cookies_<userId>.json` | アカウント切り替え用の Cookie バックアップ | あり |
| `saved_accounts.json` | クイックログイン用のアカウント情報 | あり |
| `pronouns_restore.json` | VRChat 本人確認で一時的に書き換えた pronouns の復元用 | あり |

`saved_accounts.json` に保存されるのは、1アカウントにつき次の 6 項目です（`storage.rs` の `SavedAccount`）。

- `user_id` — VRChat のユーザーID
- `display_name` — 表示名
- `thumbnail_url` — サムネイル画像のURL
- `auth_token` — 認証トークン
- `saved_at` — 保存日時
- `last_login_at` — 最終ログイン日時

現在ログイン中の認証トークンは、OS の資格情報マネージャーにも保存されます（`storage.rs` の `save_auth_token`、エントリ名 `vrchat_auth_token`）。

メールアドレスとパスワードは保存していません。ログイン時に VRChat API へ渡すのみです。パスワードを入力しない「トークンログイン」を推奨しています。

## 保護の方式

実装は `secure_store.rs` にあります。

- **暗号方式** — ChaCha20-Poly1305（RustCrypto・純Rust実装）
- **マスターキー** — 256bit。`getrandom` で生成し、OS のキーチェーン（Windows は資格情報マネージャー）に保存
  - keyring のエントリ名は `vrcpersona_master_key`
  - サービス名にアプリの identifier を使うため、開発版と製品版で鍵が分離されます
- **ファイル形式** — マジックヘッダ `VPENC1`（6バイト）＋ ランダム nonce（12バイト）＋ 暗号文（＋16バイトの認証タグ）
  - nonce は暗号化のたびに生成するため、同じ内容でも暗号文は毎回異なります
  - 認証タグにより、改ざんされた場合は復号が失敗します
- **旧バージョンからの移行** — 暗号化されていないファイルを検出した場合、読み込み後に暗号化して保存し直します（`decode_or_migrate`）

これらの挙動は `secure_store.rs` 末尾のユニットテストで確認できます。

## 防げない範囲

`secure_store.rs` の冒頭コメントより。

> ローカル暗号化で防げるのは主に「ファイルをコピーして別環境で読む」タイプの脅威。マスターキーはOSキーチェーンにあるため、同一ユーザー権限で動くマルウェアはキーチェーンごと復号でき、これは本方式では防げない残存リスク。

利用者と同じ権限でマルウェアが動作している状況は、この方式では防げません。

この暗号化が対象としているのは、AppData 配下のJSONファイルを走査して認証トークンを取得するタイプのマルウェアです。

## 認証トークンについて

VRChat の認証トークン（auth cookie）は、取得時のIPアドレスに紐づいており、別のIPからは使用できません。

- [VRChat Creator Guidelines](https://hello.vrchat.com/creator-guidelines)（2025-04-15更新）— "If a user account is interacting with our API, we assume that the interaction comes from the user's device and IP."
- [VRChat Feedback — 接続ごとにIPが変わる環境でログインできない不具合](https://feedback.vrchat.com/bug-reports/p/workaround-found-cloudflare-warp-blocks-login-and-causes-error-since-feb-27-2026)（2026-02-28 報告 / 2026-03-11 に VRChat 側が「Tracked」に更新）— IPが変わると `authToken doesn't correspond with an active session` となり、IPを固定すると解消する
- [VRChat公式アカウントの回答](https://feedback.vrchat.com/feature-requests/p/allow-authcookie-to-be-used-from-a-different-ip-address-extra-features)（2020-02-18）— トークンの盗難を想定した措置である旨の説明

トークンは VRChat 公式サイトでログアウトすることでいつでも無効化できます。

トークンで VRChat API に対してできる操作は、パスワードでログインした場合と同じです。どちらの方法でも、最終的にアプリが使用するのは同じ認証トークンです。トークンログインの利点はアプリの権限が小さくなることではなく、パスワードを渡さずに済むこと、および漏洩時に他の環境で使い回せないことです。

出典を含む詳細は [FAQ](https://vrcpersona.sasaken1102s.net/faqs/#token-login) に記載しています。

---

## このリポジトリについて

- ここにあるファイルは、VRCPersona v1.0.0 の `src-tauri/src/` にあるものと同一です
- 実装を変更した場合は、こちらも更新します
- ビルド可能な crate ではありません

## ライセンス

[GPLv3](./LICENSE)

VRCPersona 本体は非公開のソフトウェアで、[利用規約](https://vrcpersona.sasaken1102s.net/terms/)により改変・複製・再頒布を禁じています。<strong>このリポジトリに収録しているファイルは、その例外です。</strong>著作権者として、これらのファイルに限り GPLv3 のもとで利用・改変・再頒布を許諾します。本体のその他の部分には適用されません。

## Issue / Pull Request

[CONTRIBUTING.md](./CONTRIBUTING.md) を参照してください。Issue は受け付けています。コードの Pull Request は受け付けていません。

## リンク

- 公式サイト: https://vrcpersona.sasaken1102s.net/
- よくある質問: https://vrcpersona.sasaken1102s.net/faqs/
- プライバシーポリシー: https://vrcpersona.sasaken1102s.net/privacy/
