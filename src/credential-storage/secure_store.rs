//! ローカル認証情報の暗号化（saved_accounts.json / cookies*.json）。
//!
//! 背景: VRChatの認証トークン・Cookieが平文JSONで保存されていた。AppData配下の
//! jsonを漁ってVRChatトークンを窃取するマルウェアが実在するため、ファイルコピー系の
//! 脅威に対して暗号化する。
//!
//! セキュリティ上の限界（重要）: ローカル暗号化で防げるのは主に「ファイルをコピーして
//! 別環境で読む」タイプの脅威。マスターキーはOSキーチェーンにあるため、同一ユーザー権限で
//! 動くマルウェアはキーチェーンごと復号でき、これは本方式では防げない残存リスク。
//!
//! 設計: マスターキー方式。
//!   - 鍵取得を [`KeyProvider`] トレイトで抽象化し、実装を差し替えられるようにしている。
//!     デスクトップは keyring 実装。
//!   - 暗号は ChaCha20-Poly1305（純Rust・全OS共通・RustCrypto）。
//!   - ファイル形式: マジックヘッダ `VPENC1`(6B) + ランダムnonce(12B) + 暗号文(+16Bタグ)。

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use keyring::Entry;
use once_cell::sync::OnceCell;

/// 暗号化ファイルのマジックヘッダ（バージョン1）
const MAGIC: &[u8] = b"VPENC1";
/// nonce長（ChaCha20-Poly1305は96bit）
const NONCE_LEN: usize = 12;
/// keyringに保存するマスターキーのエントリ名（AUTH_TOKEN_KEYとは別枠）
const MASTER_KEY_ENTRY: &str = "vrcpersona_master_key";

/// マスターキー取得を抽象化するトレイト。
/// デスクトップは [`KeyringKeyProvider`]。
pub trait KeyProvider: Send + Sync {
    /// 256bitマスターキーを取得する（無ければ生成して保存し、以後は同じ鍵を返す）
    fn get_or_create_master_key(&self) -> Result<[u8; 32], String>;
}

/// デスクトップ実装: OSキーチェーン（keyringクレート）にマスターキーを保存する。
pub struct KeyringKeyProvider {
    /// keyringのサービス名（アプリのidentifierを使う。dev/prodで自動分離される）
    service_name: String,
}

impl KeyringKeyProvider {
    /// @param service_name - keyringサービス名（アプリのidentifier）
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }
}

impl KeyProvider for KeyringKeyProvider {
    fn get_or_create_master_key(&self) -> Result<[u8; 32], String> {
        let entry = Entry::new(&self.service_name, MASTER_KEY_ENTRY).map_err(|e| e.to_string())?;
        match entry.get_password() {
            Ok(b64) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64.trim())
                    .map_err(|e| format!("マスターキーのデコードに失敗: {}", e))?;
                let arr: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "マスターキーの長さが不正（32バイトではない）".to_string())?;
                Ok(arr)
            }
            Err(keyring::Error::NoEntry) => {
                // 未生成: ランダムな256bit鍵を生成して保存
                let mut key = [0u8; 32];
                getrandom::getrandom(&mut key)
                    .map_err(|e| format!("マスターキーの生成に失敗（RNG）: {}", e))?;
                let b64 = base64::engine::general_purpose::STANDARD.encode(key);
                entry
                    .set_password(&b64)
                    .map_err(|e| format!("マスターキーの保存に失敗: {}", e))?;
                log::info!("Generated new master key in keychain");
                Ok(key)
            }
            Err(e) => Err(format!("マスターキーの取得に失敗: {}", e)),
        }
    }
}

/// プロセス全体で共有するKeyProvider（setup時に [`init_provider`] で初期化）
static PROVIDER: OnceCell<Box<dyn KeyProvider>> = OnceCell::new();

/// KeyProviderを初期化する（アプリ起動時に一度だけ呼ぶ）。
/// 二重初期化は無視する。
/// @param provider - 使用するKeyProvider実装
pub fn init_provider(provider: Box<dyn KeyProvider>) {
    if PROVIDER.set(provider).is_err() {
        log::warn!("secure_store provider already initialized");
    }
}

/// 初期化済みのKeyProviderからマスターキーを取得する
fn master_key() -> Result<[u8; 32], String> {
    let provider = PROVIDER
        .get()
        .ok_or_else(|| "secure_store provider未初期化".to_string())?;
    provider.get_or_create_master_key()
}

/// バイト列が本モジュールの暗号化形式（マジックヘッダ付き）かどうか判定する。
/// @param data - 判定対象のバイト列
/// @returns 暗号化形式なら true
pub fn is_encrypted(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

/// 指定した鍵で平文を暗号化する（マジックヘッダ + nonce + 暗号文 を返す）。
/// @param key - 256bitマスターキー
/// @param plaintext - 平文
/// @returns 暗号化済みバイト列
fn encrypt_with(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("nonce生成に失敗（RNG）: {}", e))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| "暗号化に失敗".to_string())?;

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// 指定した鍵で暗号化バイト列を復号する。
/// @param key - 256bitマスターキー
/// @param data - `encrypt_with` が生成した暗号化バイト列
/// @returns 復号した平文
fn decrypt_with(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if !is_encrypted(data) {
        return Err("暗号化ヘッダがありません".to_string());
    }
    let rest = &data[MAGIC.len()..];
    if rest.len() < NONCE_LEN {
        return Err("暗号化データが短すぎます".to_string());
    }
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| "復号に失敗（鍵不一致または改ざん）".to_string())
}

/// 平文を暗号化する（グローバルのマスターキーを使用）。
/// @param plaintext - 平文
/// @returns 暗号化済みバイト列
pub fn encrypt_bytes(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let key = master_key()?;
    encrypt_with(&key, plaintext)
}

/// 暗号化バイト列を復号する（グローバルのマスターキーを使用）。
/// @param data - 暗号化バイト列
/// @returns 復号した平文
pub fn decrypt_bytes(data: &[u8]) -> Result<Vec<u8>, String> {
    let key = master_key()?;
    decrypt_with(&key, data)
}

/// ファイルの生バイトを中身（JSON等）へ変換する。旧形式（平文）との後方互換のため、
/// マジックヘッダがあれば復号し、無ければ平文とみなしてそのまま返す。
/// 平文だった場合は呼び出し側が暗号化して保存し直す（ワンウェイ移行）。
/// @param raw - ファイルから読んだ生バイト
/// @returns (中身のバイト列, 平文だったか)
pub fn decode_or_migrate(raw: &[u8]) -> Result<(Vec<u8>, bool), String> {
    if is_encrypted(raw) {
        Ok((decrypt_bytes(raw)?, false))
    } else {
        Ok((raw.to_vec(), true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト用の固定鍵プロバイダ
    struct FixedKeyProvider([u8; 32]);
    impl KeyProvider for FixedKeyProvider {
        fn get_or_create_master_key(&self) -> Result<[u8; 32], String> {
            Ok(self.0)
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [7u8; 32];
        let plaintext = b"{\"auth_token\":\"authcookie_secret\"}";
        let encrypted = encrypt_with(&key, plaintext).unwrap();

        // マジックヘッダが付き、平文がそのまま現れないこと
        assert!(is_encrypted(&encrypted));
        assert!(encrypted.starts_with(MAGIC));
        assert!(!encrypted.windows(plaintext.len()).any(|w| w == plaintext));

        let decrypted = decrypt_with(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn nonce_is_randomized_per_encryption() {
        let key = [3u8; 32];
        let plaintext = b"same input";
        let a = encrypt_with(&key, plaintext).unwrap();
        let b = encrypt_with(&key, plaintext).unwrap();
        // 同じ平文でも暗号文（nonce含む）は毎回変わる
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let key = [1u8; 32];
        let wrong = [2u8; 32];
        let encrypted = encrypt_with(&key, b"secret").unwrap();
        assert!(decrypt_with(&wrong, &encrypted).is_err());
    }

    #[test]
    fn tamper_is_detected() {
        let key = [9u8; 32];
        let mut encrypted = encrypt_with(&key, b"secret payload").unwrap();
        // 末尾（タグ or 暗号文）を1バイト改ざん
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xff;
        assert!(decrypt_with(&key, &encrypted).is_err());
    }

    #[test]
    fn decode_or_migrate_handles_plaintext() {
        // 旧平文（マジックヘッダ無し）はそのまま返り、移行フラグが立つ
        let plaintext = br#"{"accounts":{}}"#;
        assert!(!is_encrypted(plaintext));
        let (bytes, was_plaintext) = decode_or_migrate(plaintext).unwrap();
        assert_eq!(bytes, plaintext);
        assert!(was_plaintext);
    }

    #[test]
    fn decode_or_migrate_via_provider_roundtrip() {
        // provider経由の暗号化→decode_or_migrateで復号でき、移行フラグは立たない
        init_provider(Box::new(FixedKeyProvider([5u8; 32])));
        let plaintext = br#"{"cookies":"value"}"#;
        let encrypted = encrypt_bytes(plaintext).unwrap();
        let (bytes, was_plaintext) = decode_or_migrate(&encrypted).unwrap();
        assert_eq!(bytes, plaintext);
        assert!(!was_plaintext);
    }
}
