use crate::secure_store;
use keyring::Entry;
use reqwest_cookie_store::CookieStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::Path;

const AUTH_TOKEN_KEY: &str = "vrchat_auth_token";
const SAVED_ACCOUNTS_FILE: &str = "saved_accounts.json";
const PRONOUNS_RESTORE_FILE: &str = "pronouns_restore.json";

/**
 * 保存済みアカウント情報
 */
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SavedAccount {
    pub user_id: String,
    pub display_name: String,
    pub thumbnail_url: Option<String>,
    pub auth_token: String,
    pub saved_at: String,
    pub last_login_at: String,
}

/**
 * 保存済みアカウントファイル
 */
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SavedAccountsFile {
    pub last_logged_in_user_id: Option<String>,
    pub accounts: HashMap<String, SavedAccount>,
}

impl Default for SavedAccountsFile {
    fn default() -> Self {
        Self {
            last_logged_in_user_id: None,
            accounts: HashMap::new(),
        }
    }
}

/**
 * VRChat本人確認でpronounsを一時的に書き換える際の復元用コンテキスト。
 *
 * 本人確認は pronouns にnonceを書き込み → サーバーが検証 → 元の値へ復元、という流れだが、
 * 復元APIが失敗した場合やアプリが強制終了された場合、pronounsにnonceが残ったままになる。
 * フロント側のuseRefはメモリ上にしか無く再起動で失われるため、ここでディスクへ逃がしておき、
 * 次回起動時に残骸を検出して自動復元できるようにする。
 *
 * pronounsはidentityフィールドで、書き換わったまま戻らないと影響が大きい。
 * 秘密情報ではないが、同ディレクトリの他の認証情報ファイルと扱いを揃えて暗号化する。
 */
/// ⚠️ フロントエンドへIPCで返すので **camelCase で serialize する**。
/// これが無いと `vrchat_user_id` のまま返り、TS側の `ctx.vrchatUserId` が
/// undefined になって「別アカウントの残骸」と誤判定され、**復元が永久に走らない**。
/// （ディスク上のJSONも同じ形式になるが、未リリース機能なので移行は不要）
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PronounsRestoreCtx {
    /// 対象のVRChatユーザーID（別アカウントのpronounsを壊さないための照合に使う）
    pub vrchat_user_id: String,
    /// 書き換える前のpronounsの値（空文字もあり得る）
    pub original_pronouns: String,
    /// 書き込んだnonce（残骸の同定・ユーザーへの案内に使う）
    pub nonce: String,
    /// 書き込んだ時刻（RFC3339）
    pub created_at: String,
}

/**
 * Cookieを保存（暗号化してファイルへ書き込む）
 */
pub fn save_cookies(cookie_store: &CookieStore, path: &Path) -> Result<(), String> {
    // 一旦メモリ上にJSONを書き出してから暗号化して保存する
    let mut json: Vec<u8> = Vec::new();
    cookie_store
        .save_json(&mut json)
        .map_err(|e| format!("Failed to serialize cookies: {}", e))?;

    let encrypted = secure_store::encrypt_bytes(&json)?;
    fs::write(path, &encrypted).map_err(|e| format!("Failed to write cookie file: {}", e))?;

    log::info!("Cookies saved (encrypted) to: {:?}", path);
    Ok(())
}

/**
 * Cookieを読み込み（暗号化ファイルは復号。旧平文ファイルは移行して暗号化保存し直す）
 */
pub fn load_cookies(path: &Path) -> Result<CookieStore, String> {
    if !path.exists() {
        log::info!("No cookie file found, creating new cookie store");
        return Ok(CookieStore::default());
    }

    let raw = fs::read(path).map_err(|e| format!("Failed to read cookie file: {}", e))?;
    let (json, was_plaintext) = secure_store::decode_or_migrate(&raw)?;

    let cookie_store = CookieStore::load_json(Cursor::new(json))
        .map_err(|e| format!("Failed to load cookies: {}", e))?;

    // 旧平文だった場合は暗号化して保存し直す（ワンウェイ移行・平文の痕跡を消す）
    if was_plaintext {
        if let Err(e) = save_cookies(&cookie_store, path) {
            log::warn!("Failed to migrate plaintext cookies to encrypted: {}", e);
        } else {
            log::info!("Migrated plaintext cookies to encrypted: {:?}", path);
        }
    }

    log::info!("Cookies loaded from: {:?}", path);
    Ok(cookie_store)
}

/**
 * Cookieを削除
 */
pub fn delete_cookies(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_file(path).map_err(|e| format!("Failed to delete cookie file: {}", e))?;
        log::info!("Cookies deleted");
    }

    Ok(())
}

/**
 * 認証トークンを保存
 */
pub fn save_auth_token(token: &str, service_name: &str) -> Result<(), String> {
    let entry = Entry::new(service_name, AUTH_TOKEN_KEY).map_err(|e| e.to_string())?;
    entry.set_password(token).map_err(|e| e.to_string())?;
    Ok(())
}

/**
 * 認証トークンを読み込み
 */
pub fn load_auth_token(service_name: &str) -> Result<String, String> {
    let entry = Entry::new(service_name, AUTH_TOKEN_KEY).map_err(|e| e.to_string())?;
    entry.get_password().map_err(|e| e.to_string())
}

/**
 * 認証トークンを削除
 */
pub fn delete_auth_token(service_name: &str) -> Result<(), String> {
    let entry = Entry::new(service_name, AUTH_TOKEN_KEY).map_err(|e| e.to_string())?;
    entry.delete_password().map_err(|e| e.to_string())?;
    Ok(())
}

/**
 * 保存済みアカウントファイルのパスを取得
 */
pub fn saved_accounts_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(SAVED_ACCOUNTS_FILE)
}

/**
 * 保存済みアカウント一覧を読み込み（暗号化ファイルは復号。旧平文は移行して保存し直す）
 */
pub fn load_saved_accounts(data_dir: &Path) -> Result<SavedAccountsFile, String> {
    let path = saved_accounts_path(data_dir);
    if !path.exists() {
        log::info!("No saved accounts file found, returning default");
        return Ok(SavedAccountsFile::default());
    }

    let raw = fs::read(&path).map_err(|e| format!("Failed to read saved accounts: {}", e))?;
    let (json, was_plaintext) = secure_store::decode_or_migrate(&raw)?;

    let data: SavedAccountsFile = serde_json::from_slice(&json)
        .map_err(|e| format!("Failed to parse saved accounts: {}", e))?;

    // 旧平文だった場合は暗号化して保存し直す（ワンウェイ移行・平文の痕跡を消す）
    if was_plaintext {
        if let Err(e) = save_saved_accounts(&data, data_dir) {
            log::warn!(
                "Failed to migrate plaintext saved accounts to encrypted: {}",
                e
            );
        } else {
            log::info!("Migrated plaintext saved accounts to encrypted");
        }
    }

    log::info!("Loaded {} saved accounts", data.accounts.len());
    Ok(data)
}

/**
 * 保存済みアカウント一覧を書き込み（暗号化して保存）
 */
pub fn save_saved_accounts(data: &SavedAccountsFile, data_dir: &Path) -> Result<(), String> {
    let path = saved_accounts_path(data_dir);

    let json = serde_json::to_vec(data)
        .map_err(|e| format!("Failed to serialize saved accounts: {}", e))?;
    let encrypted = secure_store::encrypt_bytes(&json)?;

    fs::write(&path, &encrypted).map_err(|e| format!("Failed to write saved accounts: {}", e))?;

    log::info!(
        "Saved {} accounts (encrypted) to: {:?}",
        data.accounts.len(),
        path
    );
    Ok(())
}

/**
 * pronouns復元コンテキストのファイルパスを取得
 */
pub fn pronouns_restore_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(PRONOUNS_RESTORE_FILE)
}

/**
 * pronouns復元コンテキストを書き込む（暗号化して保存）。
 * pronounsを書き換える「前」に必ず呼ぶこと。
 */
pub fn save_pronouns_restore_ctx(ctx: &PronounsRestoreCtx, data_dir: &Path) -> Result<(), String> {
    let path = pronouns_restore_path(data_dir);

    let json = serde_json::to_vec(ctx)
        .map_err(|e| format!("Failed to serialize pronouns restore ctx: {}", e))?;
    let encrypted = secure_store::encrypt_bytes(&json)?;

    fs::write(&path, &encrypted)
        .map_err(|e| format!("Failed to write pronouns restore ctx: {}", e))?;

    log::info!("Saved pronouns restore context for {}", ctx.vrchat_user_id);
    Ok(())
}

/**
 * pronouns復元コンテキストを読み込む（無ければ None）。
 *
 * 壊れたファイルは復元不能なので削除して None を返す。ここでエラーを返すと
 * 起動時の復元処理全体が止まってしまい、残骸を消す手立てが無くなるため。
 */
pub fn load_pronouns_restore_ctx(data_dir: &Path) -> Result<Option<PronounsRestoreCtx>, String> {
    let path = pronouns_restore_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read(&path).map_err(|e| format!("Failed to read pronouns restore ctx: {}", e))?;
    let (json, _was_plaintext) = secure_store::decode_or_migrate(&raw)?;

    match serde_json::from_slice::<PronounsRestoreCtx>(&json) {
        Ok(ctx) => Ok(Some(ctx)),
        Err(e) => {
            log::warn!("Discarding unreadable pronouns restore ctx: {}", e);
            let _ = delete_file_if_exists(&path);
            Ok(None)
        }
    }
}

/**
 * pronouns復元コンテキストを削除する（復元が完了したとき・不要になったときに呼ぶ）
 */
pub fn clear_pronouns_restore_ctx(data_dir: &Path) -> Result<(), String> {
    let path = pronouns_restore_path(data_dir);
    delete_file_if_exists(&path)?;
    log::info!("Cleared pronouns restore context");
    Ok(())
}

/**
 * 起動時に data_dir 内の認証情報ファイルを平文→暗号化へワンウェイ移行する。
 *
 * `saved_accounts.json` と `cookies.json` はそれぞれのロード関数側でも移行されるが、
 * アカウント別バックアップ `cookies_{user_id}.json` はコピー経由でしか読まれないため、
 * ここで `cookies*.json` をすべて走査して平文なら暗号化して上書きする。
 * 既に暗号化済みのファイルはスキップする。
 */
pub fn migrate_credential_files(data_dir: &Path) {
    // saved_accounts.json（読み込むと平文なら自動で暗号化保存し直される）
    if let Err(e) = load_saved_accounts(data_dir) {
        log::warn!("saved_accounts migration check failed: {}", e);
    }

    // cookies.json / cookies_{user_id}.json を走査
    let entries = match fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("Failed to read data_dir for migration: {}", e);
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_cookie_file = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("cookies") && n.ends_with(".json"))
            .unwrap_or(false);
        if !is_cookie_file {
            continue;
        }
        if let Err(e) = migrate_file_in_place(&path) {
            log::warn!("Failed to migrate credential file {:?}: {}", path, e);
        }
    }
}

/**
 * 単一ファイルを平文→暗号化へ移行する（既に暗号化済みなら何もしない）。
 * JSONの内容には触れず、生バイトをそのまま暗号化してヘッダ付きで上書きする。
 */
fn migrate_file_in_place(path: &Path) -> Result<(), String> {
    let raw = fs::read(path).map_err(|e| format!("read failed: {}", e))?;
    if secure_store::is_encrypted(&raw) {
        return Ok(());
    }
    let encrypted = secure_store::encrypt_bytes(&raw)?;
    fs::write(path, &encrypted).map_err(|e| format!("write failed: {}", e))?;
    log::info!("Migrated credential file to encrypted: {:?}", path);
    Ok(())
}

/**
 * ファイルをコピー
 */
pub fn copy_file(src: &Path, dst: &Path) -> Result<(), String> {
    fs::copy(src, dst).map_err(|e| format!("Failed to copy file {:?} -> {:?}: {}", src, dst, e))?;
    log::info!("File copied: {:?} -> {:?}", src, dst);
    Ok(())
}

/**
 * ファイルが存在すれば削除
 */
pub fn delete_file_if_exists(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_file(path).map_err(|e| format!("Failed to delete file {:?}: {}", path, e))?;
        log::info!("File deleted: {:?}", path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /**
     * Cookie永続化フォーマットの後方互換性テスト
     *
     * cookie_store 0.21.1 で「legacy serialization」と新しい `serde` モジュールが分離され、
     * `save_json` / `load_json` は非推奨になったが互換性のために残されている。
     * VRCPersonaは既存ユーザーのログイン状態を維持する必要があるため、
     * 意図的に legacy API を使い続けている（新APIに移行するとフォーマットが変わり、
     * アップデート時に全ユーザーがVRChatからログアウトされる）。
     *
     * このテストは legacy フォーマットでの save → load ラウンドトリップが
     * 壊れていないことを保証する。cookie_store のアップグレードで落ちたら、
     * 移行処理を書くまでリリースしてはいけない。
     */
    #[test]
    fn legacy_json_roundtrip_preserves_cookies() {
        let mut store = CookieStore::default();
        let url = "https://api.vrchat.cloud/".parse::<url::Url>().unwrap();
        // save_jsonが永続化するのは有効期限付きcookieのみ（セッションcookieは対象外）。
        // VRChatのauth cookieも期限付きなので、それに合わせる。
        store
            .parse(
                "auth=dummy_value_for_test; Path=/; Domain=vrchat.cloud; Max-Age=3600",
                &url,
            )
            .expect("cookieのパースに失敗");

        let mut json: Vec<u8> = Vec::new();
        store.save_json(&mut json).expect("save_jsonに失敗");
        assert!(!json.is_empty(), "保存されたJSONが空");

        let loaded = CookieStore::load_json(Cursor::new(json)).expect("load_jsonに失敗");
        let names: Vec<String> = loaded.iter_any().map(|c| c.name().to_string()).collect();
        assert!(
            names.contains(&"auth".to_string()),
            "ラウンドトリップ後にauth cookieが失われた: {:?}",
            names
        );
    }

    /**
     * 旧バージョン（cookie_store 0.20 系）が書き出したJSONを読めるか検証する。
     *
     * 下のJSONは実際に cookie_store 0.20.0 の `save_json` に出力させたものを固定値として
     * 取り込んでいる（値はダミー）。既存ユーザーの cookies.json はこの形式で保存されているため、
     * これが読めなくなるとアップデート時に全ユーザーがVRChatからログアウトされる。
     */
    #[test]
    fn can_load_json_written_by_cookie_store_0_20() {
        // cookie_store 0.20.0 の save_json が実際に出力した形式（JSON Lines）
        let legacy_json = concat!(
            r#"{"raw_cookie":"twoFactorAuth=old_2fa_value; Path=/; Domain=vrchat.cloud; Max-Age=3600","path":["/",true],"domain":{"Suffix":"vrchat.cloud"},"expires":{"AtUtc":"2126-07-25T09:06:53Z"}}"#,
            "\n",
            r#"{"raw_cookie":"auth=old_version_value; Path=/; Domain=vrchat.cloud; Max-Age=3600","path":["/",true],"domain":{"Suffix":"vrchat.cloud"},"expires":{"AtUtc":"2126-07-25T09:06:53Z"}}"#,
            "\n"
        );

        let store = CookieStore::load_json(Cursor::new(legacy_json.as_bytes()))
            .expect("旧バージョンが書いたJSONの読み込みに失敗");

        let names: Vec<String> = store.iter_any().map(|c| c.name().to_string()).collect();
        assert!(
            names.contains(&"auth".to_string()),
            "旧形式からauth cookieを復元できなかった: {:?}",
            names
        );
        assert!(
            names.contains(&"twoFactorAuth".to_string()),
            "旧形式からtwoFactorAuth cookieを復元できなかった: {:?}",
            names
        );
    }
}
