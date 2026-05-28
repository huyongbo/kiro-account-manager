#![allow(clippy::needless_pass_by_value)] // Tauri 命令需要按值传递参数

use crate::core::account::Account;
use crate::commands::common::{extract_user_info, get_usage_by_provider};
use crate::state::AppState;
use serde::Serialize;
use std::sync::{Mutex, MutexGuard};
use tauri::{Emitter, State};

/// 展开路径中的 ~ 为用户主目录
fn expand_home_dir(path: &str) -> Result<String, String> {
    if path.starts_with('~') {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| "无法获取用户主目录".to_string())?;
        Ok(path.replacen('~', &home, 1))
    } else {
        Ok(path.to_string())
    }
}

/// 检查账号是否已存在（按 user_id 或 client_id_hash 去重）
fn find_existing_account(
    accounts: &[Account],
    user_id: Option<&String>,
    _email: Option<&String>,
) -> Option<usize> {
    if let Some(uid) = user_id {
        return accounts
            .iter()
            .position(|a| a.user_id.as_ref() == Some(uid) || a.client_id_hash.as_ref() == Some(uid));
    }
    None
}

fn lock_account_store<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, String> {
    mutex
        .lock()
        .map_err(|_| "Failed to acquire store lock".to_string())
}
#[derive(Serialize)]
pub struct KiroCliImportResult {
    pub success: bool,
    pub is_new: bool,
    pub account: Option<Account>,
    pub error: Option<String>,
}

/// 获取 kiro-cli 默认数据库路径
#[tauri::command]
pub fn get_kiro_cli_default_path() -> Result<String, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "无法获取用户主目录".to_string())?;

    let mut candidates = Vec::new();

    if cfg!(target_os = "macos") {
        candidates.push(
            std::path::PathBuf::from(&home)
                .join("Library")
                .join("Application Support")
                .join("kiro-cli")
                .join("data.sqlite3"),
        );
    } else if cfg!(target_os = "windows") {
        // Kiro CLI 2.0 原生支持 Windows
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            candidates.push(
                std::path::PathBuf::from(local_app_data)
                    .join("Kiro-Cli")
                    .join("data.sqlite3"),
            );
        }
    } else {
        if let Ok(xdg_data_home) = std::env::var("XDG_DATA_HOME") {
            candidates.push(
                std::path::PathBuf::from(xdg_data_home)
                    .join("kiro-cli")
                    .join("data.sqlite3"),
            );
        }
        candidates.push(
            std::path::PathBuf::from(&home)
                .join(".local")
                .join("share")
                .join("kiro-cli")
                .join("data.sqlite3"),
        );
    }

    for path in candidates {
        if path.exists() {
            return Ok(path.to_string_lossy().to_string());
        }
    }

    // 文件不存在，返回空字符串（前端会显示占位符）
    Ok(String::new())
}
/// 从 kiro-auth-token-cli.json 读取 CLI token（类比 IDE 导入读 kiro-auth-token.json）
fn read_kiro_cli_token_file() -> Result<serde_json::Value, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "无法获取用户主目录".to_string())?;

    let path = std::path::Path::new(&home)
        .join(".aws")
        .join("sso")
        .join("cache")
        .join("kiro-auth-token-cli.json");

    if !path.exists() {
        return Err(format!("未找到 kiro-cli token 文件: {}", path.display()));
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("读取 kiro-auth-token-cli.json 失败: {e}"))?;

    serde_json::from_str(&content)
        .map_err(|e| format!("解析 kiro-auth-token-cli.json 失败: {e}"))
}

/// 从 kiro-cli 导入账号（直接读 kiro-auth-token-cli.json，类比 IDE 导入）
#[tauri::command]
pub async fn import_from_kiro_cli(
    _db_path: String,
    state: State<'_, AppState>,
) -> Result<KiroCliImportResult, String> {
    eprintln!("[Kiro CLI Import] 开始导入（读取 kiro-auth-token-cli.json）");

    // 1. 读取 kiro-auth-token-cli.json
    let token_json = read_kiro_cli_token_file()?;

    let access_token = token_json["accessToken"].as_str()
        .ok_or("kiro-auth-token-cli.json 缺少 accessToken")?
        .to_string();
    let refresh_token = token_json["refreshToken"].as_str()
        .ok_or("kiro-auth-token-cli.json 缺少 refreshToken")?
        .to_string();
    let expires_at = token_json["expiresAt"].as_str().map(str::to_string);
    let auth_method = token_json["authMethod"].as_str().unwrap_or("IdC").to_string();
    let region = token_json["region"].as_str().unwrap_or("us-east-1").to_string();
    let client_id_hash = token_json["clientIdHash"].as_str().map(str::to_string);
    let start_url = token_json["startUrl"].as_str().map(str::to_string);
    let profile_arn = token_json["profileArn"].as_str().map(str::to_string);

    eprintln!("[Kiro CLI Import] auth_method={auth_method}, region={region}, client_id_hash={client_id_hash:?}");

    // 2. 判断 provider（类比 IDE 导入逻辑）
    let provider = if auth_method == "IdC" {
        // 有自定义 start_url 且不是 BuilderId 默认 URL → Enterprise
        match start_url.as_deref() {
            Some(url) if !url.to_lowercase().contains("view.awsapps.com") => "Enterprise",
            _ => "BuilderId",
        }
    } else {
        // Social 账号，通过 profileArn 判断
        match profile_arn.as_deref() {
            Some(arn) if arn.to_lowercase().contains("github") => "Github",
            _ => "Google",
        }
    }.to_string();

    eprintln!("[Kiro CLI Import] provider={provider}");

    // 3. 读取 client registration（类比 IDE 导入读 {clientIdHash}.json）
    let (client_id, client_secret) = if auth_method == "IdC" {
        if let Some(ref hash) = client_id_hash {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_default();
            let client_path = std::path::Path::new(&home)
                .join(".aws").join("sso").join("cache")
                .join(format!("{hash}.json"));
            if let Ok(content) = std::fs::read_to_string(&client_path) {
                if let Ok(reg) = serde_json::from_str::<serde_json::Value>(&content) {
                    let cid = reg["clientId"].as_str().map(str::to_string);
                    let csec = reg["clientSecret"].as_str().map(str::to_string);
                    eprintln!("[Kiro CLI Import] 读取到 client registration: clientId={cid:?}");
                    (cid, csec)
                } else { (None, None) }
            } else {
                eprintln!("[Kiro CLI Import] 未找到 {hash}.json，跳过 client registration");
                (None, None)
            }
        } else { (None, None) }
    } else { (None, None) };

    // 4. 用 clientIdHash 作为账号唯一标识（类比 IDE 导入用 email）
    //    clientIdHash 是 SHA1({"startUrl":"..."})，对同一账号是固定的
    let user_id = client_id_hash.clone()
        .or_else(|| {
            // 如果没有 clientIdHash，用 refreshToken 前 20 字符作为标识
            Some(refresh_token.chars().take(20).collect())
        });

    eprintln!("[Kiro CLI Import] user_id={user_id:?}");

    // 5. 检查账号是否已存在（先 drop store，await 之后再重新获取）
    let existing_index = {
        let store = lock_account_store(&state.store)?;
        find_existing_account(&store.accounts, user_id.as_ref(), None)
    };
    let is_new = existing_index.is_none();

    // 6. 创建账号标签
    let label = if is_new {
        format!("从 kiro-cli 导入 ({})", start_url.as_deref().unwrap_or("BuilderId"))
    } else {
        let store = lock_account_store(&state.store)?;
        existing_index
            .and_then(|idx| store.accounts.get(idx))
            .map(|a| a.label.clone())
            .unwrap_or_else(|| "从 kiro-cli 导入".to_string())
    };

    // 7. 创建 Account（Enterprise 用 new_enterprise，其他用 new）
    let mut account = if provider == "Enterprise" || provider == "BuilderId" {
        Account::new_enterprise(
            user_id.clone().unwrap_or_else(|| "unknown".to_string()),
            label,
        )
    } else {
        // Social 账号，email 后续通过 API 获取，先用占位符
        Account::new(String::new(), label)
    };

    // 8. 填充字段
    account.access_token = Some(access_token);
    account.refresh_token = Some(refresh_token);
    account.expires_at = expires_at;
    account.provider = Some(provider.clone());
    account.user_id = user_id;
    // oidc_region：来自 JSON 文件的 region，用于 token 刷新（类比 IDE 导入的 oidc_region）
    // region：CW 服务调用的 region，Enterprise 账号需要多区域探测，先用 oidc_region 占位
    account.oidc_region = Some(region.clone());
    account.region = Some(region.clone()); // 先用 oidc_region，Enterprise 账号后续探测会更新
    account.auth_method = Some(auth_method.clone());
    account.client_id_hash = client_id_hash;
    account.start_url = start_url;
    account.client_id = client_id;
    account.client_secret = client_secret;
    if auth_method != "IdC" {
        account.profile_arn = profile_arn;
    }

    // 9. 尝试调用 API 获取配额和真实用户信息（失败不阻断导入）
    //    Enterprise 账号使用多区域探测，同时更新 CW 服务 region
    let access_token_ref = account.access_token.clone().unwrap_or_default();
    if provider == "Enterprise" {
        use crate::commands::common::get_enterprise_usage_with_region_probe;
        use crate::commands::machine_guid::get_machine_id;
        let machine_id = account.machine_id.clone().unwrap_or_else(get_machine_id);
        match get_enterprise_usage_with_region_probe(&access_token_ref, &machine_id).await {
            Ok((result, detected_region)) => {
                if !detected_region.is_empty() {
                    eprintln!("[Kiro CLI Import] Enterprise 探测到 CW region: {detected_region}");
                    account.region = Some(detected_region); // 更新为真实 CW 服务 region
                }
                let (api_email, api_user_id) = extract_user_info(&result.usage_data);
                if let Some(e) = api_email { account.email = Some(e); }
                if let Some(uid) = api_user_id { account.user_id = Some(uid); }
                account.usage_data = Some(result.usage_data);
                crate::commands::common::update_account_status(&mut account, result.is_banned, result.is_auth_error);
            }
            Err(e) => {
                eprintln!("[Kiro CLI Import] Enterprise 获取配额失败（不影响导入）: {e}");
                account.status = "invalid".to_string();
            }
        }
    } else {
        match get_usage_by_provider(&provider, &access_token_ref).await {
            Ok(result) => {
                let (api_email, api_user_id) = extract_user_info(&result.usage_data);
                if let Some(e) = api_email { account.email = Some(e); }
                if let Some(uid) = api_user_id { account.user_id = Some(uid); }
                account.usage_data = Some(result.usage_data);
                crate::commands::common::update_account_status(&mut account, result.is_banned, result.is_auth_error);
            }
            Err(e) => {
                eprintln!("[Kiro CLI Import] 获取配额失败（不影响导入）: {e}");
                account.status = "invalid".to_string();
            }
        }
    }

    // 10. 保存账号（await 之后重新获取 store）
    let mut store = lock_account_store(&state.store)?;
    if let Some(idx) = existing_index {
        // 更新现有账号，保留 machine_id 和 id
        account.machine_id.clone_from(&store.accounts[idx].machine_id);
        account.id.clone_from(&store.accounts[idx].id);
        store.accounts[idx] = account.clone();
    } else {
        // 新账号，生成 machine_id
        if account.machine_id.is_none() {
            account.machine_id = Some(uuid::Uuid::new_v4().to_string().to_lowercase());
        }
        store.accounts.push(account.clone());
    }

    store.save_to_file();
    drop(store);

    let display_email = &account.email;
    let display_user_id = &account.user_id;
    eprintln!("[Kiro CLI Import] 导入成功: is_new={is_new}, email={display_email:?}, user_id={display_user_id:?}");

    Ok(KiroCliImportResult {
        success: true,
        is_new,
        account: Some(account),
        error: None,
    })
}

// ============================================================
// CLI 2.0 切号功能
// ============================================================

/// 检测 CLI 2.0 安装状态
#[tauri::command]
pub fn check_cli_installation() -> crate::kiro::cli::CliInstallationInfo {
    crate::kiro::cli::check_cli_installation()
}

/// 读取 CLI 数据库快照（前端展示用）
#[tauri::command]
pub fn read_cli_db_snapshot(
    db_path: String,
) -> Result<crate::kiro::cli::KiroCliDbSnapshot, String> {
    let expanded_path = expand_home_dir(&db_path)?;
    crate::kiro::cli::read_cli_db_snapshot(&expanded_path)
}

/// 切号到 CLI 账号
#[tauri::command]
pub async fn switch_to_cli_account(
    account_id: String,
    db_path: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<crate::kiro::cli::KiroCliWriteBackup, String> {
    let expanded_path = expand_home_dir(&db_path)?;

    // 1. 从 store 读取账号数据
    let account = {
        let store = lock_account_store(&state.store)?;
        store
            .accounts
            .iter()
            .find(|a| a.id == account_id)
            .cloned()
            .ok_or_else(|| format!("账号不存在: {account_id}"))?
    };

    // 2. 切号前刷新 token（确保写入的是有效 token）
    let refreshed_account = if account.refresh_token.is_some() {
        log::info!("[CLI Switch] 切号前刷新 token...");
        match crate::commands::common::refresh_token_by_provider(&account).await {
            Ok(refresh_result) => {
                log::info!("[CLI Switch] Token 刷新成功");
                // 更新 store 中的 token
                {
                    let mut store = lock_account_store(&state.store)?;
                    if let Some(a) = store.accounts.iter_mut().find(|a| a.id == account_id) {
                        crate::commands::common::apply_refreshed_account_tokens(a, &refresh_result);
                        let _ = crate::commands::common::save_store(&store);
                    }
                }
                // 构造刷新后的账号对象
                let mut updated = account.clone();
                updated.access_token = Some(refresh_result.access_token);
                updated.refresh_token = refresh_result.refresh_token;
                // 根据 expires_in 计算 expires_at
                let expires_at = chrono::Utc::now() + chrono::Duration::seconds(refresh_result.expires_in);
                updated.expires_at = Some(expires_at.to_rfc3339());
                updated
            }
            Err(e) => {
                log::warn!("[CLI Switch] Token 刷新失败: {}, 使用现有 token", e);
                account
            }
        }
    } else {
        account
    };

    // 3. 切号后立即获取配额检测封禁状态
    let provider = refreshed_account.provider.as_ref()
        .ok_or("账号缺少 provider 字段")?;
    let access_token = refreshed_account.access_token.as_ref()
        .ok_or("账号缺少 access_token")?;

    log::info!("[CLI Switch] 切号后检测账号状态...");
    match get_usage_by_provider(provider, access_token).await {
        Ok(usage_result) => {
            // 更新账号状态（包括封禁检测）
            let mut store = lock_account_store(&state.store)?;
            if let Some(a) = store.accounts.iter_mut().find(|a| a.id == account_id) {
                a.usage_data = Some(usage_result.usage_data);
                crate::commands::common::update_account_status(a, usage_result.is_banned, usage_result.is_auth_error);
                let _ = crate::commands::common::save_store(&store);

                // 通知前端刷新账号列表
                let _ = app.emit("accounts-updated", ());

                if usage_result.is_banned {
                    log::warn!("[CLI Switch] 检测到账号已封禁");
                    return Err("账号已被封禁，无法切换到 CLI".to_string());
                }
            }
        }
        Err(e) => {
            log::warn!("[CLI Switch] 获取配额失败: {}, 继续切号", e);
            // 获取配额失败不阻止切号，但记录警告
        }
    }

    // 4. 构造切号载荷
    let payload = build_switch_payload(&refreshed_account)?;

    // 5. 执行切号写入（包括清除旧 key）
    crate::kiro::cli::switch_cli_account(&expanded_path, &payload)
}

/// 回滚切号操作
#[tauri::command]
pub fn rollback_cli_switch(
    db_path: String,
    backup: crate::kiro::cli::KiroCliWriteBackup,
) -> Result<(), String> {
    let expanded_path = expand_home_dir(&db_path)?;
    crate::kiro::cli::rollback_cli_switch(&expanded_path, &backup)
}

/// 构造切号载荷（从 Account 转换为 CLI 2.0 格式）
fn build_switch_payload(
    account: &Account,
) -> Result<crate::kiro::cli::KiroCliSwitchPayload, String> {
    // 判断账号类型
    let provider = account.provider.as_ref().ok_or("账号缺少 provider 字段")?;
    let (token_key, device_reg_key, auth_method) = match provider.as_str() {
        "BuilderId" => (
            "kirocli:odic:token",
            "kirocli:odic:device-registration",
            "IdC",
        ),
        "Google" | "Github" => (
            "kirocli:social:token",
            "kirocli:social:device-registration",
            "social",
        ),
        _ => return Err(format!("不支持的 provider: {}", provider)),
    };

    // 默认 profile_arn（与 Electron 版本一致）
    const SOCIAL_PROFILE_ARN: &str = "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK";
    const BUILDER_ID_PROFILE_ARN: &str = "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX";

    // 构造 token JSON
    let mut token_data = serde_json::json!({
        "access_token": account.access_token,
        "refresh_token": account.refresh_token,
        "region": account.region.as_ref().unwrap_or(&"us-east-1".to_string()),
    });

    // 总是生成新的 expires_at（当前时间 + 1小时）
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    token_data["expires_at"] = serde_json::json!(expires_at.to_rfc3339());

    // IdC 账号：补齐固定字段
    if auth_method == "IdC" {
        token_data["scopes"] = serde_json::json!([
            "codewhisperer:completions",
            "codewhisperer:analysis",
            "codewhisperer:conversations",
        ]);
        token_data["oauth_flow"] = serde_json::json!("Pkce");
        // IdC 账号使用 BuilderId profile_arn
        let profile_arn = account.profile_arn.as_ref()
            .map(|s| s.as_str())
            .unwrap_or(BUILDER_ID_PROFILE_ARN);
        token_data["profile_arn"] = serde_json::json!(profile_arn);
    }

    // Social 账号：补齐 start_url 和 profile_arn
    if auth_method == "social" {
        token_data["start_url"] = serde_json::json!("https://view.awsapps.com/start");
        let profile_arn = account.profile_arn.as_ref()
            .map(|s| s.as_str())
            .unwrap_or(SOCIAL_PROFILE_ARN);
        token_data["profile_arn"] = serde_json::json!(profile_arn);
    }

    let token_value = serde_json::to_string(&token_data)
        .map_err(|e| format!("序列化 token 失败: {e}"))?;

    // 构造 device registration JSON
    let device_reg_data = serde_json::json!({
        "client_id": account.client_id.as_ref().unwrap_or(&String::new()),
        "client_secret": account.client_secret.as_ref().unwrap_or(&String::new()),
        "region": account.region.as_ref().unwrap_or(&"us-east-1".to_string()),
    });

    let device_reg_value = serde_json::to_string(&device_reg_data)
        .map_err(|e| format!("序列化 device registration 失败: {e}"))?;

    Ok(crate::kiro::cli::KiroCliSwitchPayload {
        token_key: token_key.to_string(),
        token_value,
        device_reg_key: device_reg_key.to_string(),
        device_reg_value,
    })
}

#[cfg(test)]
mod tests {
    use super::lock_account_store;
    use std::sync::Mutex;

    #[test]
    fn lock_account_store_returns_error_when_mutex_is_poisoned() {
        let mutex = Mutex::new(());
        let _ = std::panic::catch_unwind(|| {
            let _guard = mutex.lock().expect("mutex should lock before poison");
            panic!("poison lock");
        });

        let err = lock_account_store(&mutex).expect_err("poisoned mutex should return error");
        assert!(err.contains("store lock"));
    }
}
