//! Login v3: device registration, the `start_login` state machine (password, 2FA, device
//! approval, region redirect), data-key recovery and the authenticated session.
//!
//! Not implemented: SSO (browser redirect) logins, WebAuthn/FIDO 2FA, biometric/passkey login,
//! and account recovery. SSO users fall back to their "alternate" master password, the same
//! fallback Commander offers.

use std::fmt;
use std::io::{BufRead, Write};
use std::str::FromStr;

use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use prost::Message;
use rsa::RsaPrivateKey;

use crate::crypto::{self, AesKey};
use crate::prelude::*;
use crate::proto::account_summary::{AccountSummaryElements, AccountSummaryRequest};
use crate::proto::authentication::{
    ApiRequestPayload,
    Device,
    DeviceRegistrationRequest,
    DeviceVerificationRequest,
    EncryptedDataKeyType,
    LoginMethod,
    LoginResponse,
    LoginState,
    LoginType,
    PasswordMethod,
    RegisterDeviceDataKeyRequest,
    RegisterDeviceInRegionRequest,
    SessionTokenType,
    StartLoginRequest,
    TwoFactorChannelInfo,
    TwoFactorChannelType as Ct,
    TwoFactorExpiration,
    TwoFactorPushType,
    TwoFactorSendPushRequest,
    TwoFactorValidateRequest,
    TwoFactorValidateResponse,
    TwoFactorValueType,
    ValidateAuthHashRequest,
    ValidateDeviceVerificationCodeRequest,
};
use crate::rest::{CLIENT_VERSION, LOCALE, RestContext};
use crate::settings::Settings;

pub struct Session {
    pub rest:          RestContext,
    pub user:          String,
    pub session_token: Vec<u8>,
    pub data_key:      AesKey,
    pub rsa_key:       Option<RsaPrivateKey>,
    pub ecc_key:       Option<SecretKey>,
    pub summary:       AccountSummaryElements,
}

impl Session {
    /// Registers this device's public-key-encrypted copy of the account data key.
    pub fn register_device_data_key(&mut self, device_token: Vec<u8>, device_key: &SecretKey) -> Result<Registration> {
        let request = RegisterDeviceDataKeyRequest {
            encrypted_device_token:    device_token,
            encrypted_device_data_key: crypto::encrypt_ec(&self.data_key, &device_key.public_key())?,
        };
        match self
            .rest
            .execute("authentication/register_encrypted_data_key_for_device", &self.session_token, &request)
        {
            Ok(_) => Ok(Registration::Added),
            Err(Error::Api(failure)) if failure.error == "device_data_key_exists" => Ok(Registration::AlreadyPresent),
            Err(error) => Err(error),
        }
    }

    /// Runs a legacy JSON ("v2") command through `vault/execute_v2_command`.
    pub fn execute_v2(&mut self, mut request: serde_json::Value) -> Result<serde_json::Value> {
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        if let Some(request) = request.as_object_mut() {
            request.insert("client_version".into(), CLIENT_VERSION.into());
            request.insert("client_time".into(), serde_json::Value::from(now_millis as u64));
            request.insert("locale".into(), LOCALE.into());
            request.insert("device_id".into(), "Commander".into());
            request.insert("session_token".into(), b64_encode(&self.session_token).into());
            request.insert("username".into(), self.user.to_lowercase().into());
        }
        let payload = ApiRequestPayload {
            payload: serde_json::to_vec(&request)?,
            ..Default::default()
        };
        let body = self.rest.execute_payload("vault/execute_v2_command", &payload)?;
        let response: serde_json::Value = serde_json::from_slice(&body)?;
        if response.get("result").and_then(serde_json::Value::as_str) == Some("success") {
            return Ok(response);
        }
        let field = |key: &str| {
            response
                .get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        Err(Error::api(field("result_code"), field("message")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    Added,
    AlreadyPresent,
}

/// Where the master password comes from: fail on a wrong supplied value or prompt interactively.
#[derive(Clone)]
pub enum Password {
    Given(String),
    Prompt,
}

impl From<Option<String>> for Password {
    fn from(password: Option<String>) -> Self {
        password.map_or(Self::Prompt, Self::Given)
    }
}

pub fn prompt(message: &str) -> Result<String> {
    eprint!("{message}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        return Err(Error::Cancelled);
    }
    Ok(line.trim().to_owned())
}

fn prompt_password(message: &str) -> Result<String> {
    Ok(rpassword::prompt_password(message)?)
}

fn device_name() -> String {
    let os = match std::env::consts::OS {
        "macos" => "macOS",
        other => other,
    };
    format!("Keeper CLI (Rust) on {os}")
}

const MAX_REGION_RETRIES: u8 = 4;

#[derive(Clone, Copy)]
enum DeviceRetry {
    Available,
    Used,
}

enum PasswordState {
    Pending(Password),
    Verified {
        password:   String,
        salt:       Vec<u8>,
        iterations: u32,
    },
}

enum RequestMode {
    Initial,
    Start(LoginType),
    Resume {
        login_token: Vec<u8>,
        login_type:  LoginType,
    },
}

impl RequestMode {
    fn login_type(&self) -> LoginType {
        match self {
            Self::Initial => LoginType::Normal,
            Self::Start(login_type) | Self::Resume { login_type, .. } => *login_type,
        }
    }

    fn restart(&self) -> Self {
        Self::Start(self.login_type())
    }
}

struct LoginFlow<'a> {
    config:   &'a mut Settings,
    rest:     RestContext,
    user:     String,
    password: PasswordState,
}

pub fn login(config: &mut Settings, user: String, password: Password) -> Result<Session> {
    let user = user.trim().to_owned();
    if user.is_empty() {
        return Err(Error::Cancelled);
    }
    clear_unbound_clone_code(config, &user);
    config.user = Some(user.clone());

    let mut retry = DeviceRetry::Available;
    loop {
        let result = LoginFlow {
            rest: RestContext::new(config.server.as_deref().unwrap_or(crate::settings::DEFAULT_SERVER))?,
            config,
            user: user.clone(),
            password: PasswordState::Pending(password.clone()),
        }
        .run();
        match result {
            Ok(session) => {
                config.user = Some(session.user.clone());
                config.server = Some(session.rest.host.to_string());
                config.file_user = config.user.clone();
                config.save()?;
                return Ok(session);
            }
            Err(Error::Api(failure))
                if failure.error == "device_not_registered" && matches!(retry, DeviceRetry::Available) =>
            {
                eprintln!("Registering new device...");
                config.device_token = None;
                config.private_key = None;
                config.clone_code = None;
                config.save()?;
                config.file_user = config.user.clone();
                retry = DeviceRetry::Used;
            }
            Err(error) => return Err(error),
        }
    }
}

fn clear_unbound_clone_code(config: &mut Settings, user: &str) {
    if config.clone_code.is_some()
        && !matches!(config.file_user.as_deref(), Some(owner) if owner.eq_ignore_ascii_case(user))
    {
        config.clone_code = None;
    }
}

impl LoginFlow<'_> {
    fn run(mut self) -> Result<Session> {
        let mut mode = RequestMode::Initial;
        let mut pending_response = None;
        let mut region_retries = 0;
        loop {
            let response = match pending_response.take() {
                Some(response) => response,
                None => {
                    let request = self.request_for(&mode)?;
                    let body = match self.rest.execute("authentication/start_login", &[], &request) {
                        Ok(body) => body,
                        Err(Error::Api(failure)) if failure.error == "region_redirect" => {
                            let Some(host) = failure.region_host.as_deref() else {
                                return Err(failure.into());
                            };
                            self.redirect(host, &mut region_retries)?;
                            mode = mode.restart();
                            continue;
                        }
                        Err(Error::Api(failure))
                            if failure.error == "device_not_registered"
                                && failure.additional_info.as_deref()
                                    == Some("invalid device token, not registered in this region") =>
                        {
                            let host = self.rest.host.to_string();
                            self.redirect(&host, &mut region_retries)?;
                            mode = mode.restart();
                            continue;
                        }
                        Err(Error::Api(mut failure)) if failure.error == "restricted_client_type" => {
                            failure.message = format!(
                                "{}.\n\nAsk your Keeper administrator to enable \"Commander SDK\" under Enforcement Policies > \
                                 Platform Restrictions for your role.",
                                failure.message
                            );
                            return Err(failure.into());
                        }
                        Err(Error::Api(mut failure)) => {
                            if let Some(info) = failure.additional_info.as_deref().filter(|info| !info.is_empty()) {
                                failure.message = format!("{}\n{info}", failure.message);
                            }
                            return Err(failure.into());
                        }
                        Err(error) => return Err(error),
                    };
                    LoginResponse::decode(body.as_slice())?
                }
            };
            let login_type = mode.login_type();
            match LoginState::try_from(response.login_state).unwrap_or(LoginState::InvalidLoginstate) {
                LoginState::LoggedIn => return self.finish(response),
                LoginState::DeviceApprovalRequired => {
                    self.device_approval(&response)?;
                    mode = RequestMode::Start(login_type);
                }
                LoginState::Requires2fa => {
                    mode = RequestMode::Resume {
                        login_token: self.two_factor(&response)?,
                        login_type,
                    };
                }
                LoginState::RequiresUsername => {
                    mode = RequestMode::Resume {
                        login_token: response.encrypted_login_token,
                        login_type,
                    };
                }
                LoginState::RedirectCloudSso | LoginState::RedirectOnsiteSso => {
                    eprintln!("SSO login is not supported by this client.");
                    eprintln!("Attempting to authenticate with a master password.");
                    eprintln!("(SSO users can create a Master Password in Web Vault > Settings)");
                    mode = RequestMode::Start(LoginType::Alternate);
                }
                LoginState::RegionRedirect => {
                    self.redirect(&response.state_specific_value, &mut region_retries)?;
                    mode = mode.restart();
                }
                LoginState::RequiresAuthHash => {
                    pending_response = Some(self.verify_password(&response)?);
                }
                LoginState::RequiresDeviceEncryptedDataKey => {
                    return Err(Error::Generic(
                        "This SSO device needs its data key approved; approve it from the Web Vault or Admin Console first"
                            .into(),
                    ));
                }
                LoginState::DeviceAccountLocked | LoginState::DeviceLocked => {
                    return Err(Error::Generic("This device is locked".into()));
                }
                LoginState::AccountLocked => {
                    return Err(Error::Generic(format!("User account `{}` is LOCKED", self.user)));
                }
                LoginState::LicenseExpired => return Err(Error::Generic("Your Keeper license has expired".into())),
                LoginState::Upgrade => {
                    return Err(Error::Generic("Application or device is out of date and requires an update.".into()));
                }
                LoginState::RequiresAccountCreation => {
                    return Err(Error::Generic("This account needs to be created.".into()));
                }
                other => return Err(Error::Generic(format!("Unsupported login state {other:?}"))),
            }
        }
    }

    fn request_for(&mut self, mode: &RequestMode) -> Result<StartLoginRequest> {
        let mut request = StartLoginRequest {
            client_version: CLIENT_VERSION.into(),
            encrypted_device_token: self.device_token()?,
            login_method: LoginMethod::ExistingAccount as i32,
            ..Default::default()
        };
        match mode {
            RequestMode::Initial => {
                request.username = self.user.to_lowercase();
                if let Some(clone_code) = self.config.clone_code.as_deref().filter(|code| !code.trim().is_empty()) {
                    request.clone_code = decode_credential(clone_code, "clone code")?;
                    request.username.clear();
                }
            }
            RequestMode::Start(login_type) => {
                request.username = self.user.to_lowercase();
                request.login_type = *login_type as i32;
            }
            RequestMode::Resume {
                login_token,
                login_type,
            } => {
                request.username = self.user.to_lowercase();
                request.encrypted_login_token = login_token.clone();
                request.login_method = LoginMethod::InvalidLoginmethod as i32;
                request.login_type = *login_type as i32;
            }
        }
        Ok(request)
    }

    fn redirect(&mut self, host: &str, retries: &mut u8) -> Result<()> {
        if *retries >= MAX_REGION_RETRIES {
            return Err(Error::api("region_redirect_limit", "too many Keeper region redirects"));
        }
        *retries += 1;
        self.rest.host = host.parse()?;
        eprintln!("Redirecting to region: {}", self.rest.host);
        self.register_device_in_region()
    }

    fn register_device_in_region(&mut self) -> Result<()> {
        let request = RegisterDeviceInRegionRequest {
            encrypted_device_token: self.device_token()?,
            client_version: CLIENT_VERSION.into(),
            device_name: device_name(),
            device_public_key: self
                .device_key()?
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            ..Default::default()
        };
        self.rest
            .execute("authentication/register_device_in_region", &[], &request)
            .map(drop)
            .map_err(regional_registration_failure)
    }

    fn device_key(&self) -> Result<SecretKey> {
        let encoded = self
            .config
            .private_key
            .as_deref()
            .ok_or_else(|| Error::Generic("device private key missing from config".into()))?;
        Ok(SecretKey::from_slice(&decode_credential(encoded, "device private key")?)?)
    }

    fn device_token(&mut self) -> Result<Vec<u8>> {
        if let Some(token) = &self.config.device_token {
            return decode_credential(token, "device token");
        }
        let private = SecretKey::random(&mut rand::rngs::OsRng);
        let request = DeviceRegistrationRequest {
            client_version: CLIENT_VERSION.into(),
            device_name: device_name(),
            device_public_key: private.public_key().to_encoded_point(false).as_bytes().to_vec(),
            ..Default::default()
        };
        let body = self.rest.execute("authentication/register_device", &[], &request)?;
        let device = Device::decode(body.as_slice())?;
        self.config.device_token = Some(b64_encode(&device.encrypted_device_token));
        self.config.private_key = Some(b64_encode(&private.to_bytes()));
        self.config.save()?;
        self.config.file_user = self.config.user.clone();
        Ok(device.encrypted_device_token)
    }

    fn verify_password(&mut self, response: &LoginResponse) -> Result<LoginResponse> {
        let salt_entry = response
            .salt
            .iter()
            .find(|salt| salt.name.eq_ignore_ascii_case("alternate"))
            .or_else(|| response.salt.first())
            .ok_or_else(|| Error::Generic("Account recovery is required; complete it in the Web Vault".into()))?;
        let salt = salt_entry.salt.clone();
        let iterations =
            u32::try_from(salt_entry.iterations).map_err(|_| Error::Generic("invalid PBKDF2 iterations".into()))?;

        loop {
            let password = match &self.password {
                PasswordState::Pending(Password::Given(password)) => password.clone(),
                PasswordState::Pending(Password::Prompt) => {
                    eprintln!("Enter master password for {}", self.user);
                    let password = prompt_password("Password: ")?;
                    if password.is_empty() {
                        return Err(Error::Cancelled);
                    }
                    password
                }
                PasswordState::Verified { password, .. } => password.clone(),
            };
            let request = ValidateAuthHashRequest {
                password_method:       PasswordMethod::Entered as i32,
                auth_response:         crypto::derive_keyhash_v1(&password, &salt, iterations),
                encrypted_login_token: response.encrypted_login_token.clone(),
            };
            let body = match self.rest.execute("authentication/validate_auth_hash", &[], &request) {
                Ok(body) => body,
                Err(Error::Api(mut failure)) if failure.error == "auth_failed" => {
                    match &self.password {
                        PasswordState::Pending(Password::Prompt) => {
                            eprintln!("Invalid email or password combination, please re-enter.");
                            continue;
                        }
                        _ => {
                            failure.message = "Invalid email or password combination.".into();
                            return Err(failure.into());
                        }
                    }
                }
                Err(error) => return Err(error),
            };
            let response = LoginResponse::decode(body.as_slice())?;
            self.password = PasswordState::Verified {
                password,
                salt,
                iterations,
            };
            return Ok(response);
        }
    }

    /// Returns once the user wants the login re-checked (after approving, or entering a code).
    fn device_approval(&mut self, response: &LoginResponse) -> Result<()> {
        eprintln!("\nDevice Approval Required\n");
        eprintln!("  1. Email - Send approval link to your email");
        eprintln!("  2. Keeper Push - Send notification to an approved device");
        eprintln!("  3. 2FA Push - Send code via your 2FA method");
        eprintln!("  c <code>. Enter a verification code");
        eprintln!("  q. Cancel login\n");
        loop {
            let selection = prompt("Selection (or Enter to check status): ")?.to_lowercase();
            let result = match selection.as_str() {
                "" => return Ok(()),
                "q" => return Err(Error::Cancelled),
                "1" | "es" | "email_send" => {
                    let request = DeviceVerificationRequest {
                        username: self.user.to_lowercase(),
                        encrypted_device_token: self.device_token()?,
                        verification_channel: "email".into(),
                        client_version: CLIENT_VERSION.into(),
                        ..Default::default()
                    };
                    self.rest
                        .execute("authentication/request_device_verification", &[], &request)
                        .map(drop)
                        .map(|()| eprintln!("Email sent to {}. Click the approval link, then press Enter.", self.user))
                }
                "2" | "kp" | "keeper_push" => {
                    self.send_push(&response.encrypted_login_token, TwoFactorPushType::TwoFaPushKeeper, Vec::new())
                        .map(|()| eprintln!("Push notification sent. Approve on your device, then press Enter."))
                }
                "3" | "2fs" | "2fa_send" => {
                    self.send_push(&response.encrypted_login_token, TwoFactorPushType::TwoFaPushNone, Vec::new())
                        .map(|()| eprintln!("2FA code sent. Enter it with 'c <code>'."))
                }
                selection if selection == "c" || selection.starts_with("c ") => {
                    let code = match selection.strip_prefix("c ") {
                        Some(code) => code.trim().to_owned(),
                        None => prompt("Enter verification code: ")?,
                    };
                    if code.is_empty() {
                        continue;
                    }
                    let request = ValidateDeviceVerificationCodeRequest {
                        username: self.user.to_lowercase(),
                        client_version: CLIENT_VERSION.into(),
                        verification_code: code.clone(),
                        ..Default::default()
                    };
                    let verified =
                        match self
                            .rest
                            .execute("authentication/validate_device_verification_code", &[], &request)
                        {
                            Err(error) if is_device_not_registered(&error) => return Err(error),
                            result => {
                                result.map(drop).or_else(|_| {
                                    self.validate_2fa(
                                        &response.encrypted_login_token,
                                        &code,
                                        TwoFactorValueType::TwoFaCodeNone,
                                        Vec::new(),
                                        TwoFactorExpiration::TwoFaExpImmediately,
                                    )
                                    .map(drop)
                                })
                            }
                        };
                    match verified {
                        Ok(()) => return Ok(()),
                        Err(error) if is_device_not_registered(&error) => return Err(error),
                        Err(_) => {
                            eprintln!("Invalid code. Please try again.");
                            continue;
                        }
                    }
                }
                _ => {
                    eprintln!("Invalid selection. Enter 1, 2, 3, c, q, or press Enter.");
                    continue;
                }
            };
            if let Err(error) = result {
                if is_device_not_registered(&error) {
                    return Err(error);
                }
                eprintln!("{error}");
            }
        }
    }

    fn send_push(&mut self, login_token: &[u8], push_type: TwoFactorPushType, channel_uid: Vec<u8>) -> Result<()> {
        let request = TwoFactorSendPushRequest {
            encrypted_login_token: login_token.to_vec(),
            push_type: push_type as i32,
            channel_uid,
            ..Default::default()
        };
        self.rest
            .execute("authentication/2fa_send_push", &[], &request)
            .map(drop)
    }

    fn validate_2fa(
        &mut self,
        login_token: &[u8],
        code: &str,
        value_type: TwoFactorValueType,
        channel_uid: Vec<u8>,
        expire_in: TwoFactorExpiration,
    ) -> Result<Vec<u8>> {
        let request = TwoFactorValidateRequest {
            encrypted_login_token: login_token.to_vec(),
            value: code.to_owned(),
            value_type: value_type as i32,
            channel_uid,
            expire_in: expire_in as i32,
            ..Default::default()
        };
        let body = self.rest.execute("authentication/2fa_validate", &[], &request)?;
        Ok(TwoFactorValidateResponse::decode(body.as_slice())?.encrypted_login_token)
    }

    fn two_factor(&mut self, response: &LoginResponse) -> Result<Vec<u8>> {
        let mut channels: Vec<TwoFactorChannelInfo> = response
            .channels
            .iter()
            .filter(|channel| Channel::try_from(channel.channel_type).is_ok())
            .cloned()
            .collect();
        if channels.is_empty() {
            if !response.channels.is_empty() {
                eprintln!(
                    "Your 2FA methods (e.g. security keys) are not supported here; falling back to backup codes."
                );
            }
            channels.push(TwoFactorChannelInfo {
                channel_type: Ct::TwoFaCtBackup as i32,
                ..Default::default()
            });
        }

        eprintln!("\nTwo-Factor Authentication Required\n");
        for (index, channel) in channels.iter().enumerate() {
            let kind = Channel::try_from(channel.channel_type).expect("filtered supported channels");
            eprintln!("  {}. {kind} {} {}", index + 1, channel.channel_name, channel.phone_number);
        }
        eprintln!("  q. Cancel login\n");
        let channel = loop {
            let selection = prompt("Selection: ")?;
            if selection == "q" {
                return Err(Error::Cancelled);
            }
            if let Some(channel) = selection
                .parse::<usize>()
                .ok()
                .and_then(|index| index.checked_sub(1))
                .and_then(|index| channels.get(index))
            {
                break channel.clone();
            }
            eprintln!("Invalid entry.");
        };
        let channel_type = Channel::try_from(channel.channel_type).expect("filtered supported channels");
        let value_type = TwoFactorValueType::from(channel_type);

        if channel_type == Channel::Sms {
            match self.send_push(
                &response.encrypted_login_token,
                TwoFactorPushType::TwoFaPushSms,
                channel.channel_uid.clone(),
            ) {
                Ok(()) => eprintln!("SMS sent successfully."),
                Err(error) if is_device_not_registered(&error) => return Err(error),
                Err(_) => eprintln!("Was unable to send SMS."),
            }
        }

        let durations = [
            Expiration(TwoFactorExpiration::TwoFaExpImmediately),
            Expiration(TwoFactorExpiration::TwoFaExp12Hours),
            Expiration(TwoFactorExpiration::TwoFaExp24Hours),
            Expiration(TwoFactorExpiration::TwoFaExp30Days),
            Expiration(TwoFactorExpiration::TwoFaExpNever),
        ];
        let allowed: Vec<_> = durations
            .into_iter()
            .filter(|duration| duration.0 as i32 <= channel.max_expiration.max(0))
            .collect();
        let mut duration = Expiration(TwoFactorExpiration::TwoFaExpImmediately);
        let names = allowed.iter().map(Expiration::token).collect::<Vec<_>>().join("|");
        eprintln!("\n2FA Code Duration: {duration}.\nTo change duration: 2fa_duration={names}");

        loop {
            let answer = prompt("\nEnter 2FA Code: ")?;
            if let Some(value) = answer.strip_prefix("2fa_duration=") {
                match value.trim().parse::<Expiration>() {
                    Ok(parsed) if allowed.contains(&parsed) => {
                        duration = parsed;
                        eprintln!("2FA Code Duration: {duration}");
                    }
                    _ => eprintln!("Invalid 2FA Duration: {value}"),
                }
                continue;
            }
            if answer.is_empty() {
                continue;
            }
            match self.validate_2fa(
                &response.encrypted_login_token,
                &answer,
                value_type,
                channel.channel_uid.clone(),
                duration.0,
            ) {
                Ok(token) => {
                    eprintln!("2FA code verified.");
                    return Ok(token);
                }
                Err(error) if is_device_not_registered(&error) => return Err(error),
                Err(_) => eprintln!("Invalid 2FA code. Please try again."),
            }
        }
    }

    fn finish(self, response: LoginResponse) -> Result<Session> {
        let data_key = match EncryptedDataKeyType::try_from(response.encrypted_data_key_type) {
            Ok(EncryptedDataKeyType::ByDevicePublicKey) => {
                crypto::decrypt_ec(&response.encrypted_data_key, &self.device_key()?)?
            }
            Ok(EncryptedDataKeyType::ByPassword) => {
                match &self.password {
                    PasswordState::Verified { password, .. } => {
                        crypto::decrypt_encryption_params(&response.encrypted_data_key, password)?
                    }
                    PasswordState::Pending(_) => {
                        return Err(Error::Generic("server did not request the master password".into()));
                    }
                }
            }
            Ok(EncryptedDataKeyType::ByAlternate) => {
                match &self.password {
                    PasswordState::Verified {
                        password,
                        salt,
                        iterations,
                    } => {
                        let key = crypto::derive_keyhash_v2("data_key", password, salt, *iterations);
                        crypto::decrypt_aes_v2(&response.encrypted_data_key, &key)?
                    }
                    PasswordState::Pending(_) => {
                        return Err(Error::Generic("server did not request the master password".into()));
                    }
                }
            }
            other => return Err(Error::Generic(format!("Data key type {other:?} is not supported"))),
        };
        self.config.clone_code = (!response.clone_code.is_empty()).then(|| b64_encode(&response.clone_code));

        match SessionTokenType::try_from(response.session_token_type).unwrap_or(SessionTokenType::Restrict) {
            SessionTokenType::NoRestriction => {}
            SessionTokenType::Purchase | SessionTokenType::Restrict => {
                return Err(Error::Generic(
                    "Your Keeper account has expired. Renew it in the Keeper app or at https://keepersecurity.com/vault"
                        .into(),
                ));
            }
            SessionTokenType::AccountRecovery => {
                return Err(Error::Generic(
                    "Your Master Password has expired; change it in the Web Vault, then log in again".into(),
                ));
            }
            SessionTokenType::ShareAccount => {
                return Err(Error::Generic(
                    "Account transfer consent is required; accept it in the Web Vault, then log in again".into(),
                ));
            }
            other => {
                return Err(Error::Generic(format!(
                    "Please log into the Web Vault to update your account settings ({other:?})"
                )));
            }
        }

        let mut session = Session {
            rest:          self.rest,
            user:          response.primary_username,
            session_token: response.encrypted_session_token,
            data_key:      AesKey::try_from(data_key)?,
            rsa_key:       None,
            ecc_key:       None,
            summary:       AccountSummaryElements::default(),
        };
        let summary = AccountSummaryElements::decode(
            session
                .rest
                .execute(
                    "login/account_summary",
                    &session.session_token,
                    &AccountSummaryRequest {
                        summary_version: 3,
                        ..Default::default()
                    },
                )?
                .as_slice(),
        )?;
        if let Some(keys) = &summary.keys_info {
            if !keys.encrypted_private_key.is_empty() {
                let der = crypto::decrypt_cbc::<aes::cipher::block_padding::Pkcs7>(
                    &keys.encrypted_private_key,
                    &session.data_key,
                )?;
                session.rsa_key = Some(crypto::load_rsa_private_key(&der)?);
            }
            if !keys.encrypted_ecc_private_key.is_empty() {
                let raw = crypto::decrypt_aes_v2(&keys.encrypted_ecc_private_key, &session.data_key)?;
                session.ecc_key = Some(SecretKey::from_slice(&raw)?);
            }
        }
        session.summary = summary;
        Ok(session)
    }
}

fn decode_credential(encoded: &str, field: &str) -> Result<Vec<u8>> {
    let encoded = encoded.trim().trim_end_matches('=');
    if encoded.is_empty() {
        return Err(Error::Generic(format!("empty {field} in config")));
    }
    data_encoding::BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|error| Error::Generic(format!("invalid {field} encoding: {error}")))
}

fn regional_registration_failure(error: Error) -> Error {
    match error {
        Error::Api(mut failure) => {
            failure.error = "device_not_registered".into();
            Error::Api(failure)
        }
        other => {
            Error::api("device_not_registered", format!("device registration failed in redirected region: {other}"))
        }
    }
}
fn is_device_not_registered(error: &Error) -> bool {
    matches!(error, Error::Api(failure) if failure.error == "device_not_registered")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Channel {
    Totp,
    Sms,
    Duo,
    Rsa,
    Dna,
    Backup,
}

impl TryFrom<i32> for Channel {
    type Error = ();

    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        Ok(match Ct::try_from(value).map_err(|_| ())? {
            Ct::TwoFaCtTotp => Self::Totp,
            Ct::TwoFaCtSms => Self::Sms,
            Ct::TwoFaCtDuo => Self::Duo,
            Ct::TwoFaCtRsa => Self::Rsa,
            Ct::TwoFaCtDna => Self::Dna,
            Ct::TwoFaCtBackup => Self::Backup,
            _ => return Err(()),
        })
    }
}

impl From<Channel> for TwoFactorValueType {
    fn from(channel: Channel) -> Self {
        match channel {
            Channel::Totp => Self::TwoFaCodeTotp,
            Channel::Sms => Self::TwoFaCodeSms,
            Channel::Duo => Self::TwoFaCodeDuo,
            Channel::Rsa => Self::TwoFaCodeRsa,
            Channel::Dna => Self::TwoFaCodeDna,
            Channel::Backup => Self::TwoFaCodeNone,
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Totp => "TOTP (Google and Microsoft Authenticator)",
            Self::Sms => "Send SMS Code",
            Self::Duo => "DUO",
            Self::Rsa => "RSA SecurID",
            Self::Dna => "Keeper DNA (Watch)",
            Self::Backup => "Backup Codes",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Expiration(TwoFactorExpiration);

impl Expiration {
    fn token(&self) -> &'static str {
        match self.0 {
            TwoFactorExpiration::TwoFaExpImmediately => "login",
            TwoFactorExpiration::TwoFaExp5Minutes => "5_minutes",
            TwoFactorExpiration::TwoFaExp12Hours => "12_hours",
            TwoFactorExpiration::TwoFaExp24Hours => "24_hours",
            TwoFactorExpiration::TwoFaExp30Days => "30_days",
            TwoFactorExpiration::TwoFaExpNever => "forever",
        }
    }
}

impl FromStr for Expiration {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "login" => Ok(Self(TwoFactorExpiration::TwoFaExpImmediately)),
            "5_minutes" => Ok(Self(TwoFactorExpiration::TwoFaExp5Minutes)),
            "12_hours" => Ok(Self(TwoFactorExpiration::TwoFaExp12Hours)),
            "24_hours" => Ok(Self(TwoFactorExpiration::TwoFaExp24Hours)),
            "30_days" => Ok(Self(TwoFactorExpiration::TwoFaExp30Days)),
            "forever" => Ok(Self(TwoFactorExpiration::TwoFaExpNever)),
            _ => Err(Error::Generic(format!("invalid 2FA duration {value:?}"))),
        }
    }
}

impl fmt::Display for Expiration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            TwoFactorExpiration::TwoFaExpImmediately | TwoFactorExpiration::TwoFaExp5Minutes => "Require Every Login",
            TwoFactorExpiration::TwoFaExp12Hours => "Ask Every 12 hours",
            TwoFactorExpiration::TwoFaExp24Hours => "Ask Every 24 hours",
            TwoFactorExpiration::TwoFaExp30Days => "Ask Every 30 days",
            TwoFactorExpiration::TwoFaExpNever => "Save on this Device Forever",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_credentials_are_redacted() {
        let error = decode_credential("super-secret!", "device token")
            .unwrap_err()
            .to_string();
        assert!(error.contains("device token"));
        assert!(!error.contains("super-secret"));
    }

    #[test]
    fn two_factor_duration_roundtrips_through_traits() {
        for duration in [
            TwoFactorExpiration::TwoFaExpImmediately,
            TwoFactorExpiration::TwoFaExp12Hours,
            TwoFactorExpiration::TwoFaExp24Hours,
            TwoFactorExpiration::TwoFaExp30Days,
            TwoFactorExpiration::TwoFaExpNever,
        ] {
            let wrapped = Expiration(duration);
            assert_eq!(wrapped.token().parse::<Expiration>().unwrap(), wrapped);
        }
    }

    #[test]
    fn clone_code_is_bound_to_its_file_user() {
        let mut settings = Settings::default();
        settings.file_user = Some("alice@example.com".into());
        settings.clone_code = Some("alice-code".into());
        clear_unbound_clone_code(&mut settings, "bob@example.com");
        assert!(settings.clone_code.is_none());

        settings.clone_code = Some("alice-code".into());
        clear_unbound_clone_code(&mut settings, "ALICE@example.com");
        assert_eq!(settings.clone_code.as_deref(), Some("alice-code"));
    }
}
