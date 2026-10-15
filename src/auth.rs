//! Login v3: device registration, the `start_login` state machine (password, 2FA, device
//! approval, region redirect), data-key recovery and the authenticated session.
//!
//! Not implemented: SSO (browser redirect) logins, WebAuthn/FIDO 2FA, biometric/passkey login,
//! and account recovery. SSO users fall back to their "alternate" master password, the same
//! fallback Commander offers.

use std::io::{BufRead, Write};

use p256::SecretKey;
use prost::Message;
use rsa::RsaPrivateKey;

use crate::config::Config;
use crate::crypto;
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
use crate::rest::{CLIENT_VERSION, Response, RestContext};

pub struct Session {
    pub rest:        RestContext,
    pub user:        String,
    pub account_uid: Vec<u8>,
    session_token:   Vec<u8>,
    pub data_key:    Vec<u8>,
    pub rsa_key:     Option<RsaPrivateKey>,
    pub ecc_key:     Option<SecretKey>,
    pub summary:     AccountSummaryElements,
}

impl Session {
    /// Authenticated protobuf call; returns the decrypted response body.
    pub fn call(&mut self, endpoint: &str, request: Option<&dyn MessageBytes>) -> Result<Vec<u8>> {
        let payload = ApiRequestPayload {
            payload: request.map(MessageBytes::bytes).unwrap_or_default(),
            encrypted_session_token: self.session_token.clone(),
            ..Default::default()
        };
        match self.rest.execute(endpoint, &payload)? {
            Response::Ok(body) => Ok(body),
            Response::Failed(f) => Err(f.into()),
        }
    }

    pub fn call_typed<Rs: Message + Default>(&mut self, endpoint: &str, request: &dyn MessageBytes) -> Result<Rs> {
        Ok(Rs::decode(self.call(endpoint, Some(request))?.as_slice())?)
    }

    pub fn logout(&mut self) -> Result<()> {
        self.call("vault/logout_v3", None).map(drop)
    }
}

/// Object-safe stand-in for `prost::Message::encode_to_vec`.
pub trait MessageBytes {
    fn bytes(&self) -> Vec<u8>;
}

impl<M: Message> MessageBytes for M {
    fn bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

fn unauthenticated(rest: &mut RestContext, endpoint: &str, request: &dyn MessageBytes) -> Result<Response> {
    let payload = ApiRequestPayload {
        payload: request.bytes(),
        ..Default::default()
    };
    rest.execute(endpoint, &payload)
}

fn unauthenticated_ok(rest: &mut RestContext, endpoint: &str, request: &dyn MessageBytes) -> Result<Vec<u8>> {
    match unauthenticated(rest, endpoint, request)? {
        Response::Ok(body) => Ok(body),
        Response::Failed(f) => Err(f.into()),
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

struct LoginFlow<'a> {
    config:    &'a mut Config,
    rest:      RestContext,
    user:      String,
    password:  Option<String>,
    /// Supplied on the command line: a wrong one must fail instead of re-prompting forever.
    password_is_fixed: bool,
    salt:      Vec<u8>,
    iterations: u32,
    alternate: bool,
}

enum DeviceTokenProblem {
    WrongRegion,
    Invalid,
}

pub fn login(config: &mut Config, user: Option<String>, password: Option<String>) -> Result<Session> {
    let user = match user.or_else(|| config.get("user").map(str::to_owned)) {
        Some(u) => u,
        None => prompt("Email: ")?,
    };
    if user.is_empty() {
        return Err(Error::Cancelled);
    }
    if config.get("user").is_some_and(|u| !u.eq_ignore_ascii_case(&user)) {
        // A clone code resumes a specific account's session; it is meaningless for another user.
        config.set("clone_code", None);
    }
    let flow = LoginFlow {
        rest: RestContext::new(config.server())?,
        config,
        user,
        password_is_fixed: password.is_some(),
        password,
        salt: Vec::new(),
        iterations: 0,
        alternate: false,
    };
    let session = flow.run()?;
    config.set("user", Some(session.user.clone()));
    config.set("server", Some(session.rest.host()));
    config.save()?;
    Ok(session)
}

impl LoginFlow<'_> {
    fn run(mut self) -> Result<Session> {
        let mut resp = match self.start_login(LoginType::Normal, true) {
            Err(Error::Api { code, .. }) if code == "device_not_registered" => {
                eprintln!("Registering new device...");
                self.reset_device();
                self.start_login(LoginType::Normal, false)?
            }
            other => other?,
        };

        loop {
            let state = LoginState::try_from(resp.login_state).unwrap_or(LoginState::InvalidLoginstate);
            resp = match state {
                LoginState::LoggedIn => return self.finish(resp),
                LoginState::DeviceApprovalRequired => {
                    if self.device_approval(&resp)? {
                        self.start_login(LoginType::Normal, false)?
                    } else {
                        resp
                    }
                }
                LoginState::Requires2fa => {
                    let token = self.two_factor(&resp)?;
                    self.resume_login(token, self.login_type(), LoginMethod::ExistingAccount)?
                }
                LoginState::RequiresUsername => {
                    self.resume_login(resp.encrypted_login_token, LoginType::Normal, LoginMethod::ExistingAccount)?
                }
                LoginState::RedirectCloudSso | LoginState::RedirectOnsiteSso => {
                    eprintln!("SSO login is not supported by this client.");
                    eprintln!("Attempting to authenticate with a master password.");
                    eprintln!("(SSO users can create a Master Password in Web Vault > Settings)");
                    self.alternate = true;
                    self.start_login(LoginType::Alternate, false)?
                }
                LoginState::RegionRedirect => {
                    self.redirect(&resp.state_specific_value)?;
                    self.start_login(self.login_type(), false)?
                }
                LoginState::RequiresAuthHash => self.verify_password(&resp)?,
                LoginState::RequiresDeviceEncryptedDataKey => {
                    return Err(Error::Generic(
                        "This SSO device needs its data key approved; approve it from the Web Vault or Admin Console first".into(),
                    ));
                }
                LoginState::DeviceAccountLocked | LoginState::DeviceLocked => {
                    self.reset_device();
                    self.config.save()?;
                    return Err(Error::Generic("This device is locked".into()));
                }
                LoginState::AccountLocked => return Err(Error::Generic(format!("User account `{}` is LOCKED", self.user))),
                LoginState::LicenseExpired => return Err(Error::Generic("Your Keeper license has expired".into())),
                LoginState::Upgrade => {
                    return Err(Error::Generic("Application or device is out of date and requires an update.".into()));
                }
                LoginState::RequiresAccountCreation => return Err(Error::Generic("This account needs to be created.".into())),
                other => return Err(Error::Generic(format!("Unsupported login state {other:?}"))),
            };
        }
    }

    fn login_type(&self) -> LoginType {
        if self.alternate {
            LoginType::Alternate
        } else {
            LoginType::Normal
        }
    }

    fn reset_device(&mut self) {
        for key in ["device_token", "private_key", "clone_code"] {
            self.config.set(key, None);
        }
    }

    fn device_key(&self) -> Result<SecretKey> {
        let encoded = self
            .config
            .get("private_key")
            .ok_or_else(|| Error::Generic("device private key missing from config".into()))?;
        crypto::load_ec_private_key(&b64_decode(encoded)?)
    }

    fn device_token(&mut self) -> Result<Vec<u8>> {
        if let Some(token) = self.config.get("device_token") {
            return b64_decode(token);
        }
        let private = crypto::generate_ec_key();
        let rq = DeviceRegistrationRequest {
            client_version: CLIENT_VERSION.into(),
            device_name: device_name(),
            device_public_key: crypto::unload_ec_public_key(&private.public_key()),
            ..Default::default()
        };
        let device = Device::decode(unauthenticated_ok(&mut self.rest, "authentication/register_device", &rq)?.as_slice())?;
        self.config.set("device_token", Some(b64_encode(&device.encrypted_device_token)));
        self.config.set("private_key", Some(b64_encode(&private.to_bytes())));
        self.config.save()?;
        Ok(device.encrypted_device_token)
    }

    fn redirect(&mut self, host: &str) -> Result<()> {
        eprintln!("Redirecting to region: {host}");
        self.rest.set_server(host);
        let rq = RegisterDeviceInRegionRequest {
            encrypted_device_token: self.device_token()?,
            client_version: CLIENT_VERSION.into(),
            device_name: device_name(),
            device_public_key: crypto::unload_ec_public_key(&self.device_key()?.public_key()),
            ..Default::default()
        };
        match unauthenticated(&mut self.rest, "authentication/register_device_in_region", &rq)? {
            Response::Ok(_) => Ok(()),
            // "exists" means the device is already known in that region, which is the goal.
            Response::Failed(f) if f.error == "exists" => Ok(()),
            Response::Failed(f) => Err(f.into()),
        }
    }

    fn start_login(&mut self, login_type: LoginType, use_clone_code: bool) -> Result<LoginResponse> {
        let clone_code = if use_clone_code {
            self.config.get("clone_code").map(b64_decode).transpose()?
        } else {
            None
        };
        let mut rq = StartLoginRequest {
            client_version: CLIENT_VERSION.into(),
            username: self.user.to_lowercase(),
            encrypted_device_token: self.device_token()?,
            login_type: login_type as i32,
            login_method: LoginMethod::ExistingAccount as i32,
            ..Default::default()
        };
        if let Some(code) = clone_code {
            rq.clone_code = code;
            rq.username.clear();
        }
        self.send_start_login(&rq, login_type)
    }

    fn resume_login(&mut self, login_token: Vec<u8>, login_type: LoginType, method: LoginMethod) -> Result<LoginResponse> {
        let rq = StartLoginRequest {
            client_version: CLIENT_VERSION.into(),
            username: self.user.to_lowercase(),
            encrypted_device_token: self.device_token()?,
            encrypted_login_token: login_token,
            login_type: login_type as i32,
            login_method: method as i32,
            ..Default::default()
        };
        self.send_start_login(&rq, login_type)
    }

    fn send_start_login(&mut self, rq: &StartLoginRequest, login_type: LoginType) -> Result<LoginResponse> {
        let failure = match unauthenticated(&mut self.rest, "authentication/start_login", rq)? {
            Response::Ok(body) => return Ok(LoginResponse::decode(body.as_slice())?),
            Response::Failed(f) => f,
        };
        let problem = match failure.error.as_str() {
            "region_redirect" => {
                let host = failure.region_host.clone().unwrap_or_default();
                self.redirect(&host)?;
                return self.start_login(login_type, false);
            }
            "device_not_registered"
                if failure.additional_info.as_deref() == Some("invalid device token, not registered in this region") =>
            {
                DeviceTokenProblem::WrongRegion
            }
            "device_not_registered" => DeviceTokenProblem::Invalid,
            "restricted_client_type" => {
                return Err(Error::api(
                    failure.error,
                    format!(
                        "{}.\n\nAsk your Keeper administrator to enable \"Commander SDK\" under Enforcement Policies > \
                         Platform Restrictions for your role.",
                        failure.message
                    ),
                ));
            }
            _ => {
                let mut message = failure.message;
                if let Some(info) = failure.additional_info.filter(|i| !i.is_empty()) {
                    message = format!("{message}\n{info}");
                }
                return Err(Error::api(failure.error, message));
            }
        };
        match problem {
            DeviceTokenProblem::WrongRegion => {
                let host = self.rest.host();
                self.redirect(&host)?;
                self.start_login(login_type, false)
            }
            DeviceTokenProblem::Invalid => Err(Error::api("device_not_registered", failure.message)),
        }
    }

    fn verify_password(&mut self, resp: &LoginResponse) -> Result<LoginResponse> {
        let salt = resp
            .salt
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case("alternate"))
            .or_else(|| resp.salt.first())
            .ok_or_else(|| Error::Generic("Account recovery is required; complete it in the Web Vault".into()))?;
        self.salt = salt.salt.clone();
        self.iterations = u32::try_from(salt.iterations).map_err(|_| Error::Generic("invalid PBKDF2 iterations".into()))?;

        let mut announced = false;
        loop {
            let password = match self.password.clone() {
                Some(p) => p,
                None => {
                    if !announced {
                        eprintln!("Enter master password for {}", self.user);
                        announced = true;
                    }
                    let p = prompt_password("Password: ")?;
                    if p.is_empty() {
                        return Err(Error::Cancelled);
                    }
                    p
                }
            };
            let rq = ValidateAuthHashRequest {
                password_method: PasswordMethod::Entered as i32,
                auth_response: crypto::derive_keyhash_v1(&password, &self.salt, self.iterations),
                encrypted_login_token: resp.encrypted_login_token.clone(),
            };
            match unauthenticated(&mut self.rest, "authentication/validate_auth_hash", &rq)? {
                Response::Ok(body) => {
                    self.password = Some(password);
                    return Ok(LoginResponse::decode(body.as_slice())?);
                }
                Response::Failed(f) => {
                    let message = if f.error == "auth_failed" {
                        "Invalid email or password combination, please re-enter.".to_owned()
                    } else {
                        f.message.clone()
                    };
                    if self.password_is_fixed || f.error != "auth_failed" {
                        return Err(Error::api(f.error, message));
                    }
                    eprintln!("{message}");
                    self.password = None;
                }
            }
        }
    }

    /// Returns true when the login should be restarted to pick up an approval.
    fn device_approval(&mut self, resp: &LoginResponse) -> Result<bool> {
        eprintln!("\nDevice Approval Required\n");
        eprintln!("  1. Email - Send approval link to your email");
        eprintln!("  2. Keeper Push - Send notification to an approved device");
        eprintln!("  3. 2FA Push - Send code via your 2FA method");
        eprintln!("  c <code>. Enter a verification code");
        eprintln!("  q. Cancel login\n");
        loop {
            let selection = prompt("Selection (or Enter to check status): ")?.to_lowercase();
            let result = match selection.as_str() {
                "" => return Ok(true),
                "q" => return Err(Error::Cancelled),
                "1" | "es" | "email_send" => {
                    let rq = DeviceVerificationRequest {
                        username: self.user.to_lowercase(),
                        encrypted_device_token: self.device_token()?,
                        verification_channel: "email".into(),
                        client_version: CLIENT_VERSION.into(),
                        ..Default::default()
                    };
                    unauthenticated_ok(&mut self.rest, "authentication/request_device_verification", &rq)
                        .map(|_| eprintln!("Email sent to {}. Click the approval link, then press Enter.", self.user))
                }
                "2" | "kp" | "keeper_push" => self
                    .send_push(&resp.encrypted_login_token, TwoFactorPushType::TwoFaPushKeeper, Vec::new())
                    .map(|()| eprintln!("Push notification sent. Approve on your device, then press Enter.")),
                "3" | "2fs" | "2fa_send" => self
                    .send_push(&resp.encrypted_login_token, TwoFactorPushType::TwoFaPushNone, Vec::new())
                    .map(|()| eprintln!("2FA code sent. Enter it with 'c <code>'.")),
                s if s == "c" || s.starts_with("c ") => {
                    let code = match s.strip_prefix("c ") {
                        Some(code) => code.trim().to_owned(),
                        None => prompt("Enter verification code: ")?,
                    };
                    if code.is_empty() {
                        continue;
                    }
                    let email = ValidateDeviceVerificationCodeRequest {
                        username: self.user.to_lowercase(),
                        client_version: CLIENT_VERSION.into(),
                        verification_code: code.clone(),
                        ..Default::default()
                    };
                    let verified = unauthenticated_ok(&mut self.rest, "authentication/validate_device_verification_code", &email)
                        .map(drop)
                        .or_else(|_| {
                            self.validate_2fa(&resp.encrypted_login_token, &code, TwoFactorValueType::TwoFaCodeNone, Vec::new(), TwoFactorExpiration::TwoFaExpImmediately)
                                .map(drop)
                        });
                    match verified {
                        Ok(()) => return Ok(true),
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
            if let Err(e) = result {
                eprintln!("{e}");
            }
        }
    }

    fn send_push(&mut self, login_token: &[u8], push_type: TwoFactorPushType, channel_uid: Vec<u8>) -> Result<()> {
        let rq = TwoFactorSendPushRequest {
            encrypted_login_token: login_token.to_vec(),
            push_type: push_type as i32,
            channel_uid,
            ..Default::default()
        };
        unauthenticated_ok(&mut self.rest, "authentication/2fa_send_push", &rq).map(drop)
    }

    fn validate_2fa(
        &mut self,
        login_token: &[u8],
        code: &str,
        value_type: TwoFactorValueType,
        channel_uid: Vec<u8>,
        expire_in: TwoFactorExpiration,
    ) -> Result<Vec<u8>> {
        let rq = TwoFactorValidateRequest {
            encrypted_login_token: login_token.to_vec(),
            value: code.to_owned(),
            value_type: value_type as i32,
            channel_uid,
            expire_in: expire_in as i32,
            ..Default::default()
        };
        let rs = TwoFactorValidateResponse::decode(unauthenticated_ok(&mut self.rest, "authentication/2fa_validate", &rq)?.as_slice())?;
        Ok(rs.encrypted_login_token)
    }

    fn two_factor(&mut self, resp: &LoginResponse) -> Result<Vec<u8>> {
        let mut channels: Vec<TwoFactorChannelInfo> = resp
            .channels
            .iter()
            .filter(|c| channel_info(c.channel_type).is_some())
            .cloned()
            .collect();
        if channels.is_empty() {
            if !resp.channels.is_empty() {
                eprintln!("Your 2FA methods (e.g. security keys) are not supported here; falling back to backup codes.");
            }
            channels.push(TwoFactorChannelInfo {
                channel_type: Ct::TwoFaCtBackup as i32,
                ..Default::default()
            });
        }

        eprintln!("\nTwo-Factor Authentication Required\n");
        for (i, c) in channels.iter().enumerate() {
            let (desc, _) = channel_info(c.channel_type).unwrap_or(("Unknown", TwoFactorValueType::TwoFaCodeNone));
            eprintln!("  {}. {desc} {} {}", i + 1, c.channel_name, c.phone_number);
        }
        eprintln!("  q. Cancel login\n");
        let channel = loop {
            let selection = prompt("Selection: ")?;
            if selection == "q" {
                return Err(Error::Cancelled);
            }
            if let Some(c) = selection.parse::<usize>().ok().and_then(|i| i.checked_sub(1)).and_then(|i| channels.get(i)) {
                break c.clone();
            }
            eprintln!("Invalid entry.");
        };
        let (_, value_type) = channel_info(channel.channel_type).expect("filtered above");

        if channel.channel_type == Ct::TwoFaCtSms as i32 {
            match self.send_push(&resp.encrypted_login_token, TwoFactorPushType::TwoFaPushSms, channel.channel_uid.clone()) {
                Ok(()) => eprintln!("SMS sent successfully."),
                Err(_) => eprintln!("Was unable to send SMS."),
            }
        }

        // Expiration enum values are ordered, so "allowed" is everything up to the channel max.
        let durations = [
            ("login", TwoFactorExpiration::TwoFaExpImmediately),
            ("12_hours", TwoFactorExpiration::TwoFaExp12Hours),
            ("24_hours", TwoFactorExpiration::TwoFaExp24Hours),
            ("30_days", TwoFactorExpiration::TwoFaExp30Days),
            ("forever", TwoFactorExpiration::TwoFaExpNever),
        ];
        let allowed: Vec<_> = durations
            .iter()
            .filter(|(_, d)| *d as i32 <= channel.max_expiration.max(0))
            .collect();
        let mut duration = TwoFactorExpiration::TwoFaExpImmediately;
        let names: Vec<&str> = allowed.iter().map(|(n, _)| *n).collect();
        eprintln!("\n2FA Code Duration: {}.\nTo change duration: 2fa_duration={}", duration_name(duration), names.join("|"));

        loop {
            let answer = prompt("\nEnter 2FA Code: ")?;
            if let Some(rest) = answer.strip_prefix("2fa_duration=") {
                match allowed.iter().find(|(n, _)| *n == rest.trim().to_lowercase()) {
                    Some((_, d)) => {
                        duration = *d;
                        eprintln!("2FA Code Duration: {}", duration_name(duration));
                    }
                    None => eprintln!("Invalid 2FA Duration: {rest}"),
                }
                continue;
            }
            if answer.is_empty() {
                continue;
            }
            match self.validate_2fa(&resp.encrypted_login_token, &answer, value_type, channel.channel_uid.clone(), duration) {
                Ok(token) => {
                    eprintln!("2FA code verified.");
                    return Ok(token);
                }
                Err(_) => eprintln!("Invalid 2FA code. Please try again."),
            }
        }
    }

    fn finish(self, resp: LoginResponse) -> Result<Session> {
        let data_key = match EncryptedDataKeyType::try_from(resp.encrypted_data_key_type) {
            Ok(EncryptedDataKeyType::ByDevicePublicKey) => crypto::decrypt_ec(&resp.encrypted_data_key, &self.device_key()?)?,
            Ok(EncryptedDataKeyType::ByPassword) => {
                crypto::decrypt_encryption_params(&resp.encrypted_data_key, self.password.as_deref().unwrap_or_default())?
            }
            Ok(EncryptedDataKeyType::ByAlternate) => {
                let key = crypto::derive_keyhash_v2(
                    "data_key",
                    self.password.as_deref().unwrap_or_default(),
                    &self.salt,
                    self.iterations,
                );
                crypto::decrypt_aes_v2(&resp.encrypted_data_key, &key)?
            }
            other => return Err(Error::Generic(format!("Data key type {other:?} is not supported"))),
        };
        self.config.set("clone_code", Some(b64_encode(&resp.clone_code)));

        match SessionTokenType::try_from(resp.session_token_type).unwrap_or(SessionTokenType::Restrict) {
            SessionTokenType::NoRestriction => {}
            SessionTokenType::Purchase | SessionTokenType::Restrict => {
                return Err(Error::Generic(
                    "Your Keeper account has expired. Renew it in the Keeper app or at https://keepersecurity.com/vault".into(),
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
            rest: self.rest,
            user: resp.primary_username,
            account_uid: resp.account_uid,
            session_token: resp.encrypted_session_token,
            data_key,
            rsa_key: None,
            ecc_key: None,
            summary: AccountSummaryElements::default(),
        };
        let summary: AccountSummaryElements = session.call_typed("login/account_summary", &AccountSummaryRequest {
            summary_version: 3,
            ..Default::default()
        })?;
        if let Some(keys) = &summary.keys_info {
            if !keys.encrypted_private_key.is_empty() {
                let der = crypto::decrypt_aes_v1(&keys.encrypted_private_key, &session.data_key)?;
                session.rsa_key = Some(crypto::load_rsa_private_key(&der)?);
            }
            if !keys.encrypted_ecc_private_key.is_empty() {
                let raw = crypto::decrypt_aes_v2(&keys.encrypted_ecc_private_key, &session.data_key)?;
                session.ecc_key = Some(crypto::load_ec_private_key(&raw)?);
            }
        }
        session.summary = summary;
        Ok(session)
    }
}

fn channel_info(channel_type: i32) -> Option<(&'static str, TwoFactorValueType)> {
    Some(match Ct::try_from(channel_type).ok()? {
        Ct::TwoFaCtTotp => ("TOTP (Google and Microsoft Authenticator)", TwoFactorValueType::TwoFaCodeTotp),
        Ct::TwoFaCtSms => ("Send SMS Code", TwoFactorValueType::TwoFaCodeSms),
        Ct::TwoFaCtDuo => ("DUO", TwoFactorValueType::TwoFaCodeDuo),
        Ct::TwoFaCtRsa => ("RSA SecurID", TwoFactorValueType::TwoFaCodeRsa),
        Ct::TwoFaCtDna => ("Keeper DNA (Watch)", TwoFactorValueType::TwoFaCodeDna),
        Ct::TwoFaCtBackup => ("Backup Codes", TwoFactorValueType::TwoFaCodeNone),
        _ => return None,
    })
}

fn duration_name(d: TwoFactorExpiration) -> &'static str {
    match d {
        TwoFactorExpiration::TwoFaExpImmediately | TwoFactorExpiration::TwoFaExp5Minutes => "Require Every Login",
        TwoFactorExpiration::TwoFaExp12Hours => "Ask Every 12 hours",
        TwoFactorExpiration::TwoFaExp24Hours => "Ask Every 24 hours",
        TwoFactorExpiration::TwoFaExp30Days => "Ask Every 30 days",
        TwoFactorExpiration::TwoFaExpNever => "Save on this Device Forever",
    }
}
