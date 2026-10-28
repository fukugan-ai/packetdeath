//! The user directory: `users.json`, written atomically. `docs/design.md`
//! "段階13 WebApp" 認証と権限.
//!
//! Passwords are kept as Argon2id PHC strings and nothing else. An unknown name
//! costs the same hash work as a known one, so the answer to "wrong password"
//! does not say whether the account exists. The last active administrator can
//! be neither removed, disabled nor demoted.

use std::path::{Path, PathBuf};

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use serde::{Deserialize, Serialize};

/// Longest and shortest password accepted.
pub const PASSWORD_MIN: usize = 12;
pub const PASSWORD_MAX: usize = 256;
/// Longest user name.
pub const NAME_MAX: usize = 128;

/// What a user may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Reads only.
    Viewer,
    /// Reads and changes settings.
    Operator,
    /// Also manages users.
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    name: String,
    role: Role,
    hash: String,
    disabled: bool,
    created: u64,
}

/// A user as the screens see it: no hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct View {
    pub name: String,
    pub role: Role,
    pub disabled: bool,
    pub created: u64,
}

/// Why a change to the directory was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum UserError {
    BadName,
    WeakPassword,
    Exists,
    NotFound,
    LastAdmin,
    Store(String),
}

impl std::fmt::Display for UserError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserError::BadName => write!(out, "the name must be 1 to {NAME_MAX} of letters, digits, '.', '_', '-', '@' or '+'"),
            UserError::WeakPassword => write!(out, "the password must be {PASSWORD_MIN} to {PASSWORD_MAX} characters"),
            UserError::Exists => write!(out, "that name is taken"),
            UserError::NotFound => write!(out, "no such user"),
            UserError::LastAdmin => write!(out, "the last active administrator cannot be removed, disabled or demoted"),
            UserError::Store(why) => write!(out, "the user file: {why}"),
        }
    }
}

impl std::error::Error for UserError {}

/// The directory.
pub struct Users {
    path: PathBuf,
    list: Vec<Stored>,
    /// A hash no password matches, checked against when the name is unknown.
    decoy: String,
}

fn hash_of(password: &str) -> Result<String, UserError> {
    let made = Argon2::default().hash_password(password.as_bytes());
    made.map(|h| h.to_string()).map_err(|e| UserError::Store(e.to_string()))
}

fn name_ok(name: &str) -> bool {
    (1..=NAME_MAX).contains(&name.len())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | '+'))
}

fn password_ok(password: &str) -> bool {
    (PASSWORD_MIN..=PASSWORD_MAX).contains(&password.chars().count())
}

impl Users {
    /// Open the directory. A missing file is an empty directory; a file that
    /// cannot be read or parsed is an error, so the console never starts as if
    /// no one had an account.
    pub fn open(path: &Path) -> Result<Self, UserError> {
        let list = match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map_err(|e| UserError::Store(format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(UserError::Store(format!("{}: {e}", path.display()))),
        };
        let mut seed = [0_u8; 24];
        getrandom::fill(&mut seed).map_err(|e| UserError::Store(e.to_string()))?;
        let decoy = hash_of(&format!("decoy-{seed:?}"))?;
        Ok(Self { path: path.to_path_buf(), list, decoy })
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    fn save(&self) -> Result<(), UserError> {
        let text = serde_json::to_string_pretty(&self.list).map_err(|e| UserError::Store(e.to_string()))?;
        let mut tmp = self.path.clone();
        tmp.set_extension("tmp");
        std::fs::write(&tmp, text).map_err(|e| UserError::Store(e.to_string()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| UserError::Store(e.to_string()))
    }

    fn active_admins(&self) -> usize {
        self.list.iter().filter(|u| u.role == Role::Admin && !u.disabled).count()
    }

    /// Add a user.
    pub fn create(&mut self, name: &str, password: &str, role: Role, now: u64) -> Result<(), UserError> {
        if !name_ok(name) {
            return Err(UserError::BadName);
        }
        if !password_ok(password) {
            return Err(UserError::WeakPassword);
        }
        if self.list.iter().any(|u| u.name == name) {
            return Err(UserError::Exists);
        }
        let hash = hash_of(password)?;
        self.list.push(Stored { name: name.to_owned(), role, hash, disabled: false, created: now });
        self.save()
    }

    /// The role of `name` when `password` is right and the account is active.
    pub fn verify(&self, name: &str, password: &str) -> Option<Role> {
        let found = self.list.iter().find(|u| u.name == name);
        let hash = found.map_or(self.decoy.as_str(), |u| u.hash.as_str());
        let Ok(parsed) = PasswordHash::new(hash) else {
            return None;
        };
        let right = Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok();
        found.filter(|u| right && !u.disabled).map(|u| u.role)
    }

    pub fn role_of(&self, name: &str) -> Option<Role> {
        self.list.iter().find(|u| u.name == name && !u.disabled).map(|u| u.role)
    }

    pub fn list(&self) -> Vec<View> {
        let view = |u: &Stored| View { name: u.name.clone(), role: u.role, disabled: u.disabled, created: u.created };
        self.list.iter().map(view).collect()
    }

    fn index(&self, name: &str) -> Result<usize, UserError> {
        self.list.iter().position(|u| u.name == name).ok_or(UserError::NotFound)
    }

    /// Whether changing user `at` to `role` / `disabled` would leave no active administrator.
    fn leaves_none(&self, at: usize, role: Role, disabled: bool) -> bool {
        let was_active_admin = self.list[at].role == Role::Admin && !self.list[at].disabled;
        let stays = role == Role::Admin && !disabled;
        was_active_admin && !stays && self.active_admins() <= 1
    }

    pub fn set_role(&mut self, name: &str, role: Role) -> Result<(), UserError> {
        let at = self.index(name)?;
        if self.leaves_none(at, role, self.list[at].disabled) {
            return Err(UserError::LastAdmin);
        }
        self.list[at].role = role;
        self.save()
    }

    pub fn set_disabled(&mut self, name: &str, disabled: bool) -> Result<(), UserError> {
        let at = self.index(name)?;
        if self.leaves_none(at, self.list[at].role, disabled) {
            return Err(UserError::LastAdmin);
        }
        self.list[at].disabled = disabled;
        self.save()
    }

    pub fn set_password(&mut self, name: &str, password: &str) -> Result<(), UserError> {
        if !password_ok(password) {
            return Err(UserError::WeakPassword);
        }
        let at = self.index(name)?;
        self.list[at].hash = hash_of(password)?;
        self.save()
    }

    pub fn remove(&mut self, name: &str) -> Result<(), UserError> {
        let at = self.index(name)?;
        if self.leaves_none(at, Role::Viewer, true) {
            return Err(UserError::LastAdmin);
        }
        self.list.remove(at);
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse battery";

    fn scratch(name: &str) -> Result<PathBuf, std::io::Error> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("users-test").join(format!("{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir.join("users.json"))
    }

    #[test]
    fn a_created_user_verifies_and_the_file_holds_no_plain_password() -> Result<(), Box<dyn std::error::Error>> {
        let path = scratch("hash")?;
        let mut users = Users::open(&path)?;
        users.create("alice", PW, Role::Admin, 1)?;
        assert_eq!(users.verify("alice", PW), Some(Role::Admin));
        assert_eq!(users.verify("alice", "wrong password!!"), None);
        assert_eq!(users.verify("nobody", PW), None);
        let text = std::fs::read_to_string(&path)?;
        assert!(!text.contains(PW) && text.contains("$argon2id$"));
        Ok(())
    }

    #[test]
    fn the_directory_survives_a_reopen_and_a_broken_file_is_an_error() -> Result<(), Box<dyn std::error::Error>> {
        let path = scratch("reopen")?;
        Users::open(&path)?.create("alice", PW, Role::Admin, 1)?;
        assert_eq!(Users::open(&path)?.role_of("alice"), Some(Role::Admin));
        std::fs::write(&path, "not json")?;
        assert!(matches!(Users::open(&path), Err(UserError::Store(_))));
        Ok(())
    }

    #[test]
    fn names_and_passwords_are_checked_and_a_name_is_taken_once() -> Result<(), Box<dyn std::error::Error>> {
        let mut users = Users::open(&scratch("rules")?)?;
        assert_eq!(users.create("", PW, Role::Viewer, 0), Err(UserError::BadName));
        assert_eq!(users.create("a b", PW, Role::Viewer, 0), Err(UserError::BadName));
        assert_eq!(users.create(&"x".repeat(NAME_MAX + 1), PW, Role::Viewer, 0), Err(UserError::BadName));
        assert_eq!(users.create("bob", "short", Role::Viewer, 0), Err(UserError::WeakPassword));
        users.create("bob", PW, Role::Viewer, 0)?;
        users.create("carol.smith+pd@example.org", PW, Role::Viewer, 0)?;
        assert_eq!(users.create("bob", PW, Role::Viewer, 0), Err(UserError::Exists));
        Ok(())
    }

    #[test]
    fn the_last_active_administrator_cannot_leave() -> Result<(), Box<dyn std::error::Error>> {
        let mut users = Users::open(&scratch("last")?)?;
        users.create("alice", PW, Role::Admin, 0)?;
        users.create("bob", PW, Role::Operator, 0)?;
        assert_eq!(users.set_role("alice", Role::Viewer), Err(UserError::LastAdmin));
        assert_eq!(users.set_disabled("alice", true), Err(UserError::LastAdmin));
        assert_eq!(users.remove("alice"), Err(UserError::LastAdmin));
        users.set_role("bob", Role::Admin)?;
        users.remove("alice")?;
        assert_eq!(users.remove("bob"), Err(UserError::LastAdmin));
        Ok(())
    }

    #[test]
    fn a_disabled_user_cannot_sign_in_and_a_new_password_replaces_the_old() -> Result<(), Box<dyn std::error::Error>> {
        let mut users = Users::open(&scratch("disable")?)?;
        users.create("alice", PW, Role::Admin, 0)?;
        users.create("bob", PW, Role::Viewer, 0)?;
        users.set_disabled("bob", true)?;
        assert_eq!(users.verify("bob", PW), None);
        users.set_disabled("bob", false)?;
        users.set_password("bob", "another long password")?;
        assert_eq!(users.verify("bob", PW), None);
        assert_eq!(users.verify("bob", "another long password"), Some(Role::Viewer));
        assert_eq!(users.set_password("ghost", PW), Err(UserError::NotFound));
        Ok(())
    }
}
