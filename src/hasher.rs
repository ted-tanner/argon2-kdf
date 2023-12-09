use crate::error::Argon2Error;
use crate::lexer::TokenizedHash;

use base64::engine::general_purpose::STANDARD_NO_PAD as b64_stdnopad;
use base64::Engine;
use rand::{rngs::OsRng, Fill};
use std::default::Default;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::str::FromStr;

use crate::bindings::{
    argon2_error_message, argon2d_ctx, argon2i_ctx, argon2id_ctx, Argon2_Context,
    Argon2_ErrorCodes_ARGON2_OK, Argon2_version_ARGON2_VERSION_13,
};

/// The Argon2 spec consist of 3 different algorithms: one that aims to be resistant to GPU
/// cracking attacks (argon2d), one that aims to be resistant to side-channel attacks
/// (argon2i), and a hybrid algorithm that aims to be resistant to both types of attacks.
/// See <https://en.wikipedia.org/wiki/Argon2> for more information.
///
/// Argon2id is a good default. The other algorithms should only be used in rare cases,
/// preferably only when a cryptography expert can validate that using one of the other two
/// algorithms is safe.
#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    /// GPU-cracking attack resistant/memory-hard
    Argon2d,

    /// Side-channel attack resistant
    Argon2i,

    /// GPU-cracking attack resistant/memory-hard and side-channel attack resistant
    Argon2id,
}

/// A secret that mixes with a password (and a salt) to create a hash. This is sometimes
/// referred to as a "[pepper](https://en.wikipedia.org/wiki/Pepper_(cryptography))."
///
/// A 32-byte key is recommended. Do not use an alphanumeric password or passphrase; the
/// entrophy of a 32-character password is much lower than the entrophy of a 32-byte key. This
/// key should be generated with a cryptographically-secure random number generator and stored
/// securely.
#[derive(Clone, Copy, Debug)]
pub struct Secret<'a>(&'a [u8]);

impl<'a> Secret<'a> {
    /// Wraps a reference to a slice containing a secret key
    pub fn using<T: AsRef<[u8]>>(secret: &'a T) -> Self {
        Self(secret.as_ref())
    }
}

impl<'a> From<&'a [u8]> for Secret<'a> {
    fn from(secret: &'a [u8]) -> Self {
        Self(secret)
    }
}

impl<'a> From<&'a Vec<u8>> for Secret<'a> {
    fn from(secret: &'a Vec<u8>) -> Self {
        Self(secret)
    }
}

impl<'a, const SIZE: usize> From<&'a [u8; SIZE]> for Secret<'a> {
    fn from(secret: &'a [u8; SIZE]) -> Self {
        Self(secret)
    }
}

impl<'a> From<&'a dyn AsRef<[u8]>> for Secret<'a> {
    fn from(secret: &'a dyn AsRef<[u8]>) -> Self {
        Self(secret.as_ref())
    }
}

impl<'a> From<&'a str> for Secret<'a> {
    fn from(secret: &'a str) -> Self {
        Self(secret.as_bytes())
    }
}

impl<'a> From<&'a String> for Secret<'a> {
    fn from(secret: &'a String) -> Self {
        Self(secret.as_bytes())
    }
}

/// A builder for a hash. Parameters for hashing, such as
#[derive(Clone, Debug)]
pub struct Hasher<'a> {
    alg: Algorithm,
    custom_salt: Option<&'a [u8]>,
    salt_len: u32,
    hash_len: u32,
    iterations: u32,
    mem_cost_kib: u32,
    threads: u32,
    secret: Option<Secret<'a>>,
}

impl Default for Hasher<'_> {
    /// Create a new `Hasher` with default values.
    ///
    /// This provides some reasonable defaults, but it is recommended that you tinker with
    /// these parameters to find the best settings for your application. The more resources the
    /// hashing requires, the stronger the hash. Increase the memory cost (and perhaps the
    /// parallelization factor) as high as your application can afford, then likewise raise the
    /// iteration count.
    ///
    /// Unless you are _absolutely positive_ you want to use a different algorithm, use
    /// the default argon2id algorithm for password hashing and key derivation.
    ///
    /// The defaults are as follows:
    ///
    /// * Algorithm: Argon2id
    /// * Salt Length: 16 bytes
    /// * Hash Length: 32 bytes
    /// * Iterations: 18
    /// * Memory Cost: 62500 kibibytes (equal to 64 megabytes)
    /// * Parallelization Factor: 1 thread
    ///
    /// `Hasher` allows for a secret, sometimes called a
    /// "[pepper](https://en.wikipedia.org/wiki/Pepper_(cryptography))," to be mixed with the
    /// password before hashing. `Hasher` can be used securely without a secret, though
    /// high-security applications might consider using one.
    fn default() -> Self {
        Self {
            alg: Algorithm::Argon2id,
            custom_salt: None,
            salt_len: 16,
            hash_len: 32,
            iterations: 18,
            mem_cost_kib: 62500,
            threads: 1,
            secret: None,
        }
    }
}

impl<'a> Hasher<'a> {
    /// Create a new `Hasher` with default values.
    ///
    /// This provides some reasonable defaults, but it is recommended that you tinker with
    /// these parameters to find the best settings for your application. The more resources the
    /// hashing requires, the stronger the hash. Increase the memory cost (and perhaps the
    /// parallelization factor) as high as your application can afford, then likewise raise the
    /// iteration count.
    ///
    /// Unless you are _absolutely positive_ you want to use a different algorithm, use
    /// the default argon2id algorithm for password hashing and key derivation.
    ///
    /// The defaults are as follows:
    ///
    /// * Algorithm: Argon2id
    /// * Salt Length: 16 bytes
    /// * Hash Length: 32 bytes
    /// * Iterations: 18
    /// * Memory Cost: 62500 kibibytes (equal to 64 megabytes)
    /// * Parallelization Factor: 1 thread
    ///
    /// `Hasher` allows for a secret, sometimes called a
    /// "[pepper](https://en.wikipedia.org/wiki/Pepper_(cryptography))," to be mixed with the
    /// password before hashing. `Hasher` can be used securely without a secret, though
    /// high-security applications might consider using one.
    pub fn new() -> Self {
        Self::default()
    }

    /// Specifies the hashing algorithm to use.
    ///
    /// The Argon2 spec consist of 3 different algorithms: one that aims to be resistant to GPU
    /// cracking attacks (argon2d), one that aims to be resistant to side-channel attacks
    /// (argon2i), and a hybrid algorithm that aims to be resistant to both types of attacks.
    /// See <https://en.wikipedia.org/wiki/Argon2> for more information.
    ///
    /// Argon2id is a good default. The other algorithms should only be used in rare cases,
    /// preferably only when a cryptography expert can validate that using one of the other two
    /// algorithms is safe.
    pub fn algorithm(mut self, alg: Algorithm) -> Self {
        self.alg = alg;
        self
    }

    /// When left unspecified, a salt is generated using a cryptographically-secure random
    /// number generator. In most cases, this function should not be used. Only use this
    /// function if you are trying to generate a hash deterministically with a known salt and
    /// a randomly generated salt will not suffice.
    pub fn custom_salt<SLT>(mut self, salt: &'a SLT) -> Self
    where
        SLT: AsRef<[u8]> + ?Sized,
    {
        self.custom_salt = Some(salt.as_ref());
        self
    }

    /// The length of the salt for the hash, in bytes. Using salt that is too short can lower
    /// the strength of the generated hash. 16 bytes is a reasonable default salt length.
    ///
    /// If a salt is specified manually using [`custom_salt()`], the length of the provided
    /// salt will override the length specified here.
    pub fn salt_length(mut self, salt_len: u32) -> Self {
        self.salt_len = salt_len;
        self
    }

    /// The length of the resulting hash, in bytes.
    ///
    /// Short hashes can be insecure. The shorter the hash, the greater the chance of
    /// collisions. A 32-byte hash should be plenty for any application.
    ///
    /// Note that the length of the hash _string_ will be different; the hash string specifies
    /// parameters and the salt used to generate the hash. The hash is base64-encoded in the
    /// hash string, so even the hash itself is longer in the hash string than the specified
    /// number of bytes.
    ///
    /// A hash is just an array of bytes, whereas a hash string looks something like this:
    ///
    /// _$argon2id$v=19$m=62500,t=18,p=2$AQIDBAUGBwg$ypJ3pKxN4aWGkwMv0TOb08OIzwrfK1SZWy64vyTLKo8_
    pub fn hash_length(mut self, hash_len: u32) -> Self {
        self.hash_len = hash_len;
        self
    }

    /// The number of times the hashing algorithm is repeated in order to slow down the hashing
    /// and thwart those pesky hackers.
    pub fn iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// The amount of memory required to compute a hash. This is where a lot of the magic of
    /// Argon2 happens. By setting a hard memory requirement for generating a hash,
    /// brute-forcing a password becomes infeasable even for well-funded adversaries with
    /// access to a lot of processing power.
    ///
    /// Set this parameter as high as you can afford to. Be cautious setting this lower than
    /// 62500 KiB (64 MB). If reasonable, increase this to 125000 KiB (128 MB) or 250000 KiB
    /// (256 MB) (or even higher were security is critical).
    pub fn memory_cost_kib(mut self, cost: u32) -> Self {
        self.mem_cost_kib = cost;
        self
    }

    /// The number of CPU threads required to generate a hash. If this is set higher than the
    /// total number of logical CPU cores on a given machine, hashing may fail or take an
    /// astronomically long time to generate on said machine.
    ///
    /// While increasing the thread count does strengthen the hash, it is impractical to raise
    /// this parameter for some applications. Aim to increase the memory cost before increasing
    /// the thread count. With a high memory cost, just 1 thread can still provide excellent
    /// security.
    pub fn threads(mut self, threads: u32) -> Self {
        self.threads = threads;
        self
    }

    /// A secret that mixes with a password (and a salt) to create a hash. This is sometimes
    /// referred to as a "[pepper](https://en.wikipedia.org/wiki/Pepper_(cryptography))."
    ///
    /// This secret is not necessary to generate strong hashes, though high-security
    /// applications might consider using a secret. Many argon2 libraries don't expose this
    /// parameter (because it isn't necessary), so using a secret can limit interoperability
    /// with other languages/libraries.
    ///
    /// A 32-byte key is recommended. Do not use an alphanumeric password or passphrase; the
    /// entrophy of a 32-character password is much lower than the entrophy of a 32-byte key.
    /// This key should be generated with a cryptographically-secure random number generator
    /// and stored securely.
    pub fn secret(mut self, secret: Secret<'a>) -> Self {
        self.secret = Some(secret);
        self
    }

    /// Consumes the `Hasher` and returns a hash.
    ///
    /// This is an expensive operation. For some appliations, it might make sense to move this
    /// operation to a separate thread using `std::thread` or something like
    /// [the Rayon crate](https://docs.rs/rayon/latest/rayon/) to avoid blocking main threads.
    pub fn hash<P>(self, password: &P) -> Result<Hash, Argon2Error>
    where
        P: AsRef<[u8]> + ?Sized,
    {
        let hash_len_usize = match usize::try_from(self.hash_len) {
            Ok(l) => l,
            Err(_) => return Err(Argon2Error::InvalidParameter("Hash length is too big")),
        };

        let mut hash_buffer = MaybeUninit::new(Vec::with_capacity(hash_len_usize));
        let mut hash_buffer = unsafe {
            (*hash_buffer.as_mut_ptr()).set_len(hash_len_usize);
            (*hash_buffer.as_mut_ptr())
                .try_fill(&mut OsRng)
                .expect("Failed to fill buffer with random bytes");

            hash_buffer.assume_init()
        };

        let (salt_len_u32, salt_len_usize) = if let Some(s) = self.custom_salt {
            let salt_len_u32 = match u32::try_from(s.len()) {
                Ok(l) => l,
                Err(_) => return Err(Argon2Error::InvalidParameter("Salt length is too big")),
            };

            (salt_len_u32, s.len())
        } else {
            let salt_len_usize = match usize::try_from(self.salt_len) {
                Ok(l) => l,
                Err(_) => return Err(Argon2Error::InvalidParameter("Salt length is too big")),
            };

            (self.salt_len, salt_len_usize)
        };

        let salt;
        let salt = if let Some(s) = self.custom_salt {
            s
        } else {
            let mut rand_salt = MaybeUninit::new(Vec::with_capacity(salt_len_usize));
            salt = unsafe {
                (*rand_salt.as_mut_ptr()).set_len(salt_len_usize);
                (*rand_salt.as_mut_ptr())
                    .try_fill(&mut OsRng)
                    .expect("Failed to fill buffer with random bytes");

                rand_salt.assume_init()
            };

            &salt
        };

        let (secret_ptr, secret_len) = {
            if let Some(s) = self.secret {
                let length = match s.0.len().try_into() {
                    Ok(l) => l,
                    Err(_) => return Err(Argon2Error::InvalidParameter("Secret is too long")),
                };

                (s.0.as_ref().as_ptr() as *mut _, length)
            } else {
                (std::ptr::null_mut(), 0)
            }
        };

        // Some buffers here are cast to *mut to pass to C. C will not modify these buffers
        // so this is safe
        let mut ctx = Argon2_Context {
            out: hash_buffer.as_mut_ptr(),
            // hash_len was originally converted from a u32 to a usize, so this is safe
            outlen: self.hash_len,
            pwd: password as *const _ as *mut _,
            pwdlen: match password.as_ref().len().try_into() {
                Ok(l) => l,
                Err(_) => return Err(Argon2Error::InvalidParameter("Password is too long")),
            },
            salt: salt.as_ref().as_ptr() as *mut _,
            // Careful not to use self.salt_len here; it may be overridden if a custom salt
            // has been specified
            saltlen: salt_len_u32,
            secret: secret_ptr,
            secretlen: secret_len,
            ad: std::ptr::null_mut(),
            adlen: 0,
            t_cost: self.iterations,
            m_cost: self.mem_cost_kib,
            lanes: self.threads,
            threads: self.threads,
            version: Argon2_version_ARGON2_VERSION_13,
            allocate_cbk: None,
            free_cbk: None,
            flags: 0,
        };

        let result = unsafe {
            match self.alg {
                Algorithm::Argon2d => argon2d_ctx(&mut ctx as *mut _),
                Algorithm::Argon2i => argon2i_ctx(&mut ctx as *mut _),
                Algorithm::Argon2id => argon2id_ctx(&mut ctx as *mut _),
            }
        };

        if result != Argon2_ErrorCodes_ARGON2_OK {
            let err_msg = String::from_utf8_lossy(unsafe {
                CStr::from_ptr(argon2_error_message(result)).to_bytes()
            });

            return Err(Argon2Error::CLibError(err_msg.into_owned()));
        }

        Ok(Hash {
            alg: self.alg,
            mem_cost_kib: self.mem_cost_kib,
            iterations: self.iterations,
            threads: self.threads,
            salt: Vec::from(salt),
            hash: hash_buffer,
        })
    }
}

/// A container for an Argon2 hash, the corresponding salt, and the parameters used for
/// hashing
#[derive(Clone, Debug)]
pub struct Hash {
    alg: Algorithm,
    mem_cost_kib: u32,
    iterations: u32,
    threads: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

impl ToString for Hash {
    /// Generates a hash string. Aside from the hash, the hash string also includes the salt
    /// and paramters used to generate the hash, making it easy to store in a database or a
    /// cache. This string is formatted to a standard shared by most implementations of argon2,
    /// so other argon2 libraries should be able to use this hash string.
    ///
    /// A hash string looks something like this:
    ///
    /// _$argon2id$v=19$m=62500,t=18,p=2$AQIDBAUGBwg$ypJ3pKxN4aWGkwMv0TOb08OIzwrfK1SZWy64vyTLKo8_
    fn to_string(&self) -> String {
        let b64_salt = b64_stdnopad.encode(&self.salt);
        let b64_hash = b64_stdnopad.encode(&self.hash);

        let alg = match self.alg {
            Algorithm::Argon2d => "d",
            Algorithm::Argon2i => "i",
            Algorithm::Argon2id => "id",
        };

        format!(
            "$argon2{}$v={}$m={},t={},p={}${}${}",
            alg,
            Argon2_version_ARGON2_VERSION_13,
            self.mem_cost_kib,
            self.iterations,
            self.threads,
            b64_salt,
            b64_hash,
        )
    }
}

impl FromStr for Hash {
    type Err = Argon2Error;

    /// Deserializes a hash string into parts (e.g. the hash, the salt, parameters) that can
    /// be used for purposes such as verification or encryption.
    ///
    /// A hash string looks something like this:
    ///
    /// _$argon2id$v=19$m=62500,t=18,p=2$AQIDBAUGBwg$ypJ3pKxN4aWGkwMv0TOb08OIzwrfK1SZWy64vyTLKo8_
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tokenized_hash = TokenizedHash::from_str(s)?;

        if tokenized_hash.v != Argon2_version_ARGON2_VERSION_13 {
            return Err(Argon2Error::InvalidHash("Hash version is unsupported"));
        }

        let decoded_salt = match b64_stdnopad.decode(tokenized_hash.b64_salt) {
            Ok(s) => s,
            Err(_) => {
                return Err(Argon2Error::InvalidHash(
                    "Invalid character in base64-encoded salt",
                ))
            }
        };

        let decoded_hash = match b64_stdnopad.decode(tokenized_hash.b64_hash) {
            Ok(h) => h,
            Err(_) => {
                return Err(Argon2Error::InvalidHash(
                    "Invalid character in base64-encoded hash",
                ))
            }
        };

        Ok(Self {
            alg: tokenized_hash.alg,
            mem_cost_kib: tokenized_hash.mem_cost_kib,
            iterations: tokenized_hash.iterations,
            threads: tokenized_hash.threads,
            salt: decoded_salt,
            hash: decoded_hash,
        })
    }
}

impl Hash {
    /// Returns a reference to a byte slice of the computed hash/key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.hash
    }

    /// Returns a reference to a byte slice of the salt used to generate the hash.
    pub fn salt_bytes(&self) -> &[u8] {
        &self.salt
    }

    /// Checks if the hash matches the provided password.
    ///
    /// Because verification requires re-hashing the password, this is an expensive operation.
    /// For some appliations, it might make sense to move this operation to a separate thread
    /// using `std::thread` or something like
    /// [the Rayon crate](https://docs.rs/rayon/latest/rayon/) to avoid blocking main threads.
    pub fn verify<P>(&self, password: &P) -> bool
    where
        P: AsRef<[u8]> + ?Sized,
    {
        self.verify_with_or_without_secret::<P>(password, None)
    }

    /// Checks if the hash matches the provided password using the provided secret.
    ///
    /// Because verification requires re-hashing the password, this is an expensive operation.
    /// For some appliations, it might make sense to move this operation to a separate thread
    /// using `std::thread` or something like
    /// [the Rayon crate](https://docs.rs/rayon/latest/rayon/) to avoid blocking main threads.
    pub fn verify_with_secret<P>(&self, password: &P, secret: Secret) -> bool
    where
        P: AsRef<[u8]> + ?Sized,
    {
        self.verify_with_or_without_secret::<P>(password, Some(secret))
    }

    #[inline]
    fn verify_with_or_without_secret<P>(&self, password: &P, secret: Option<Secret>) -> bool
    where
        P: AsRef<[u8]> + ?Sized,
    {
        let hash_length: u32 = match self.hash.len().try_into() {
            Ok(l) => l,
            Err(_) => return false,
        };

        let mut hash_builder = Hasher::default()
            .algorithm(self.alg)
            .custom_salt(&self.salt)
            .hash_length(hash_length)
            .iterations(self.iterations)
            .memory_cost_kib(self.mem_cost_kib)
            .threads(self.threads);

        if let Some(s) = secret {
            hash_builder = hash_builder.secret(s);
        }

        let hashed_password = match hash_builder.hash(password) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let mut hashes_dont_match = 0u8;

        if self.hash.len() != hashed_password.hash.len() || self.hash.is_empty() {
            return false;
        }

        // Do bitwise comparison to prevent timing attacks (entire length of string must be
        // compared)
        for (i, hash_byte) in hashed_password.hash.iter().enumerate() {
            unsafe {
                hashes_dont_match |= hash_byte ^ self.hash.get_unchecked(i);
            }
        }

        hashes_dont_match == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_hash_into_hash_string() {
        let hash = Hash {
            alg: Algorithm::Argon2id,
            mem_cost_kib: 128,
            iterations: 3,
            threads: 2,
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
            hash: b64_stdnopad
                .decode("ypJ3pKxN4aWGkwMv0TOb08OIzwrfK1SZWy64vyTLKo8")
                .unwrap()
                .to_vec(),
        };

        assert_eq!(
            hash.to_string(),
            String::from(
                "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$ypJ3pKxN4aWGkwMv0TOb08OIzwrfK1SZWy64vyTLKo8"
            )
        );
    }

    #[test]
    fn test_hash_from_str() {
        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        )
        .unwrap();

        assert_eq!(hash.mem_cost_kib, 128);
        assert_eq!(hash.iterations, 3);
        assert_eq!(hash.threads, 2);
        assert_eq!(hash.salt, b64_stdnopad.decode("AQIDBAUGBwg").unwrap());
        assert_eq!(
            hash.hash,
            b64_stdnopad
                .decode("7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",)
                .unwrap()
        );

        let hash = Hash::from_str(
            "$argon2id$v=19$t=3,m=128,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        )
        .unwrap();

        assert_eq!(hash.mem_cost_kib, 128);
        assert_eq!(hash.iterations, 3);
        assert_eq!(hash.threads, 2);
        assert_eq!(hash.salt, b64_stdnopad.decode("AQIDBAUGBwg").unwrap());
        assert_eq!(
            hash.hash,
            b64_stdnopad
                .decode("7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",)
                .unwrap()
        );

        let hash = Hash::from_str(
            "$argon2id$v=19$p=2,m=128,t=3$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        )
        .unwrap();

        assert_eq!(hash.mem_cost_kib, 128);
        assert_eq!(hash.iterations, 3);
        assert_eq!(hash.threads, 2);
        assert_eq!(hash.salt, b64_stdnopad.decode("AQIDBAUGBwg").unwrap());
        assert_eq!(
            hash.hash,
            b64_stdnopad
                .decode("7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",)
                .unwrap()
        );

        let hash = Hash::from_str(
            "$argon2id$v=19$t=3,p=2,m=128$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        )
        .unwrap();

        assert_eq!(hash.mem_cost_kib, 128);
        assert_eq!(hash.iterations, 3);
        assert_eq!(hash.threads, 2);
        assert_eq!(hash.salt, b64_stdnopad.decode("AQIDBAUGBwg").unwrap());
        assert_eq!(
            hash.hash,
            b64_stdnopad
                .decode("7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",)
                .unwrap()
        );
    }

    #[test]
    fn test_invalid_hash_from_str() {
        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2,$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$t=3,m=128,p=2,m=128$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc"
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2i$v=19$p=2m=128,t=3$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$p=2m=128,t=3$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$t=3,p=2,m=128$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2$v=19$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=18$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,t3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc$",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str("$argon2id$v=19$m=128,t=3,p=2$AQIDBAUGBwg$$");

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$m=128,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$t=2,p=2$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());

        let hash = Hash::from_str(
            "$argon2id$v=19$t=2,m=128$AQIDBAUGBwg$7OU7S/azjYpnXXySR52cFWeisxk1VVjNeXqtQ8ZM/Oc",
        );

        assert!(hash.is_err());
    }

    #[test]
    fn test_hash_auth_string_argon2d() {
        let auth_string = b"@Pa$$20rd-Test";

        let key = [1u8; 32];
        let hash_builder = Hasher::default()
            .algorithm(Algorithm::Argon2d)
            .salt_length(16)
            .hash_length(32)
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .secret((&key).into());

        let hash = hash_builder.hash(auth_string).unwrap().to_string();

        assert!(Hash::from_str(&hash)
            .unwrap()
            .verify_with_secret(auth_string, (&key).into()));
    }

    #[test]
    fn test_hash_auth_string_no_secret() {
        let auth_string = b"@Pa$$20rd-Test";

        let hash = Hasher::default()
            .salt_length(16)
            .hash_length(32)
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .hash(auth_string)
            .unwrap()
            .to_string();

        assert!(Hash::from_str(&hash).unwrap().verify(auth_string));
    }

    #[test]
    fn test_hash_auth_string_argon2i() {
        let auth_string = b"@Pa$$20rd-Test";

        let key = [1u8; 32];
        let hash_builder = Hasher::default()
            .algorithm(Algorithm::Argon2i)
            .salt_length(16)
            .hash_length(32)
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .secret((&key).into());

        let hash = hash_builder.hash(auth_string).unwrap().to_string();

        assert!(Hash::from_str(&hash)
            .unwrap()
            .verify_with_secret(auth_string, (&key).into()));
    }

    #[test]
    fn test_hash_auth_string_argon2id() {
        let auth_string = b"@Pa$$20rd-Test";

        let key = [1u8; 32];
        let hash_builder = Hasher::new()
            .algorithm(Algorithm::Argon2id)
            .salt_length(16)
            .hash_length(32)
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .secret((&key).into());

        let hash = hash_builder.hash(auth_string).unwrap().to_string();

        assert!(Hash::from_str(&hash)
            .unwrap()
            .verify_with_secret(auth_string, (&key).into()));
    }

    #[test]
    fn test_custom_salt() {
        let auth_string = b"@Pa$$20rd-Test";
        let salt = b"seasalts";

        let hash = Hasher::default()
            .custom_salt(salt)
            .hash(auth_string)
            .unwrap();

        assert_eq!(hash.salt, salt);

        let hash_string = hash.to_string();

        assert!(Hash::from_str(&hash_string).unwrap().verify(auth_string));
    }

    #[test]
    fn test_verify_hash() {
        let auth_string = b"@Pa$$20rd-Test";

        let key = [0u8; 32];
        let hash_builder = Hasher::default()
            .salt_length(16)
            .hash_length(32)
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .secret((&key).into());

        let hash = hash_builder.hash(auth_string).unwrap().to_string();

        assert!(Hash::from_str(&hash)
            .unwrap()
            .verify_with_secret(auth_string, (&key).into()));
    }

    #[test]
    fn test_verify_incorrect_auth_string() {
        let auth_string = b"@Pa$$20rd-Test";

        let key = [0u8; 32];
        let hash_builder = Hasher::default()
            .salt_length(16)
            .hash_length(32)
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .secret((&key).into());

        let hash = hash_builder.hash(auth_string).unwrap().to_string();

        assert!(Hash::from_str(&hash)
            .unwrap()
            .verify_with_secret(auth_string, (&key).into()));
    }

    #[test]
    fn test_verify_incorrect_key() {
        let auth_string = b"@Pa$$20rd-Test";

        let key = [0u8; 32];
        let hash_builder = Hasher::default()
            .salt_length(16)
            .hash_length(32)
            .iterations(2)
            .memory_cost_kib(128)
            .threads(1)
            .secret((&key).into());

        let hash = hash_builder.hash(auth_string).unwrap().to_string();

        assert!(Hash::from_str(&hash)
            .unwrap()
            .verify_with_secret(auth_string, (&key).into()));
    }
}
