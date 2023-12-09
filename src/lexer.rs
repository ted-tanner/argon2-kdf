use crate::error::Argon2Error;
use crate::hasher::Algorithm;

use std::str::FromStr;

pub struct TokenizedHash {
    pub v: u32,
    pub alg: Algorithm,
    pub mem_cost_kib: u32,
    pub iterations: u32,
    pub threads: u32,
    pub b64_salt: String,
    pub b64_hash: String,
}

impl FromStr for TokenizedHash {
    type Err = Argon2Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        enum HashStates {
            Start,
            HashTypeStart,
            HashTypeA,
            HashTypeAr,
            HashTypeArg,
            HashTypeArgo,
            HashTypeArgon,
            HashTypeArgon2,
            HashTypeArgon2d,
            HashTypeArgon2i,
            HashTypeArgon2id,
            HashTypeComplete,
            VKey,
            VEquals,
            VValue,
            VComplete,
            MKey,
            MEquals,
            MValue,
            MComplete,
            TKey,
            TEquals,
            TValue,
            TComplete,
            PKey,
            PEquals,
            PValue,
            PComplete,
            Salt,
            HashStart,
            Hash,
        }

        let mut state = HashStates::Start;

        let mut has_m = false;
        let mut has_t = false;
        let mut has_p = false;

        let mut v = 0..0;
        let mut m = 0..0;
        let mut t = 0..0;
        let mut p = 0..0;

        let mut salt = String::with_capacity(22); // 16 bytes, base64-encoded (no padding)
        let mut hash = String::new();

        let mut alg = Algorithm::Argon2id;

        for (i, c) in s.chars().enumerate() {
            match state {
                HashStates::Start => {
                    state = match c {
                        '$' => HashStates::HashTypeStart,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeStart => {
                    state = match c {
                        'a' => HashStates::HashTypeA,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeA => {
                    state = match c {
                        'r' => HashStates::HashTypeAr,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeAr => {
                    state = match c {
                        'g' => HashStates::HashTypeArg,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArg => {
                    state = match c {
                        'o' => HashStates::HashTypeArgo,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgo => {
                    state = match c {
                        'n' => HashStates::HashTypeArgon,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgon => {
                    state = match c {
                        '2' => HashStates::HashTypeArgon2,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgon2 => {
                    state = match c {
                        'd' => HashStates::HashTypeArgon2d,
                        'i' => HashStates::HashTypeArgon2i,
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgon2d => {
                    state = match c {
                        '$' => {
                            alg = Algorithm::Argon2d;
                            HashStates::HashTypeComplete
                        }
                        _ => return Err(Argon2Error::InvalidHash("Missing '$' delimiter")),
                    };
                }

                HashStates::HashTypeArgon2i => {
                    state = match c {
                        'd' => HashStates::HashTypeArgon2id,
                        '$' => {
                            alg = Algorithm::Argon2i;
                            HashStates::HashTypeComplete
                        }
                        _ => return Err(Argon2Error::InvalidHash("Must begin with $argon2id")),
                    };
                }

                HashStates::HashTypeArgon2id => {
                    state = match c {
                        '$' => {
                            alg = Algorithm::Argon2id;
                            HashStates::HashTypeComplete
                        }
                        _ => return Err(Argon2Error::InvalidHash("Missing '$' delimiter")),
                    };
                }

                HashStates::HashTypeComplete => {
                    state = match c {
                        'v' => HashStates::VKey,
                        _ => return Err(Argon2Error::InvalidHash("Missing algorithm version")),
                    };
                }

                HashStates::VKey => {
                    state = match c {
                        '=' => HashStates::VEquals,
                        _ => return Err(Argon2Error::InvalidHash("Missing algorithm version")),
                    };
                }

                HashStates::VEquals => {
                    v = i..(i + 1);
                    state = HashStates::VValue;
                }

                HashStates::VValue => {
                    if c == '$' {
                        state = HashStates::VComplete;
                    } else {
                        v.end += 1;
                    }
                }

                HashStates::VComplete => {
                    state = match c {
                        'm' => HashStates::MKey,
                        't' => HashStates::TKey,
                        'p' => HashStates::PKey,
                        _ => {
                            return Err(Argon2Error::InvalidHash(
                                "Unrecognized or missing parameter",
                            ))
                        }
                    }
                }

                HashStates::MKey => {
                    if has_m {
                        return Err(Argon2Error::InvalidHash("Duplicate key 'm'"));
                    }

                    state = match c {
                        '=' => HashStates::MEquals,
                        _ => return Err(Argon2Error::InvalidHash("Missing 'm' parameter")),
                    }
                }

                HashStates::MEquals => {
                    m = i..(i + 1);
                    state = HashStates::MValue;
                }

                HashStates::MValue => {
                    if c == ',' {
                        state = HashStates::MComplete;
                    } else if c == '$' && has_t && has_p {
                        state = HashStates::Salt;
                    } else {
                        m.end += 1;
                    }
                }

                HashStates::MComplete => {
                    has_m = true;

                    state = match c {
                        't' => HashStates::TKey,
                        'p' => HashStates::PKey,
                        _ => {
                            return Err(Argon2Error::InvalidHash(
                                "Unrecognized or missing parameter",
                            ))
                        }
                    }
                }

                HashStates::TKey => {
                    if has_t {
                        return Err(Argon2Error::InvalidHash("Duplicate key 't'"));
                    }

                    state = match c {
                        '=' => HashStates::TEquals,
                        _ => return Err(Argon2Error::InvalidHash("Missing 't' paramter")),
                    }
                }

                HashStates::TEquals => {
                    t = i..(i + 1);
                    state = HashStates::TValue;
                }

                HashStates::TValue => {
                    if c == ',' {
                        state = HashStates::TComplete;
                    } else if c == '$' && has_m && has_p {
                        state = HashStates::Salt;
                    } else {
                        t.end += 1;
                    }
                }

                HashStates::TComplete => {
                    has_t = true;

                    state = match c {
                        'm' => HashStates::MKey,
                        'p' => HashStates::PKey,
                        _ => {
                            return Err(Argon2Error::InvalidHash(
                                "Unrecognized or missing paramter",
                            ))
                        }
                    }
                }

                HashStates::PKey => {
                    if has_p {
                        return Err(Argon2Error::InvalidHash("Duplicate key 'p'"));
                    }

                    state = match c {
                        '=' => HashStates::PEquals,
                        _ => return Err(Argon2Error::InvalidHash("Missing 'p' paramter")),
                    }
                }

                HashStates::PEquals => {
                    p = i..(i + 1);
                    state = HashStates::PValue;
                }

                HashStates::PValue => {
                    if c == ',' {
                        state = HashStates::PComplete;
                    } else if c == '$' && has_m && has_t {
                        state = HashStates::Salt;
                    } else {
                        p.end += 1;
                    }
                }

                HashStates::PComplete => {
                    has_p = true;

                    state = match c {
                        'm' => HashStates::MKey,
                        't' => HashStates::TKey,
                        _ => {
                            return Err(Argon2Error::InvalidHash(
                                "Unrecognized or missing parameter",
                            ))
                        }
                    }
                }

                HashStates::Salt => {
                    if c == '$' {
                        state = HashStates::HashStart;
                    } else {
                        salt.push(c);
                    }
                }

                HashStates::HashStart => {
                    if c == '$' {
                        return Err(Argon2Error::InvalidHash("Missing hash after salt"));
                    }

                    hash = String::from(&s[i..]);
                    state = HashStates::Hash;

                    break;
                }

                // Should break out of loop before this point
                HashStates::Hash => unreachable!(),
            }
        }

        if std::mem::discriminant(&state) != std::mem::discriminant(&HashStates::Hash) {
            return Err(Argon2Error::InvalidHash("Hash is incomplete"));
        }

        salt.shrink_to_fit();

        let v: u32 = match s[v].parse() {
            Ok(v) => v,
            Err(_) => return Err(Argon2Error::InvalidHash("Invalid version")),
        };

        let mem_cost_kib: u32 = match s[m].parse() {
            Ok(m) => m,
            Err(_) => return Err(Argon2Error::InvalidHash("Invalid m")),
        };

        let iterations: u32 = match s[t].parse() {
            Ok(t) => t,
            Err(_) => return Err(Argon2Error::InvalidHash("Invalid t")),
        };

        let threads: u32 = match s[p].parse() {
            Ok(p) => p,
            Err(_) => return Err(Argon2Error::InvalidHash("Invalid p")),
        };

        Ok(Self {
            v,
            alg,
            mem_cost_kib,
            iterations,
            threads,
            b64_salt: salt,
            b64_hash: hash,
        })
    }
}
