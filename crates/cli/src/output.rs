//! Small CLI output helpers (no external crate to keep MVP-0 light).

pub fn header(s: &str) {
    println!("== {s} ==");
}

pub fn kv(k: &str, v: &str) {
    println!("  {k}: {v}");
}

pub fn warn(s: &str) {
    println!("warn: {s}");
}

pub fn hint(s: &str) {
    println!("hint: {s}");
}
