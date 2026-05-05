//! Avoid logging full filesystem paths on stderr (directory names may include PII; CodeQL flags this).

use std::path::Path;

/// Last path segment for user-visible logs, or a generic placeholder when absent.
pub(crate) fn path_basename_for_log(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "input".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn basename_prefers_final_component() {
        let p = PathBuf::from("/tmp/secrets/my.dump");
        assert_eq!(path_basename_for_log(&p), "my.dump");
    }

    #[test]
    fn basename_fallback_for_empty_file_name() {
        assert_eq!(path_basename_for_log(Path::new("/")), "input");
    }
}
