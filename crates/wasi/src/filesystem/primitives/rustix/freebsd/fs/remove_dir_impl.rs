use crate::filesystem::primitives::{errors, via_parent};
use rustix::fs::{AtFlags, unlinkat};
use std::path::Path;
use std::{fs, io};

pub(crate) fn remove_dir_impl(start: &fs::File, path: &Path) -> io::Result<()> {
    if !super::beneath_supported() {
        return via_parent::remove_dir(start, path);
    }

    // FreeBSD rejects a final `..` component with `EINVAL` before
    // `AT_RESOLVE_BENEATH` can report the sandbox escape as `ENOTCAPABLE`.
    if path == Path::new("..") {
        return Err(errors::escape_attempt());
    }

    Ok(unlinkat(
        start,
        path,
        AtFlags::RESOLVE_BENEATH | AtFlags::REMOVEDIR,
    )?)
}
