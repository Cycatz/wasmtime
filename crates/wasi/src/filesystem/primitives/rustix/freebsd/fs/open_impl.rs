use super::super::super::fs::compute_oflags;
use crate::filesystem::primitives::{OpenOptions, errors, manually};
use rustix::fs::{Mode, OFlags, RawMode, openat};
use rustix::io::Errno;
use std::path::Path;
use std::{fs, io};

pub(crate) fn open_impl(
    start: &fs::File,
    path: &Path,
    options: &OpenOptions,
) -> io::Result<fs::File> {
    if !super::beneath_supported() {
        return manually::open(start, path, options);
    }

    let oflags = compute_oflags(options)? | OFlags::RESOLVE_BENEATH;

    let mode = if oflags.contains(OFlags::CREATE) {
        Mode::from_bits((options.ext.mode & 0o7777) as RawMode).unwrap()
    } else {
        Mode::empty()
    };

    match openat(start, path, oflags, mode) {
        Ok(file) => Ok(file.into()),
        Err(Errno::NOTCAPABLE) => Err(errors::escape_attempt()),
        // FreeBSD reports `EMLINK` when `O_NOFOLLOW` encounters a symlink.
        // Normalize this to the portable `ELOOP` used by WASI for this case.
        Err(Errno::MLINK) if oflags.contains(OFlags::NOFOLLOW) => Err(Errno::LOOP.into()),
        Err(err) => Err(err.into()),
    }
}
