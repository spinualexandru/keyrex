//! File operations shared by vault persistence, portable backups, and completions.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use tracing::debug;
use zeroize::Zeroizing;

/// Matches the usual SYMLOOP_MAX, so symlink cycles fail instead of spinning.
const MAX_SYMLINK_HOPS: usize = 40;

/// Staging files are named `.<destination name>.keyrex-tmp-<random>`, so leftovers from
/// an interrupted write can be traced to their destination and removed.
const TEMP_MARKER: &str = ".keyrex-tmp-";

/// Who may read a written file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Access {
    /// Owner-only on Unix, set before any bytes are written. For anything holding secrets.
    Private,
    /// Follows the umask, like a normally created file.
    Shared,
}

/// Reject symlinks and special files before reading or replacing secrets.
pub(crate) fn check_regular(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular file, not a symlink or directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Follow symlinks in the final path component. Replacing the result updates a
/// symlinked vault's target instead of swapping the link for a regular file.
pub(crate) fn resolve_link(path: &Path) -> io::Result<PathBuf> {
    let mut resolved = path.to_path_buf();
    let mut hops = 0;
    loop {
        match fs::symlink_metadata(&resolved) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                if hops == MAX_SYMLINK_HOPS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "too many levels of symbolic links",
                    ));
                }
                hops += 1;
                let target = fs::read_link(&resolved)?;
                resolved = match resolved.parent() {
                    Some(parent) => parent.join(target),
                    None => target,
                };
            }
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => return Ok(resolved),
        }
    }
}

/// Read the vault at `path`, through a symlink if it is one. Returns the file that holds
/// the bytes, and `None` for its contents when it does not exist.
pub(crate) fn read_through_link(path: &Path) -> io::Result<(PathBuf, Option<Zeroizing<Vec<u8>>>)> {
    let target = resolve_link(path)?;
    let data = if check_regular(&target)? {
        Some(Zeroizing::new(read_regular_bytes(&target)?))
    } else {
        None
    };
    Ok((target, data))
}

pub(crate) fn read_regular_bytes(path: &Path) -> io::Result<Vec<u8>> {
    if !check_regular(path)? {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "file does not exist",
        ));
    }
    let mut file = open_no_follow(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular file",
        ));
    }
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

/// Open without following a symlink swapped in after `check_regular`.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NONBLOCK keeps a swapped-in FIFO from blocking; regular file reads ignore it.
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

/// Windows has no plain no-follow open: FILE_FLAG_OPEN_REPARSE_POINT would also open
/// cloud placeholders and deduplicated files without their data, so only `check_regular`
/// guards against symlinks here.
#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> io::Result<File> {
    File::open(path)
}

pub(crate) fn read_regular(path: &Path) -> io::Result<String> {
    String::from_utf8(read_regular_bytes(path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub(crate) fn reject_same_file(source: &Path, destination: &Path) -> io::Result<()> {
    if !destination.exists() {
        return Ok(());
    }
    let same_path = fs::canonicalize(source)? == fs::canonicalize(destination)?;
    #[cfg(unix)]
    let same_inode = {
        use std::os::unix::fs::MetadataExt;
        let source_metadata = fs::metadata(source)?;
        let destination_metadata = fs::metadata(destination)?;
        source_metadata.dev() == destination_metadata.dev()
            && source_metadata.ino() == destination_metadata.ino()
    };
    #[cfg(not(unix))]
    let same_inode = false;
    if same_path || same_inode {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source and destination are the same file",
        ));
    }
    Ok(())
}

/// Stage in the destination directory, synchronize, then publish. New files never clobber.
/// Symlinks are refused; callers that should write through one resolve it first.
/// Leftover staging files from interrupted writes to `path` are removed first, so
/// concurrent writes to one destination must be serialized, as the vault lock does.
pub(crate) fn atomic_write(
    path: &Path,
    contents: &[u8],
    replace: bool,
    access: Access,
) -> io::Result<()> {
    if check_regular(path)? && !replace {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination has no file name")
    })?;
    fs::create_dir_all(parent)?;
    remove_stale_temps(parent, |destination| destination == name.as_encoded_bytes());
    let mut prefix = OsString::from(".");
    prefix.push(name);
    prefix.push(TEMP_MARKER);
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix);
    #[cfg(unix)]
    if access == Access::Shared {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o666));
    }
    // tempfile creates owner-only files on Unix, before any secret bytes are written.
    let mut staged = builder.tempfile_in(parent)?;
    staged.write_all(contents)?;
    staged.as_file().sync_all()?;
    if replace {
        staged.persist(path).map_err(|error| error.error)?;
    } else {
        persist_new(staged, path)?;
    }
    // The file is already published, so a directory that cannot be synced is not a failure.
    if let Err(error) = sync_dir(parent) {
        debug!(%error, directory = %parent.display(), "Could not sync directory after write");
    }
    Ok(())
}

/// Delete staging files that interrupted writes left in `directory` for destinations
/// accepted by `is_destination`. Only call while no such write can be in flight.
pub(crate) fn remove_stale_temps(directory: &Path, is_destination: impl Fn(&[u8]) -> bool) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name.as_encoded_bytes().strip_prefix(b".") else {
            continue;
        };
        let Some(marker) = rest
            .windows(TEMP_MARKER.len())
            .rposition(|window| window == TEMP_MARKER.as_bytes())
        else {
            continue;
        };
        if is_destination(&rest[..marker]) && entry.file_type().is_ok_and(|kind| kind.is_file()) {
            debug!(path = %entry.path().display(), "Removing interrupted write");
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Overwrite a small bookkeeping file in place: owner-only, never through a symlink, and
/// not synced, since losing the latest contents in a crash is harmless.
pub(crate) fn write_bookkeeping(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)?.write_all(contents)
}

#[cfg(unix)]
fn sync_dir(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_directory: &Path) -> io::Result<()> {
    Ok(())
}

fn persist_new(staged: NamedTempFile, path: &Path) -> io::Result<()> {
    match staged.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => Err(error.error),
        // FAT, exFAT, and some network filesystems support neither no-replace renames
        // nor hard links.
        Err(error) => {
            debug!(error = %error.error, "No-clobber rename unsupported; claiming the name first");
            claim_and_persist(error.file, path)
        }
    }
}

/// Claim the name with an exclusive create, then rename over that empty placeholder.
fn claim_and_persist(staged: NamedTempFile, path: &Path) -> io::Result<()> {
    OpenOptions::new().write(true).create_new(true).open(path)?;
    match staged.persist(path) {
        Ok(_) => Ok(()),
        Err(error) => {
            if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.len() == 0) {
                let _ = fs::remove_file(path);
            }
            Err(error.error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claimed_publish_writes_new_files_and_never_clobbers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("backup.json");
        let mut staged = NamedTempFile::new_in(directory.path()).unwrap();
        staged.write_all(b"first").unwrap();
        claim_and_persist(staged, &path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");

        let mut staged = NamedTempFile::new_in(directory.path()).unwrap();
        staged.write_all(b"second").unwrap();
        let error = claim_and_persist(staged, &path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"first");
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_resolve_through_relative_chains_and_cycles_fail() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("data/vault.dat");
        fs::create_dir(directory.path().join("data")).unwrap();
        symlink("data/vault.dat", directory.path().join("middle")).unwrap();
        symlink("middle", directory.path().join("vault.dat")).unwrap();
        assert_eq!(
            resolve_link(&directory.path().join("vault.dat")).unwrap(),
            target
        );
        let plain = directory.path().join("plain.dat");
        assert_eq!(resolve_link(&plain).unwrap(), plain);

        symlink("loop-b", directory.path().join("loop-a")).unwrap();
        symlink("loop-a", directory.path().join("loop-b")).unwrap();
        assert!(resolve_link(&directory.path().join("loop-a")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn reads_and_replacements_refuse_symlinks() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        fs::write(&target, "secret").unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_regular_bytes(&link).is_err());
        assert!(open_no_follow(&link).is_err());
        assert!(atomic_write(&link, b"replacement", true, Access::Private).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"secret");
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_directory_does_not_fail_a_published_write() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        // Root bypasses Unix mode bits, so the directory would still be readable.
        if fs::metadata(directory.path()).unwrap().uid() == 0 {
            return;
        }
        let output = directory.path().join("write-only");
        fs::create_dir(&output).unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o300)).unwrap();
        let path = output.join("vault.dat");
        let result = atomic_write(&path, b"published", false, Access::Private);
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        result.unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"published");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_chains_up_to_the_kernel_limit_resolve() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("vault.dat");
        let mut next = target.clone();
        for hop in 0..=MAX_SYMLINK_HOPS {
            let link = directory.path().join(format!("link-{hop}"));
            symlink(&next, &link).unwrap();
            next = link;
        }
        let at_limit = directory
            .path()
            .join(format!("link-{}", MAX_SYMLINK_HOPS - 1));
        assert_eq!(resolve_link(&at_limit).unwrap(), target);
        assert!(resolve_link(&next).is_err());
    }

    #[test]
    fn writes_remove_interrupted_staging_files_for_the_same_destination() {
        let directory = tempfile::tempdir().unwrap();
        let stale = directory.path().join(".vault.dat.keyrex-tmp-abc123");
        let unrelated = directory.path().join(".other.dat.keyrex-tmp-abc123");
        fs::write(&stale, "leftover secret").unwrap();
        fs::write(&unrelated, "another destination").unwrap();
        atomic_write(
            &directory.path().join("vault.dat"),
            b"saved",
            false,
            Access::Private,
        )
        .unwrap();
        assert!(!stale.exists());
        assert!(unrelated.exists());
        let leftovers = fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(TEMP_MARKER))
            .count();
        assert_eq!(leftovers, 1);
    }

    #[cfg(unix)]
    #[test]
    fn shared_files_get_the_same_mode_as_normally_created_files() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let probe = directory.path().join("probe");
        fs::write(&probe, "").unwrap();
        let shared = directory.path().join("shared");
        atomic_write(&shared, b"script", false, Access::Shared).unwrap();
        let private = directory.path().join("private");
        atomic_write(&private, b"secret", false, Access::Private).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&shared), mode(&probe));
        assert_eq!(mode(&private), 0o600);
    }
}
