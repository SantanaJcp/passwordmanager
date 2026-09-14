// SPDX-License-Identifier: AGPL-3.0-only

//! Runs acceptance-test subjects as real child processes and retains the
//! evidence needed to interpret their result.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const ARTIFACT_SCAN_LIMIT: usize = 8 * 1024 * 1024;
const ARTIFACT_COUNT_LIMIT: usize = 1_024;

/// Identifies the exact subject build represented by one observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildIdentity {
    component: String,
    build_id: String,
}

impl BuildIdentity {
    #[must_use]
    pub fn new(component: impl Into<String>, build_id: impl Into<String>) -> Self {
        Self {
            component: component.into(),
            build_id: build_id.into(),
        }
    }

    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    #[must_use]
    pub fn build_id(&self) -> &str {
        &self.build_id
    }
}

/// A synthetic marker whose observable locations must be recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Canary {
    label: String,
    marker: Vec<u8>,
}

impl Canary {
    #[must_use]
    pub fn new(label: impl Into<String>, marker: impl AsRef<[u8]>) -> Self {
        Self {
            label: label.into(),
            marker: marker.as_ref().to_vec(),
        }
    }
}

/// A channel in which a configured canary was observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanaryLocation {
    Argument(usize),
    Environment(OsString),
    Stdout,
    Stderr,
    TemporaryFile(PathBuf),
}

/// Locations recorded for one canary, without copying its marker into results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryObservation {
    label: String,
    locations: Vec<CanaryLocation>,
}

impl CanaryObservation {
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub fn locations(&self) -> &[CanaryLocation] {
        &self.locations
    }
}

/// Description of a child process. Environment inheritance is disabled unless
/// requested explicitly, so acceptance fixtures do not receive ambient values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRequest {
    program: OsString,
    args: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    inherit_environment: bool,
    timeout: Duration,
    output_limit: usize,
    build: BuildIdentity,
    canaries: Vec<Canary>,
}

impl ProcessRequest {
    #[must_use]
    pub fn new(program: impl AsRef<OsStr>, build: BuildIdentity) -> Self {
        Self {
            program: program.as_ref().to_owned(),
            args: Vec::new(),
            environment: Vec::new(),
            inherit_environment: false,
            timeout: DEFAULT_TIMEOUT,
            output_limit: DEFAULT_OUTPUT_LIMIT,
            build,
            canaries: Vec::new(),
        }
    }

    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_owned()));
        self
    }

    #[must_use]
    pub fn env(mut self, name: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        let name = name.as_ref();
        if let Some((_, current_value)) = self
            .environment
            .iter_mut()
            .find(|(current_name, _)| current_name == name)
        {
            value.as_ref().clone_into(current_value);
        } else {
            self.environment
                .push((name.to_owned(), value.as_ref().to_owned()));
        }
        self
    }

    #[must_use]
    pub fn inherit_environment(mut self, inherit: bool) -> Self {
        self.inherit_environment = inherit;
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn output_limit(mut self, bytes_per_stream: usize) -> Self {
        self.output_limit = bytes_per_stream;
        self
    }

    #[must_use]
    pub fn canaries<I>(mut self, canaries: I) -> Self
    where
        I: IntoIterator<Item = Canary>,
    {
        self.canaries.extend(canaries);
        self
    }
}

/// Portable termination information retained from [`ExitStatus`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Termination {
    code: Option<i32>,
    success: bool,
    timed_out: bool,
}

impl Termination {
    fn from_status(status: ExitStatus, timed_out: bool) -> Self {
        Self {
            code: status.code(),
            success: status.success() && !timed_out,
            timed_out,
        }
    }

    #[must_use]
    pub fn code(self) -> Option<i32> {
        self.code
    }

    #[must_use]
    pub fn success(self) -> bool {
        self.success
    }

    #[must_use]
    pub fn timed_out(self) -> bool {
        self.timed_out
    }
}

/// Complete observation of a child. Its temporary directory remains available
/// until this value is dropped.
#[derive(Debug)]
pub struct ProcessEvidence {
    temporary_directory: TemporaryDirectory,
    termination: Termination,
    stdout: Vec<u8>,
    stdout_truncated: bool,
    stderr: Vec<u8>,
    stderr_truncated: bool,
    build: BuildIdentity,
    canaries: Vec<CanaryObservation>,
    canary_scan_complete: bool,
}

impl ProcessEvidence {
    #[must_use]
    pub fn working_directory(&self) -> &Path {
        self.temporary_directory.path()
    }

    #[must_use]
    pub fn termination(&self) -> Termination {
        self.termination
    }

    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    #[must_use]
    pub fn stdout_truncated(&self) -> bool {
        self.stdout_truncated
    }

    #[must_use]
    pub fn stderr_truncated(&self) -> bool {
        self.stderr_truncated
    }

    /// False means one or more bounded channels were truncated, so absence of
    /// a canary from the observation is not conclusive.
    #[must_use]
    pub fn canary_scan_complete(&self) -> bool {
        self.canary_scan_complete
    }

    #[must_use]
    pub fn build(&self) -> &BuildIdentity {
        &self.build
    }

    #[must_use]
    pub fn canaries(&self) -> &[CanaryObservation] {
        &self.canaries
    }

    #[must_use]
    pub fn canary(&self, label: &str) -> Option<&CanaryObservation> {
        self.canaries
            .iter()
            .find(|observation| observation.label == label)
    }

    /// Removes the owned temporary directory and reports the single cleanup
    /// attempt to callers that need a checked completion boundary.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error from removing the owned directory.
    pub fn close(self) -> io::Result<()> {
        self.temporary_directory.close()
    }
}

/// Executes the request directly, without a shell, in a fresh owned directory.
///
/// # Errors
///
/// Returns an I/O error when the temporary directory cannot be created, the
/// child cannot run, or its temporary files cannot be inspected. Empty canary
/// markers are rejected as invalid input.
pub fn run(request: &ProcessRequest) -> io::Result<ProcessEvidence> {
    if request
        .canaries
        .iter()
        .any(|canary| canary.marker.is_empty())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "canary markers must not be empty",
        ));
    }
    if request.inherit_environment && !request.canaries.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ambient environment inheritance is incompatible with canary tracking",
        ));
    }

    let temporary_directory = TemporaryDirectory::create()?;
    let effective_environment = effective_environment(request);
    let mut command = Command::new(&request.program);
    command
        .args(&request.args)
        .current_dir(temporary_directory.path())
        .env_clear()
        .envs(effective_environment.iter().cloned())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);

    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("child stdout pipe was not available"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("child stderr pipe was not available"))?;
    let started = Instant::now();
    let output_limit = request.output_limit;
    let stdout_reader = thread::spawn(move || capture_output(stdout, output_limit));
    let stderr_reader = thread::spawn(move || capture_output(stderr, output_limit));
    let (status, process_timed_out) = wait_for_termination(&mut child, started, request.timeout)?;
    let output_timed_out = wait_for_output_readers(
        &mut child,
        &stdout_reader,
        &stderr_reader,
        started,
        request.timeout,
    )?;
    let stdout = join_output_reader(stdout_reader)?;
    let stderr = join_output_reader(stderr_reader)?;
    let artifacts = read_artifacts(temporary_directory.path())?;
    let canaries = observe_canaries(
        request,
        &effective_environment,
        &stdout.bytes,
        &stderr.bytes,
        &artifacts.files,
    );
    let canary_scan_complete = !stdout.truncated && !stderr.truncated && artifacts.complete;

    Ok(ProcessEvidence {
        temporary_directory,
        termination: Termination::from_status(status, process_timed_out || output_timed_out),
        stdout: stdout.bytes,
        stdout_truncated: stdout.truncated,
        stderr: stderr.bytes,
        stderr_truncated: stderr.truncated,
        build: request.build.clone(),
        canaries,
        canary_scan_complete,
    })
}

fn effective_environment(request: &ProcessRequest) -> Vec<(OsString, OsString)> {
    let mut environment = if request.inherit_environment {
        std::env::vars_os().collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    for (name, value) in &request.environment {
        if let Some((_, current_value)) = environment
            .iter_mut()
            .find(|(current_name, _)| current_name == name)
        {
            current_value.clone_from(value);
        } else {
            environment.push((name.clone(), value.clone()));
        }
    }
    environment
}

fn observe_canaries(
    request: &ProcessRequest,
    effective_environment: &[(OsString, OsString)],
    stdout: &[u8],
    stderr: &[u8],
    files: &[ScannedFile],
) -> Vec<CanaryObservation> {
    request
        .canaries
        .iter()
        .map(|canary| {
            let mut locations = Vec::new();
            for (index, argument) in request.args.iter().enumerate() {
                if contains(argument.as_encoded_bytes(), &canary.marker) {
                    locations.push(CanaryLocation::Argument(index));
                }
            }
            for (name, value) in effective_environment {
                if contains(value.as_encoded_bytes(), &canary.marker) {
                    locations.push(CanaryLocation::Environment(name.clone()));
                }
            }
            if contains(stdout, &canary.marker) {
                locations.push(CanaryLocation::Stdout);
            }
            if contains(stderr, &canary.marker) {
                locations.push(CanaryLocation::Stderr);
            }
            for file in files {
                if contains(&file.bytes, &canary.marker) {
                    locations.push(CanaryLocation::TemporaryFile(file.relative_path.clone()));
                }
            }
            CanaryObservation {
                label: canary.label.clone(),
                locations,
            }
        })
        .collect()
}

#[derive(Debug)]
struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn capture_output(mut reader: impl Read, limit: usize) -> io::Result<CapturedOutput> {
    let mut bytes = Vec::with_capacity(limit.min(8 * 1024));
    let mut truncated = false;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        let retained = remaining.min(count);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < count;
    }
    Ok(CapturedOutput { bytes, truncated })
}

fn join_output_reader(
    reader: thread::JoinHandle<io::Result<CapturedOutput>>,
) -> io::Result<CapturedOutput> {
    reader
        .join()
        .map_err(|_| io::Error::other("child output reader panicked"))?
}

fn wait_for_termination(
    child: &mut Child,
    started: Instant,
    timeout: Duration,
) -> io::Result<(ExitStatus, bool)> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((status, false));
        }
        if started.elapsed() >= timeout {
            terminate_process_tree(child)?;
            return child.wait().map(|status| (status, true));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_output_readers(
    child: &mut Child,
    stdout_reader: &thread::JoinHandle<io::Result<CapturedOutput>>,
    stderr_reader: &thread::JoinHandle<io::Result<CapturedOutput>>,
    started: Instant,
    timeout: Duration,
) -> io::Result<bool> {
    while !stdout_reader.is_finished() || !stderr_reader.is_finished() {
        if started.elapsed() >= timeout {
            terminate_process_tree(child)?;
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(false)
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_process_tree(child: &mut Child) -> io::Result<()> {
    let process_group = i32::try_from(child.id())
        .map_err(|_| io::Error::other("child process ID does not fit in i32"))?;
    // SAFETY: the negative, non-zero PID targets only the process group created
    // for this child. No pointers cross this platform FFI boundary.
    let _ = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    let _ = child.kill();
    Ok(())
}

#[cfg(not(unix))]
fn terminate_process_tree(child: &mut Child) -> io::Result<()> {
    child.kill()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn regular_files(root: &Path) -> io::Result<(Vec<PathBuf>, bool)> {
    let mut pending = vec![root.to_owned()];
    let mut files = Vec::new();
    let mut complete = true;
    let mut observed_entries = 0;
    while let Some(directory) = pending.pop() {
        let mut entries = Vec::new();
        for entry in fs::read_dir(directory)? {
            if observed_entries >= ARTIFACT_COUNT_LIMIT {
                complete = false;
                break;
            }
            entries.push(entry?);
            observed_entries += 1;
        }
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok((files, complete))
}

#[derive(Debug)]
struct ScannedFile {
    relative_path: PathBuf,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct ScannedArtifacts {
    files: Vec<ScannedFile>,
    complete: bool,
}

fn read_artifacts(root: &Path) -> io::Result<ScannedArtifacts> {
    let (paths, mut complete) = regular_files(root)?;
    let mut remaining = ARTIFACT_SCAN_LIMIT;
    let mut files = Vec::new();
    for path in paths {
        if remaining == 0 {
            complete = false;
            break;
        }
        let mut bytes = Vec::new();
        let read_limit = u64::try_from(remaining)
            .map_err(|_| io::Error::other("artifact scan limit does not fit u64"))?;
        fs::File::open(&path)?
            .take(read_limit + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > remaining {
            bytes.truncate(remaining);
            complete = false;
        }
        remaining -= bytes.len();
        files.push(ScannedFile {
            relative_path: path
                .strip_prefix(root)
                .map_err(|_| io::Error::other("artifact escaped its temporary directory"))?
                .to_owned(),
            bytes,
        });
    }
    Ok(ScannedArtifacts { files, complete })
}

#[derive(Debug)]
struct TemporaryDirectory {
    path: PathBuf,
    cleanup_attempted: bool,
}

impl TemporaryDirectory {
    fn create() -> io::Result<Self> {
        let base = std::env::temp_dir();
        for _ in 0..100 {
            let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = base.join(format!(
                "passwordmanager-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            match create_private_directory(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        cleanup_attempted: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn close(mut self) -> io::Result<()> {
        self.cleanup_attempted = true;
        fs::remove_dir_all(&self.path)
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        if !self.cleanup_attempted {
            self.cleanup_attempted = true;
            if fs::remove_dir_all(&self.path).is_err() {
                eprintln!("CLEANUP_FAILED");
            }
        }
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}
