// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PrimaryFailure {
    Usage,
    Unavailable,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CleanupFailureKind {
    OwnedPathRemoval,
    NativeResourceRestoration,
}

#[derive(Debug)]
pub(crate) struct CleanupFailure {
    pub(crate) kind: CleanupFailureKind,
    pub(crate) source: std::io::Error,
}

#[derive(Debug)]
pub(crate) enum Failure {
    Usage,
    Unavailable,
    WithCleanup {
        primary: PrimaryFailure,
        cleanups: Vec<CleanupFailure>,
    },
}

impl Failure {
    pub(crate) fn after_owned_path_cleanup(self, cleanup: std::io::Result<()>) -> Self {
        let Err(source) = cleanup else {
            return self;
        };
        let failure = CleanupFailure {
            kind: CleanupFailureKind::OwnedPathRemoval,
            source,
        };
        match self {
            Self::Usage => Self::WithCleanup {
                primary: PrimaryFailure::Usage,
                cleanups: vec![failure],
            },
            Self::Unavailable => Self::WithCleanup {
                primary: PrimaryFailure::Unavailable,
                cleanups: vec![failure],
            },
            Self::WithCleanup {
                primary,
                mut cleanups,
            } => {
                cleanups.push(failure);
                Self::WithCleanup { primary, cleanups }
            }
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn after_native_cleanup(
        self,
        cleanup: Result<(), pm_native_channel::ChannelAuthenticationError>,
    ) -> Self {
        let Err(source) = cleanup else {
            return self;
        };
        let failure = CleanupFailure {
            kind: CleanupFailureKind::NativeResourceRestoration,
            source: std::io::Error::other(source),
        };
        match self {
            Self::Usage => Self::WithCleanup {
                primary: PrimaryFailure::Usage,
                cleanups: vec![failure],
            },
            Self::Unavailable => Self::WithCleanup {
                primary: PrimaryFailure::Unavailable,
                cleanups: vec![failure],
            },
            Self::WithCleanup {
                primary,
                mut cleanups,
            } => {
                cleanups.push(failure);
                Self::WithCleanup { primary, cleanups }
            }
        }
    }

    pub(crate) const fn primary(&self) -> PrimaryFailure {
        match self {
            Self::Usage => PrimaryFailure::Usage,
            Self::Unavailable => PrimaryFailure::Unavailable,
            Self::WithCleanup { primary, .. } => match primary {
                PrimaryFailure::Usage => PrimaryFailure::Usage,
                PrimaryFailure::Unavailable => PrimaryFailure::Unavailable,
            },
        }
    }

    pub(crate) fn cleanups(&self) -> &[CleanupFailure] {
        match self {
            Self::WithCleanup { cleanups, .. } => cleanups,
            Self::Usage | Self::Unavailable => &[],
        }
    }

    pub(crate) fn has_native_cleanup_failure(&self) -> bool {
        self.cleanups()
            .iter()
            .any(|cleanup| cleanup.kind == CleanupFailureKind::NativeResourceRestoration)
    }

    pub(crate) fn merge(self, other: Self) -> Self {
        let (primary, mut cleanups) = match self {
            Self::Usage => (PrimaryFailure::Usage, Vec::new()),
            Self::Unavailable => (PrimaryFailure::Unavailable, Vec::new()),
            Self::WithCleanup { primary, cleanups } => (primary, cleanups),
        };
        cleanups.extend(match other {
            Self::Usage | Self::Unavailable => Vec::new(),
            Self::WithCleanup { cleanups, .. } => cleanups,
        });
        if cleanups.is_empty() {
            match primary {
                PrimaryFailure::Usage => Self::Usage,
                PrimaryFailure::Unavailable => Self::Unavailable,
            }
        } else {
            Self::WithCleanup { primary, cleanups }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_each_typed_cleanup_error_after_the_primary_failure() {
        let directory =
            std::env::temp_dir().join(format!("pm-custody-cleanup-errors-{}", std::process::id()));
        std::fs::create_dir(&directory).expect("fixture directory should be unique");
        let first = std::fs::remove_file(&directory);
        let second = std::fs::remove_file(&directory);
        std::fs::remove_dir(&directory).expect("fixture should remove its exact directory");

        let failure = Failure::Unavailable
            .after_owned_path_cleanup(first)
            .after_owned_path_cleanup(second);

        assert_eq!(failure.primary(), PrimaryFailure::Unavailable);
        assert_eq!(failure.cleanups().len(), 2);
        assert!(
            failure
                .cleanups()
                .iter()
                .all(|cleanup| cleanup.kind == CleanupFailureKind::OwnedPathRemoval)
        );
        assert!(
            failure
                .cleanups()
                .iter()
                .all(|cleanup| cleanup.source.raw_os_error().is_some())
        );
    }

    #[test]
    fn merging_failures_retains_cleanup_evidence() {
        let directory = std::env::temp_dir().join(format!(
            "pm-custody-combined-cleanup-errors-{}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("fixture directory should be unique");
        let cleanup = std::fs::remove_file(&directory);
        std::fs::remove_dir(&directory).expect("fixture should remove its exact directory");

        let failure = Failure::Unavailable
            .after_owned_path_cleanup(cleanup)
            .merge(Failure::Unavailable);

        assert_eq!(failure.primary(), PrimaryFailure::Unavailable);
        assert_eq!(failure.cleanups().len(), 1);
        assert_eq!(
            failure.cleanups()[0].kind,
            CleanupFailureKind::OwnedPathRemoval
        );
    }
}
