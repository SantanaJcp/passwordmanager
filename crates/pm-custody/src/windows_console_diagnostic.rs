// SPDX-License-Identifier: AGPL-3.0-only
//! Opt-in, first-public-frame measurements; never logs cell contents.

use std::{fs::File, io::Write, os::windows::io::AsRawHandle, path::Path};

use ratatui::buffer::Buffer;
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, COORD, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode,
        GetConsoleScreenBufferInfo, GetStdHandle, ReadConsoleOutputCharacterW, STD_OUTPUT_HANDLE,
    },
};
use zeroize::Zeroizing;

use crate::Failure;

pub(super) struct Diagnostic {
    output: File,
    writer: File,
}

impl Diagnostic {
    pub(super) fn create(path: &Path, writer: &File) -> Result<Self, Failure> {
        let output = File::options()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| Failure::Unavailable)?;
        let writer = writer.try_clone().map_err(|_| Failure::Unavailable)?;
        Ok(Self { output, writer })
    }

    pub(super) fn record(&mut self, stage: &str) -> Result<(), Failure> {
        let active = super::open_terminal()?;
        for (name, handle) in [
            ("writer", self.writer.as_raw_handle()),
            ("stdout", unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }),
            ("active", active.as_raw_handle()),
        ] {
            self.snapshot(stage, name, handle)?;
        }
        self.output.flush().map_err(|_| Failure::Unavailable)
    }

    fn snapshot(&mut self, stage: &str, name: &str, handle: HANDLE) -> Result<(), Failure> {
        let mut mode = 0;
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        if unsafe { GetConsoleMode(handle, &raw mut mode) } == 0
            || unsafe { GetConsoleScreenBufferInfo(handle, &raw mut info) } == 0
        {
            return Err(Failure::Unavailable);
        }
        let width = usize::try_from(info.dwSize.X).map_err(|_| Failure::Unavailable)?;
        let height = usize::try_from(info.dwSize.Y).map_err(|_| Failure::Unavailable)?;
        let cells = width
            .checked_mul(height)
            .filter(|n| *n > 0 && *n <= 1_048_576)
            .ok_or(Failure::Unavailable)?;
        let mut text = Zeroizing::new(vec![0_u16; cells]);
        let mut read = 0;
        if unsafe {
            ReadConsoleOutputCharacterW(
                handle,
                text.as_mut_ptr(),
                u32::try_from(cells).map_err(|_| Failure::Unavailable)?,
                COORD { X: 0, Y: 0 },
                &raw mut read,
            )
        } == 0
            || read as usize != cells
        {
            return Err(Failure::Unavailable);
        }
        let markers = ["Password Manager", "human TLS-RPK", "Password required"].map(|marker| {
            let needle: Vec<u16> = marker.encode_utf16().collect();
            text.chunks(width)
                .any(|row| row.windows(needle.len()).any(|v| v == needle))
        });
        writeln!(self.output,
            "TUI_PROBE stage={stage} handle={name} vt={} mode={mode} buffer={}x{} viewport={},{},{},{} cursor={},{} manager={} rpk={} prompt={}",
            mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0, info.dwSize.X, info.dwSize.Y,
            info.srWindow.Left, info.srWindow.Top, info.srWindow.Right, info.srWindow.Bottom,
            info.dwCursorPosition.X, info.dwCursorPosition.Y, markers[0], markers[1], markers[2]
        ).map_err(|_| Failure::Unavailable)
    }

    pub(super) fn frame(&mut self, buffer: &Buffer) -> Result<(), Failure> {
        let area = buffer.area;
        let mut markers = [false; 3];
        let mut prompt_at = None;
        for y in area.y..area.bottom() {
            let mut row = Zeroizing::new(String::new());
            for x in area.x..area.right() {
                row.push_str(buffer[(x, y)].symbol());
            }
            for (index, marker) in ["Password Manager", "human TLS-RPK", "Password required"]
                .iter()
                .enumerate()
            {
                if let Some(x) = row.find(marker) {
                    markers[index] = true;
                    if index == 2 {
                        prompt_at = Some((x, y));
                    }
                }
            }
        }
        writeln!(self.output,
            "TUI_PROBE stage=frame area={},{},{}x{} manager={} rpk={} prompt={} prompt-at={prompt_at:?}",
            area.x, area.y, area.width, area.height, markers[0], markers[1], markers[2]
        ).map_err(|_| Failure::Unavailable)?;
        self.output.flush().map_err(|_| Failure::Unavailable)
    }
}
