// SPDX-License-Identifier: AGPL-3.0-only
//! Opt-in, first-public-frame measurements; never logs cell contents.

use std::{fs::File, io::Write, os::windows::io::AsRawHandle, path::Path};

use ratatui::buffer::Buffer;
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE},
    System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, COORD, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode,
        GetConsoleOutputCP, GetConsoleScreenBufferInfo, GetStdHandle, ReadConsoleOutputCharacterW,
        STD_OUTPUT_HANDLE,
    },
};
use zeroize::Zeroizing;

use crate::Failure;

pub(super) struct Diagnostic {
    output: File,
    writer: File,
}

impl Diagnostic {
    pub(super) fn report_file(&self) -> Result<File, Failure> {
        self.output.try_clone().map_err(|_| Failure::Unavailable)
    }

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

    pub(super) fn writer_experiments(&mut self) -> Result<(), Failure> {
        self.writer
            .write_all(b"\x1b[2J\x1b[1;1HPM27Probe")
            .map_err(|_| Failure::Unavailable)?;
        self.record("assembled")?;
        self.writer
            .write_all(b"\x1b[2J")
            .map_err(|_| Failure::Unavailable)?;
        for part in [b"\x1b[".as_slice(), b"1", b";", b"1", b"H", b"PM27Probe"] {
            self.writer
                .write_all(part)
                .map_err(|_| Failure::Unavailable)?;
        }
        self.record("fragmented")?;
        self.writer
            .write_all("\x1b[2J\x1b[1;1H┌┌┌┌".as_bytes())
            .map_err(|_| Failure::Unavailable)?;
        self.record("utf8")
    }

    fn snapshot(&mut self, stage: &str, name: &str, handle: HANDLE) -> Result<(), Failure> {
        let mut mode = 0;
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        if unsafe { GetConsoleMode(handle, &raw mut mode) } == 0 {
            return self.query_failure(stage, name, "mode");
        }
        if unsafe { GetConsoleScreenBufferInfo(handle, &raw mut info) } == 0 {
            return self.query_failure(stage, name, "geometry");
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
        {
            return self.query_failure(stage, name, "cells");
        }
        if read as usize != cells {
            return Err(Failure::Unavailable);
        }
        let markers = ["Password Manager", "human TLS-RPK", "Password required"].map(|marker| {
            let needle: Vec<u16> = marker.encode_utf16().collect();
            text.chunks(width)
                .any(|row| row.windows(needle.len()).any(|v| v == needle))
        });
        let probe: Vec<u16> = "PM27Probe".encode_utf16().collect();
        let probe_at_origin = text.starts_with(&probe);
        let boxes = text
            .iter()
            .filter(|unit| (0x2500..=0x257f).contains(*unit))
            .count();
        let corners = text.iter().filter(|unit| **unit == 0x250c).count();
        let literal_csi = text.windows(2).filter(|pair| *pair == [0x1b, 0x5b]).count();
        let output_cp = unsafe { GetConsoleOutputCP() };
        if output_cp == 0 {
            return self.query_failure(stage, name, "output-cp");
        }
        writeln!(self.output,
            "TUI_PROBE stage={stage} handle={name} vt={} mode={mode} buffer={}x{} viewport={},{},{},{} cursor={},{} manager={} rpk={} prompt={} cp={output_cp} probe-origin={probe_at_origin} boxes={boxes} corners={corners} literal-csi={literal_csi}",
            mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0, info.dwSize.X, info.dwSize.Y,
            info.srWindow.Left, info.srWindow.Top, info.srWindow.Right, info.srWindow.Bottom,
            info.dwCursorPosition.X, info.dwCursorPosition.Y, markers[0], markers[1], markers[2]
        ).map_err(|_| Failure::Unavailable)
    }

    fn query_failure(&mut self, stage: &str, name: &str, query: &str) -> Result<(), Failure> {
        let code = unsafe { GetLastError() };
        writeln!(
            self.output,
            "TUI_PROBE stage={stage} handle={name} query={query}-failed code={code}"
        )
        .map_err(|_| Failure::Unavailable)
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
                        prompt_at = Some((
                            usize::from(area.x) + ratatui::text::Line::raw(&row[..x]).width(),
                            y,
                        ));
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
