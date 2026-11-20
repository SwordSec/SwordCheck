//! Progress reporting for long-running scans.
//!
//! Scans run on a worker thread and describe what they are doing through a
//! `Progress` handle. The handle either discards the events, prints them to
//! stderr (command line), or sends them over a channel (dashboard), so the
//! scan code never needs to know who is watching.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};

/// Something a scan wants the user to see.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// A new phase started (e.g. "Querying OSV.dev").
    Stage(String),
    /// `done` of `total` units of the current phase are finished.
    Step { done: usize, total: usize },
    /// A detail line (e.g. the product being looked up).
    Note(String),
}

#[derive(Debug, Clone, Default)]
enum Sink {
    #[default]
    None,
    Stderr,
    Channel(Sender<Event>),
}

/// A cheap, cloneable handle that scans report progress through.
#[derive(Debug, Clone, Default)]
pub struct Progress {
    sink: Sink,
    /// Set once the receiving end of a channel is gone. Shared by clones.
    cancelled: Arc<AtomicBool>,
}

impl Progress {
    /// Discards every event.
    pub fn none() -> Self {
        Self::default()
    }

    /// Prints phases and notes to stderr, one per line.
    pub fn stderr() -> Self {
        Self { sink: Sink::Stderr, ..Self::default() }
    }

    /// Returns a handle and the receiving end of its channel.
    pub fn channel() -> (Self, Receiver<Event>) {
        let (sender, receiver) = mpsc::channel();
        (Self { sink: Sink::Channel(sender), ..Self::default() }, receiver)
    }

    pub fn stage(&self, label: impl Into<String>) {
        self.send(Event::Stage(label.into()));
    }

    pub fn step(&self, done: usize, total: usize) {
        self.send(Event::Step { done, total });
    }

    pub fn note(&self, text: impl Into<String>) {
        self.send(Event::Note(text.into()));
    }

    /// Has whoever was watching gone away (the user cancelled the scan)?
    /// Long-running scans check this between network requests and stop.
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn send(&self, event: Event) {
        match &self.sink {
            Sink::None => {}
            Sink::Stderr => match event {
                Event::Stage(label) => eprintln!("› {label}"),
                Event::Note(text) => eprintln!("  {text}"),
                // Counters would flood a scrolling terminal.
                Event::Step { .. } => {}
            },
            // The receiver is gone when the user cancelled.
            Sink::Channel(sender) => {
                if sender.send(event).is_err() {
                    self.cancelled.store(true, Ordering::Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_delivers_events_in_order() {
        let (progress, events) = Progress::channel();
        progress.stage("Reading");
        progress.step(1, 2);
        progress.note("file");
        let received: Vec<Event> = events.try_iter().collect();
        assert_eq!(
            received,
            [Event::Stage("Reading".into()), Event::Step { done: 1, total: 2 }, Event::Note("file".into())]
        );
    }

    #[test]
    fn sending_after_the_receiver_is_dropped_is_harmless() {
        let (progress, events) = Progress::channel();
        let clone = progress.clone();
        assert!(!progress.cancelled());
        drop(events);
        progress.stage("still running");
        assert!(clone.cancelled(), "clones share the cancellation");
        Progress::none().step(1, 1);
        assert!(!Progress::none().cancelled());
    }
}
