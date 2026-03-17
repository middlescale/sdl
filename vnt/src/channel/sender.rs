use std::io;
use std::sync::mpsc::{SyncSender, TrySendError};

use crate::channel::notify::AcceptNotify;
pub struct AcceptSocketSender<T> {
    sender: SyncSender<T>,
    notify: AcceptNotify,
}

impl<T> Clone for AcceptSocketSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            notify: self.notify.clone(),
        }
    }
}

impl<T> AcceptSocketSender<T> {
    pub fn new(notify: AcceptNotify, sender: SyncSender<T>) -> Self {
        Self { sender, notify }
    }
    pub fn try_add_socket(&self, t: T) -> io::Result<()> {
        match self.sender.try_send(t) {
            Ok(_) => self.notify.add_socket(),
            Err(e) => match e {
                TrySendError::Full(_) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                TrySendError::Disconnected(_) => Err(io::Error::from(io::ErrorKind::WriteZero)),
            },
        }
    }
}
