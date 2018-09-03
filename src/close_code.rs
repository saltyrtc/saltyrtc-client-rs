use std::fmt;

/// Close codes used by SaltyRTC.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CloseCode {
    /// Websocket closed successfully (WebSocket internal close code)
    WsClosingNormal,
    /// Going away (WebSocket internal close code)
    WsGoingAway,
    /// Protocol error (WebSocket internal close code)
    WsProtocolError,
    /// Path full
    PathFull,
    /// SaltyRTC protocol error
    ProtocolError,
    /// Internal error
    InternalError,
    /// Handover of the signalling channel
    Handover,
    /// Dropped by initiator
    DroppedByInitiator,
    /// Initiator could not decrypt
    InitiatorCouldNotDecrypt,
    /// No shared task found
    NoSharedTask,
    /// Invalid key
    InvalidKey,
    /// Other close code
    Other(u16),
}

impl CloseCode {
    /// Return the numeric close code.
    pub fn as_number(self) -> u16 {
        use CloseCode::*;
        match self {
            WsClosingNormal => 1000,
            WsGoingAway => 1001,
            WsProtocolError => 1002,
            PathFull => 3000,
            ProtocolError => 3001,
            InternalError => 3002,
            Handover => 3003,
            DroppedByInitiator => 3004,
            InitiatorCouldNotDecrypt => 3005,
            NoSharedTask => 3006,
            InvalidKey => 3007,
            Other(code) => code,
        }
    }

    /// Create a `CloseCode` instance from a numeric close code.
    pub fn from_number(code: u16) -> CloseCode {
        use CloseCode::*;
        match code {
            1000 => WsClosingNormal,
            1001 => WsGoingAway,
            1002 => WsProtocolError,
            3000 => PathFull,
            3001 => ProtocolError,
            3002 => InternalError,
            3003 => Handover,
            3004 => DroppedByInitiator,
            3005 => InitiatorCouldNotDecrypt,
            3006 => NoSharedTask,
            3007 => InvalidKey,
            code => Other(code),
        }
    }
}

impl fmt::Display for CloseCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} ({})", self, self.as_number())
    }
}
