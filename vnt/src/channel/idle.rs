use std::net::Ipv4Addr;
use std::time::Duration;

use crate::channel::context::ChannelContext;
use crate::channel::Route;
use crate::data_plane::route_manager::RouteIdle;

pub struct Idle {
    read_idle: Duration,
    context: ChannelContext,
}

impl Idle {
    pub fn new(read_idle: Duration, context: ChannelContext) -> Self {
        Self { read_idle, context }
    }
}

pub enum IdleType {
    Timeout(Ipv4Addr, Route),
    Sleep(Duration),
    None,
}

impl Idle {
    /// 获取空闲路由
    pub fn next_idle(&self) -> IdleType {
        match self.context.route_manager().next_idle(self.read_idle) {
            RouteIdle::Timeout(ip, route) => IdleType::Timeout(ip, route),
            RouteIdle::Sleep(duration) => IdleType::Sleep(duration),
            RouteIdle::None => IdleType::None,
        }
    }
}
