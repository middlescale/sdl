use crate::command::client::CommandClient;
use crate::console_out;

fn print_usage() {
    println!("sdl <resume|list|info|route|suspend|auth|channel-change> [options]");
    println!("  sdl resume [--json]                   # 恢复本地收发服务");
    println!("  sdl list [--json]");
    println!("  sdl info [--json]");
    println!("  sdl route [--json]");
    println!("  sdl suspend [--json]                  # 挂起本地收发服务");
    println!("  sdl auth [--json] --userId/-u <user-id> [--group/-g default.ms.net] <ticket>");
    println!("  sdl channel-change [--type <relay|p2p|auto>] [--json]");
    println!("  sdl channel_change [--type <relay|p2p|auto>] [--json]");
}

pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        print_usage();
        return 0;
    }
    let command = args[1].as_str();
    match command {
        "resume" => handle_resume(&args[2..]),
        "list" => handle_list(&args[2..]),
        "info" => handle_info(&args[2..]),
        "route" => handle_route(&args[2..]),
        "suspend" => handle_suspend(&args[2..]),
        "auth" => handle_auth(&args[2..]),
        "channel-change" | "channel_change" => handle_channel_change(&args[2..]),
        _ => {
            print_usage();
            2
        }
    }
}

fn has_json_flag(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--json")
}

fn handle_resume(args: &[String]) -> i32 {
    let json = has_json_flag(args);
    let filtered: Vec<String> = args
        .iter()
        .filter(|arg| arg.as_str() != "--json")
        .cloned()
        .collect();
    if !filtered.is_empty() {
        let message =
            "sdl resume does not accept service arguments; start the daemon with `sdl-service ...`";
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": false,
                    "error": message
                }))
                .unwrap()
            );
        } else {
            eprintln!("{}", message);
        }
        return 1;
    }
    match CommandClient::new().and_then(|mut client| client.resume()) {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "result": result
                    }))
                    .unwrap()
                );
            } else {
                println!("{}", result);
            }
            0
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": false,
                        "error": e.to_string()
                    }))
                    .unwrap()
                );
            } else {
                eprintln!(
                    "resume error: {}. start the daemon first with `sdl-service ...`",
                    e
                );
            }
            1
        }
    }
}

fn parse_auth_args(args: &[String]) -> Result<(String, String, String), &'static str> {
    let mut user_id: Option<String> = None;
    let mut group = "default.ms.net".to_string();
    let mut ticket: Option<String> = None;
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-u" | "--userId" => {
                let value = iter.next().ok_or("missing user id")?;
                user_id = Some(value.clone());
            }
            "-g" | "--group" => {
                let value = iter.next().ok_or("missing group")?;
                group = value.clone();
            }
            value if value.starts_with('-') => return Err("unknown auth option"),
            value => {
                if ticket.is_some() {
                    return Err("unexpected extra argument");
                }
                ticket = Some(value.to_string());
            }
        }
    }

    match (user_id, ticket) {
        (Some(user_id), Some(ticket)) => Ok((user_id, group, ticket)),
        _ => Err("invalid arguments"),
    }
}

fn handle_list(args: &[String]) -> i32 {
    if has_json_flag(args) {
        match CommandClient::new().and_then(|mut client| client.list()) {
            Ok(list) => {
                println!("{}", serde_json::to_string_pretty(&list).unwrap());
                0
            }
            Err(e) => {
                eprintln!("list error: {}", e);
                1
            }
        }
    } else {
        match CommandClient::new().and_then(|mut client| client.list()) {
            Ok(list) => {
                console_out::console_device_list(list);
                0
            }
            Err(e) => {
                eprintln!("list error: {}", e);
                1
            }
        }
    }
}

fn handle_info(args: &[String]) -> i32 {
    if has_json_flag(args) {
        match CommandClient::new().and_then(|mut client| client.info()) {
            Ok(info) => {
                println!("{}", serde_json::to_string_pretty(&info).unwrap());
                0
            }
            Err(e) => {
                eprintln!("info error: {}", e);
                1
            }
        }
    } else {
        match CommandClient::new().and_then(|mut client| client.info()) {
            Ok(info) => {
                console_out::console_info(info);
                0
            }
            Err(e) => {
                eprintln!("info error: {}", e);
                1
            }
        }
    }
}

fn handle_route(args: &[String]) -> i32 {
    if has_json_flag(args) {
        match CommandClient::new().and_then(|mut client| client.route()) {
            Ok(route) => {
                println!("{}", serde_json::to_string_pretty(&route).unwrap());
                0
            }
            Err(e) => {
                eprintln!("route error: {}", e);
                1
            }
        }
    } else {
        match CommandClient::new().and_then(|mut client| client.route()) {
            Ok(route) => {
                console_out::console_route_table(route);
                0
            }
            Err(e) => {
                eprintln!("route error: {}", e);
                1
            }
        }
    }
}

fn handle_suspend(args: &[String]) -> i32 {
    if has_json_flag(args) {
        match CommandClient::new().and_then(|mut client| client.suspend()) {
            Ok(result) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({ "result": result })).unwrap()
                );
                0
            }
            Err(e) => {
                eprintln!("suspend error: {}", e);
                1
            }
        }
    } else {
        match CommandClient::new().and_then(|mut client| client.suspend()) {
            Ok(result) => {
                println!("{}", result);
                0
            }
            Err(e) => {
                eprintln!("suspend error: {}", e);
                1
            }
        }
    }
}

fn handle_auth(args: &[String]) -> i32 {
    let json = has_json_flag(args);
    let filtered: Vec<String> = args
        .iter()
        .filter(|arg| arg.as_str() != "--json")
        .cloned()
        .collect();
    let (user_id, group, ticket) = match parse_auth_args(&filtered) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{msg}");
            eprintln!("usage: sdl auth [--json] --userId/-u <user-id> [--group/-g default.ms.net] <ticket>");
            return 2;
        }
    };
    match CommandClient::new().and_then(|mut client| client.auth(&user_id, &group, &ticket)) {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "result": result
                    }))
                    .unwrap()
                );
            } else {
                println!("{}", result);
            }
            0
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": false,
                        "error": e.to_string()
                    }))
                    .unwrap()
                );
            } else {
                eprintln!("auth error: {}", e);
            }
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_auth_args;

    #[test]
    fn parse_auth_args_uses_default_group() {
        let args = vec![
            "--userId".to_string(),
            "u-1".to_string(),
            "ticket-1".to_string(),
        ];
        let parsed = parse_auth_args(&args).unwrap();
        assert_eq!(parsed, ("u-1".to_string(), "default.ms.net".to_string(), "ticket-1".to_string()));
    }

    #[test]
    fn parse_auth_args_accepts_explicit_group() {
        let args = vec![
            "-u".to_string(),
            "u-1".to_string(),
            "-g".to_string(),
            "sales.ms.net".to_string(),
            "ticket-1".to_string(),
        ];
        let parsed = parse_auth_args(&args).unwrap();
        assert_eq!(parsed, ("u-1".to_string(), "sales.ms.net".to_string(), "ticket-1".to_string()));
    }
}

fn handle_channel_change(args: &[String]) -> i32 {
    let json = has_json_flag(args);
    let mut channel_type = "auto".to_string();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => {}
            "--type" => {
                if let Some(value) = iter.next() {
                    channel_type = value.clone();
                }
            }
            value if !value.starts_with('-') => {
                channel_type = value.to_string();
            }
            _ => {}
        }
    }

    if json {
        match CommandClient::new().and_then(|mut client| client.channel_change(&channel_type)) {
            Ok(result) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "type": channel_type,
                        "result": result
                    }))
                    .unwrap()
                );
                0
            }
            Err(e) => {
                eprintln!("channel-change error: {}", e);
                1
            }
        }
    } else {
        match CommandClient::new().and_then(|mut client| client.channel_change(&channel_type)) {
            Ok(result) => {
                println!("{}", result);
                0
            }
            Err(e) => {
                eprintln!("channel-change error: {}", e);
                1
            }
        }
    }
}
