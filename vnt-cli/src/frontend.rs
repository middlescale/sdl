use common::command::client::CommandClient;
use common::console_out;

fn print_usage() {
    println!("vnt <start|list|info|route|stop|auth|channel-change> [options]");
    println!("  vnt start [--json]                    # 恢复本地收发服务");
    println!("  vnt list [--json]");
    println!("  vnt info [--json]");
    println!("  vnt route [--json]");
    println!("  vnt stop [--json]                     # 停止本地收发服务");
    println!("  vnt auth [--json] <user-id> <group> <ticket>");
    println!("  vnt channel-change [--type <relay|p2p|auto>] [--json]");
    println!("  vnt channel_change [--type <relay|p2p|auto>] [--json]");
}

pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        print_usage();
        return 0;
    }
    let command = args[1].as_str();
    match command {
        "start" => handle_start(&args[0], &args[2..]),
        "list" => handle_list(&args[2..]),
        "info" => handle_info(&args[2..]),
        "route" => handle_route(&args[2..]),
        "stop" => handle_stop(&args[2..]),
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

fn handle_start(_program: &str, args: &[String]) -> i32 {
    let json = has_json_flag(args);
    let filtered: Vec<String> = args
        .iter()
        .filter(|arg| arg.as_str() != "--json")
        .cloned()
        .collect();
    if !filtered.is_empty() {
        let message = "vnt start does not accept service arguments; start the daemon with `vnt-service ...`";
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
    match CommandClient::new().and_then(|mut client| client.start()) {
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
                    "start error: {}. start the daemon first with `vnt-service ...`",
                    e
                );
            }
            1
        }
    }
}

fn parse_auth_args(args: &[String]) -> Result<(String, String, String), &'static str> {
    if args.len() == 3 {
        Ok((args[0].clone(), args[1].clone(), args[2].clone()))
    } else {
        Err("invalid arguments")
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

fn handle_stop(args: &[String]) -> i32 {
    if has_json_flag(args) {
        match CommandClient::new().and_then(|mut client| client.stop()) {
            Ok(result) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({ "result": result })).unwrap()
                );
                0
            }
            Err(e) => {
                eprintln!("stop error: {}", e);
                1
            }
        }
    } else {
        match CommandClient::new().and_then(|mut client| client.stop()) {
            Ok(result) => {
                println!("{}", result);
                0
            }
            Err(e) => {
                eprintln!("stop error: {}", e);
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
            eprintln!("usage: vnt auth [--json] <user-id> <group> <ticket>");
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
