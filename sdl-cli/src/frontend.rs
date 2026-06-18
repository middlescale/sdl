use crate::command::client::CommandClient;
use crate::command::service_state::{read_service_state, write_service_state, LocalServiceState};
use crate::config::switch_saved_config_to_user;
use crate::console_out;
use std::thread;
use std::time::{Duration, Instant};

fn print_usage() {
    println!(
        "sdl <resume|list|status|gateway|route|traffic|suspend|rename|auth|switch|channel-change|version> [options]"
    );
    println!("  sdl resume [--json]                   # 恢复本地收发服务");
    println!("  sdl list [--json]");
    println!("  sdl status [--json]");
    println!("  sdl gateway [--json] [--set <gateway-name|auto>]");
    println!("  sdl route [--json]");
    println!("  sdl traffic [--json]");
    println!("  sdl suspend [--json]                  # 挂起本地收发服务");
    println!("  sdl rename [--json] <name>            # 修改当前节点显示名");
    println!("  sdl auth [--json] --userId/-u <user-id> [--group/-g default.ms.net] <ticket>");
    println!("  sdl switch [--json] --userId/-u <user-id>");
    println!("  sdl channel-change [--type <relay|p2p|auto>] [--json]");
    println!("  sdl channel_change [--type <relay|p2p|auto>] [--json]");
    println!("  sdl version [--json]");
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
        "status" | "info" => handle_status(&args[2..]),
        "gateway" => handle_gateway(&args[2..]),
        "route" => handle_route(&args[2..]),
        "traffic" => handle_traffic(&args[2..]),
        "suspend" => handle_suspend(&args[2..]),
        "rename" => handle_rename(&args[2..]),
        "auth" => handle_auth(&args[2..]),
        "switch" => handle_switch(&args[2..]),
        "channel-change" | "channel_change" => handle_channel_change(&args[2..]),
        "version" => handle_version(&args[2..]),
        _ => {
            print_usage();
            2
        }
    }
}

fn has_json_flag(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--json")
}

fn handle_version(args: &[String]) -> i32 {
    let json = has_json_flag(args);
    let filtered: Vec<String> = args
        .iter()
        .filter(|arg| arg.as_str() != "--json")
        .cloned()
        .collect();
    if !filtered.is_empty() {
        let message = "sdl version does not accept additional arguments";
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
    let version = crate::build_version_string();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "version": version
            }))
            .unwrap()
        );
    } else {
        println!("{}", version);
    }
    0
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

fn parse_switch_args(args: &[String]) -> Result<String, &'static str> {
    let mut user_id: Option<String> = None;
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-u" | "--userId" => {
                let value = iter.next().ok_or("missing user id")?;
                user_id = Some(value.clone());
            }
            value if value.starts_with('-') => return Err("unknown switch option"),
            _ => return Err("unexpected extra argument"),
        }
    }

    let user_id = user_id.ok_or("missing user id")?;
    if user_id.trim().is_empty() {
        return Err("user id cannot be empty");
    }
    Ok(user_id)
}

fn switch_saved_config_without_service(user_id: &str) -> Result<String, String> {
    switch_saved_config_to_user(user_id)
        .map_err(|e| format!("switch saved config failed: {}", e))?;
    let mut state = LocalServiceState::default();
    state.auth_pending = true;
    state.auth_message = Some(format!("reauth_required: switched to user_id={user_id}"));
    write_service_state(&state).map_err(|e| format!("write service state failed: {}", e))?;
    Ok(format!(
        "switched to user_id={}; start sdl-service and run `sdl auth --userId {} <ticket>` to authenticate",
        user_id, user_id
    ))
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

fn handle_status(args: &[String]) -> i32 {
    if has_json_flag(args) {
        match CommandClient::new().and_then(|mut client| client.status()) {
            Ok(status) => {
                println!("{}", serde_json::to_string_pretty(&status).unwrap());
                0
            }
            Err(e) => {
                eprintln!("status error: {}", e);
                1
            }
        }
    } else {
        match CommandClient::new().and_then(|mut client| client.status()) {
            Ok(status) => {
                console_out::console_info(status);
                0
            }
            Err(e) => {
                eprintln!("status error: {}", e);
                1
            }
        }
    }
}

fn handle_gateway(args: &[String]) -> i32 {
    let json = has_json_flag(args);
    let mut set_value: Option<String> = None;
    let mut filtered = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => {}
            "--set" => {
                let Some(value) = iter.next() else {
                    let message = "sdl gateway --set requires <gateway-name|auto>";
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(
                                &serde_json::json!({"ok": false, "error": message})
                            )
                            .unwrap()
                        );
                    } else {
                        eprintln!("{}", message);
                    }
                    return 1;
                };
                set_value = Some(value.clone());
            }
            _ => filtered.push(arg.clone()),
        }
    }
    if !filtered.is_empty() {
        let message = "sdl gateway only accepts [--json] [--set <gateway-name|auto>]";
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"ok": false, "error": message}))
                    .unwrap()
            );
        } else {
            eprintln!("{}", message);
        }
        return 1;
    }
    if let Some(value) = set_value {
        match CommandClient::new().and_then(|mut client| client.gateway_set(&value)) {
            Ok(result) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({"ok": true, "result": result})
                        )
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
                        serde_json::to_string_pretty(
                            &serde_json::json!({"ok": false, "error": e.to_string()})
                        )
                        .unwrap()
                    );
                } else {
                    eprintln!("gateway error: {}", e);
                }
                1
            }
        }
    } else if json {
        match CommandClient::new().and_then(|mut client| client.gateway()) {
            Ok(gateways) => {
                println!("{}", serde_json::to_string_pretty(&gateways).unwrap());
                0
            }
            Err(e) => {
                eprintln!("gateway error: {}", e);
                1
            }
        }
    } else {
        match CommandClient::new().and_then(|mut client| client.gateway()) {
            Ok(gateways) => {
                console_out::console_gateway(gateways);
                0
            }
            Err(e) => {
                eprintln!("gateway error: {}", e);
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

fn handle_traffic(args: &[String]) -> i32 {
    if has_json_flag(args) {
        match CommandClient::new().and_then(|mut client| client.traffic()) {
            Ok(traffic) => {
                println!("{}", serde_json::to_string_pretty(&traffic).unwrap());
                0
            }
            Err(e) => {
                eprintln!("traffic error: {}", e);
                1
            }
        }
    } else {
        match CommandClient::new().and_then(|mut client| client.traffic()) {
            Ok(traffic) => {
                console_out::console_traffic(traffic);
                0
            }
            Err(e) => {
                eprintln!("traffic error: {}", e);
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

fn handle_rename(args: &[String]) -> i32 {
    let json = has_json_flag(args);
    let filtered: Vec<String> = args
        .iter()
        .filter(|arg| arg.as_str() != "--json")
        .cloned()
        .collect();
    if filtered.is_empty() {
        let message = "usage: sdl rename [--json] <name>";
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
        return 2;
    }
    let new_name = filtered.join(" ");
    match CommandClient::new().and_then(|mut client| client.rename(&new_name)) {
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
                eprintln!("rename error: {}", e);
            }
            1
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
        Ok(result) => match wait_for_auth_result(&user_id, &group) {
            Ok(message) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "result": message
                        }))
                        .unwrap()
                    );
                } else {
                    println!("{}", message);
                }
                0
            }
            Err(message) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "error": message,
                            "submitted": result
                        }))
                        .unwrap()
                    );
                } else {
                    eprintln!("{}", message);
                }
                1
            }
        },
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

fn handle_switch(args: &[String]) -> i32 {
    let json = has_json_flag(args);
    let filtered: Vec<String> = args
        .iter()
        .filter(|arg| arg.as_str() != "--json")
        .cloned()
        .collect();
    let user_id = match parse_switch_args(&filtered) {
        Ok(v) => v,
        Err(msg) => {
            let usage = "usage: sdl switch [--json] --userId/-u <user-id>";
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": false,
                        "error": format!("{msg}; {usage}")
                    }))
                    .unwrap()
                );
            } else {
                eprintln!("{msg}");
                eprintln!("{usage}");
            }
            return 2;
        }
    };

    match CommandClient::new().and_then(|mut client| client.switch_user(&user_id)) {
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
        Err(ipc_error) => match switch_saved_config_without_service(&user_id) {
            Ok(result) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "result": result,
                            "service_running": false
                        }))
                        .unwrap()
                    );
                } else {
                    println!("{}", result);
                }
                0
            }
            Err(config_error) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "error": config_error,
                            "ipc_error": ipc_error.to_string()
                        }))
                        .unwrap()
                    );
                } else {
                    eprintln!("switch error: {}; ipc error: {}", config_error, ipc_error);
                }
                1
            }
        },
    }
}

fn wait_for_auth_result(user_id: &str, group: &str) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut saw_pending = false;
    while Instant::now() < deadline {
        let state = read_service_state().map_err(|e| format!("auth state read failed: {}", e))?;
        if let Some(last_error) = state.last_error {
            return Err(format!("auth failed: {}", last_error));
        }
        if state.auth_pending {
            saw_pending = true;
        }
        if state.authenticated_user_id.as_deref() == Some(user_id)
            && state.authenticated_group.as_deref() == Some(group)
        {
            return Ok(format!(
                "device authenticated: user_id={} group={}",
                user_id, group
            ));
        }
        thread::sleep(Duration::from_millis(300));
    }
    if saw_pending {
        Err("auth request submitted, but authentication is still pending".to_string())
    } else {
        Err("auth request submitted, but no final auth result was observed within 30s".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{handle_version, parse_auth_args, parse_switch_args};

    #[test]
    fn parse_auth_args_uses_default_group() {
        let args = vec![
            "--userId".to_string(),
            "u-1".to_string(),
            "ticket-1".to_string(),
        ];
        let parsed = parse_auth_args(&args).unwrap();
        assert_eq!(
            parsed,
            (
                "u-1".to_string(),
                "default.ms.net".to_string(),
                "ticket-1".to_string()
            )
        );
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
        assert_eq!(
            parsed,
            (
                "u-1".to_string(),
                "sales.ms.net".to_string(),
                "ticket-1".to_string()
            )
        );
    }

    #[test]
    fn version_command_accepts_no_args() {
        assert_eq!(handle_version(&[]), 0);
    }

    #[test]
    fn version_command_rejects_extra_args() {
        assert_eq!(handle_version(&["extra".to_string()]), 1);
    }

    #[test]
    fn parse_switch_args_accepts_user_id() {
        let args = vec!["--userId".to_string(), "sdl-user-1".to_string()];
        assert_eq!(parse_switch_args(&args).unwrap(), "sdl-user-1");
    }

    #[test]
    fn parse_switch_args_rejects_missing_user_id() {
        assert_eq!(parse_switch_args(&[]).unwrap_err(), "missing user id");
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
