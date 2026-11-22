use super::*;
use std::process::Command;

fn split_route_count() -> anyhow::Result<usize> {
    let output = if cfg!(target_os = "macos") {
        Command::new("netstat")
            .args(["-rn", "-f", "inet"])
            .output()?
    } else {
        Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                "$ErrorActionPreference='Stop'; Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1' | ForEach-Object DestinationPrefix"])
            .output()?
    };
    anyhow::ensure!(output.status.success(), "route inspection: {:?}", output);
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| {
            matches!(
                line.split_whitespace().next(),
                Some("0/1" | "0.0.0.0/1" | "128.0/1" | "128.0.0.0/1")
            )
        })
        .count())
}

struct RouteCleanup<'a>(&'a str);

impl Drop for RouteCleanup<'_> {
    fn drop(&mut self) {
        if let Err(err) = exit_node::teardown_client_routing(self.0, &[]) {
            eprintln!("native fixture route cleanup failed: {err:#}");
        }
    }
}

#[test]
#[ignore = "changes system routing; run only in a disposable native VM"]
fn native_exit_node_route_lifecycle() -> anyhow::Result<()> {
    anyhow::ensure!(
        std::env::var("SDL_TEST_DISPOSABLE_VM").as_deref() == Ok("1"),
        "this test requires an explicitly designated disposable VM"
    );
    anyhow::ensure!(
        !crate::config::saved_config_path()?.exists(),
        "run the test executable from a fresh directory"
    );
    anyhow::ensure!(
        split_route_count()? == 0,
        "unexpected existing split routes"
    );
    let mut builder = tun_rs::DeviceBuilder::new().ipv4("198.18.0.2", 30, None);
    if cfg!(target_os = "windows") {
        builder = builder.name("sdl-ci-tun");
    }
    let device = builder.build_sync()?;
    let tun = device.name()?;
    let mut saved = FileConfig {
        server_address: "https://127.0.0.1:4242/control".into(),
        ..FileConfig::default()
    };
    saved.exit_node.tun_name = Some(tun.clone());
    let manager = Arc::new(ServiceManager::new(
        saved.clone().into_runtime_config()?,
        saved,
    ));

    // Seed only the state normally produced by a successful selection. The TUN,
    // platform route operations, clear implementation and callback are real.
    for underlay in [false, true] {
        let _cleanup = RouteCleanup(&tun);
        exit_node::setup_client_routing(&tun, &[])?;
        assert!(exit_node::client_routing_active(&tun)?);
        assert_eq!(split_route_count()?, 2);
        {
            let mut config = manager.saved_config.lock().unwrap();
            config.exit_node.client_active = true;
            config.exit_node.selected_identity = Some("ab".repeat(32));
            // Windows teardown needs the test adapter alias, even though this
            // fixture does not install an exit-node DNS server.
            if cfg!(target_os = "windows") {
                config.exit_node.original_dns = vec![OriginalDnsServiceFileConfig {
                    service: tun.clone(),
                    ..Default::default()
                }];
            }
        }
        if underlay {
            ServiceCallback::new(Arc::downgrade(&manager)).underlay_changed();
        } else {
            manager.clear_exit_node(Some(&tun))?;
        }
        let status = manager.exit_node_status();
        assert!(!status.client_requested);
        assert!(!status.client_active);
        assert_eq!(status.client_route_status, "disabled");
        assert_eq!(split_route_count()?, 0);
    }
    Ok(())
}
