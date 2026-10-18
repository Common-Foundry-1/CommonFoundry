//! Whether the computer runs on battery, so the background work check can
//! wait for mains power. Any doubt reads as mains power: the check then runs
//! as on a desktop.

/// Whether the computer is running on its battery now.
pub(super) fn on_battery() -> bool {
    platform::on_battery()
}

#[cfg(windows)]
mod platform {
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};

    /// `ACLineStatus` when the computer is not on mains power.
    const AC_OFFLINE: u8 = 0;

    pub(super) fn on_battery() -> bool {
        // SAFETY: all-zero bytes are a valid SYSTEM_POWER_STATUS, and the call
        // only writes the structure it is given.
        let mut status: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
        // SAFETY: `status` is a valid, writable SYSTEM_POWER_STATUS.
        let read = unsafe { GetSystemPowerStatus(&mut status) } != 0;
        read && status.ACLineStatus == AC_OFFLINE
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::path::Path;

    pub(super) fn on_battery() -> bool {
        discharging_battery(Path::new("/sys/class/power_supply"))
    }

    /// Whether the power supplies under `root` (the kernel's power-supply
    /// class directory) say the computer runs on its battery: a battery of
    /// the computer is discharging, and no mains or USB supply is online
    /// (upower's rule). The batteries of a mouse, keyboard, game controller
    /// or pen (`scope` `Device`) say nothing about the computer.
    pub(super) fn discharging_battery(root: &Path) -> bool {
        let Ok(supplies) = std::fs::read_dir(root) else {
            return false;
        };
        let mut discharging = false;
        for supply in supplies.flatten() {
            let read = |name: &str| {
                std::fs::read_to_string(supply.path().join(name))
                    .map(|value| value.trim().to_owned())
                    .unwrap_or_default()
            };
            if read("scope") == "Device" {
                continue;
            }
            let kind = read("type");
            if (kind == "Mains" || kind.starts_with("USB")) && read("online") == "1" {
                return false;
            }
            if kind == "Battery" && read("status") == "Discharging" {
                discharging = true;
            }
        }
        discharging
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn only_a_discharging_battery_counts() {
            let root =
                std::env::temp_dir().join(format!("cmfd-wallet-power-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let supply = |name: &str, kind: &str, status: Option<&str>| {
                let path = root.join(name);
                std::fs::create_dir_all(&path).unwrap();
                std::fs::write(path.join("type"), format!("{kind}\n")).unwrap();
                if let Some(status) = status {
                    std::fs::write(path.join("status"), format!("{status}\n")).unwrap();
                }
            };
            assert!(!discharging_battery(&root), "no power-supply directory");
            supply("AC", "Mains", None);
            supply("BAT0", "Battery", Some("Charging"));
            assert!(!discharging_battery(&root));
            supply("BAT0", "Battery", Some("Discharging"));
            assert!(discharging_battery(&root));
            std::fs::remove_dir_all(&root).unwrap();
        }

        #[test]
        fn a_peripheral_battery_or_online_mains_is_not_running_on_battery() {
            let root = std::env::temp_dir().join(format!(
                "cmfd-wallet-power-peripheral-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            let write = |supply: &str, field: &str, value: &str| {
                let path = root.join(supply);
                std::fs::create_dir_all(&path).unwrap();
                std::fs::write(path.join(field), format!("{value}\n")).unwrap();
            };
            // A desktop with a Bluetooth mouse: the mouse battery discharges.
            write("hidpp_battery_0", "type", "Battery");
            write("hidpp_battery_0", "scope", "Device");
            write("hidpp_battery_0", "status", "Discharging");
            assert!(!discharging_battery(&root));
            // A laptop's own battery discharging while mains is online (a
            // full battery some firmware reports so) is not on battery.
            write("BAT0", "type", "Battery");
            write("BAT0", "status", "Discharging");
            write("AC", "type", "Mains");
            write("AC", "online", "1");
            assert!(!discharging_battery(&root));
            // Unplugged: on battery.
            write("AC", "online", "0");
            assert!(discharging_battery(&root));
            // Powered over USB-C.
            write("ucsi-source-psy-USBC000:001", "type", "USB");
            write("ucsi-source-psy-USBC000:001", "online", "1");
            assert!(!discharging_battery(&root));
            std::fs::remove_dir_all(&root).unwrap();
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod platform {
    pub(super) fn on_battery() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_power_state_can_be_read() {
        // Whatever the machine reports; the call itself must not fail.
        let _ = super::on_battery();
    }
}
