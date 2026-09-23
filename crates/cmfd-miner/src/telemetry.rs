use std::collections::BTreeMap;
use std::process::Command;

const NVIDIA_SMI_QUERY: &str = "index,uuid,power.draw,power.limit,temperature.gpu,fan.speed,utilization.gpu,clocks.current.graphics,clocks.current.memory,memory.used,memory.total";

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct GpuTelemetry {
    pub(crate) uuid: String,
    pub(crate) power_watts: Option<f64>,
    pub(crate) power_limit_watts: Option<f64>,
    pub(crate) temperature_celsius: Option<f64>,
    pub(crate) fan_percent: Option<f64>,
    pub(crate) utilization_percent: Option<f64>,
    pub(crate) graphics_clock_mhz: Option<f64>,
    pub(crate) memory_clock_mhz: Option<f64>,
    pub(crate) memory_used_mib: Option<f64>,
    pub(crate) memory_total_mib: Option<f64>,
}

pub(crate) fn query_nvidia_smi() -> Result<BTreeMap<i32, GpuTelemetry>, String> {
    let output = Command::new(nvidia_smi_command())
        .args([
            format!("--query-gpu={NVIDIA_SMI_QUERY}"),
            "--format=csv,noheader,nounits".to_owned(),
        ])
        .output()
        .map_err(|error| format!("could not start nvidia-smi: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        return Err(if detail.is_empty() {
            format!("nvidia-smi exited with {}", output.status)
        } else {
            format!("nvidia-smi exited with {}: {detail}", output.status)
        });
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "nvidia-smi returned output that is not UTF-8".to_owned())?;
    parse_nvidia_smi_csv(&stdout)
}

fn nvidia_smi_command() -> &'static str {
    if cfg!(windows) {
        "nvidia-smi.exe"
    } else {
        "nvidia-smi"
    }
}

fn parse_nvidia_smi_csv(output: &str) -> Result<BTreeMap<i32, GpuTelemetry>, String> {
    let mut result = BTreeMap::new();
    for (line_index, line) in output.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let columns: Vec<_> = line.split(',').map(str::trim).collect();
        if columns.len() != 11 {
            return Err(format!(
                "nvidia-smi row {} has {} columns instead of 11",
                line_index + 1,
                columns.len()
            ));
        }
        let index = columns[0]
            .parse::<i32>()
            .map_err(|_| format!("nvidia-smi row {} has an invalid GPU index", line_index + 1))?;
        if index < 0 || !valid_gpu_uuid(columns[1]) {
            return Err(format!(
                "nvidia-smi row {} has an invalid GPU identity",
                line_index + 1
            ));
        }
        let telemetry = GpuTelemetry {
            uuid: columns[1].to_owned(),
            power_watts: parse_optional_number(columns[2], line_index)?,
            power_limit_watts: parse_optional_number(columns[3], line_index)?,
            temperature_celsius: parse_optional_number(columns[4], line_index)?,
            fan_percent: parse_optional_number(columns[5], line_index)?,
            utilization_percent: parse_optional_number(columns[6], line_index)?,
            graphics_clock_mhz: parse_optional_number(columns[7], line_index)?,
            memory_clock_mhz: parse_optional_number(columns[8], line_index)?,
            memory_used_mib: parse_optional_number(columns[9], line_index)?,
            memory_total_mib: parse_optional_number(columns[10], line_index)?,
        };
        if result.insert(index, telemetry).is_some() {
            return Err(format!("nvidia-smi returned duplicate GPU index {index}"));
        }
    }
    if result.is_empty() {
        return Err("nvidia-smi returned no GPU telemetry rows".to_owned());
    }
    let mut uuids = std::collections::BTreeSet::new();
    if result
        .values()
        .any(|gpu| !uuids.insert(gpu.uuid.to_ascii_lowercase()))
    {
        return Err("nvidia-smi returned duplicate GPU UUIDs".to_owned());
    }
    Ok(result)
}

pub(crate) fn valid_gpu_uuid(value: &str) -> bool {
    value.len() == 40
        && value.starts_with("GPU-")
        && value[4..].bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn parse_optional_number(value: &str, line_index: usize) -> Result<Option<f64>, String> {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.is_empty()
        || normalized == "-"
        || normalized.contains("N/A")
        || normalized.contains("NOT SUPPORTED")
    {
        return Ok(None);
    }
    let parsed = value.trim().parse::<f64>().map_err(|_| {
        format!(
            "nvidia-smi row {} contains an invalid number: {value}",
            line_index + 1
        )
    })?;
    if !parsed.is_finite() || parsed < 0.0 {
        return Err(format!(
            "nvidia-smi row {} contains an out-of-range number: {value}",
            line_index + 1
        ));
    }
    Ok(Some(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multi_gpu_telemetry_and_unsupported_sensors() {
        let parsed = parse_nvidia_smi_csv(
            "0, GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, 245.50, 300.00, 64, 52, 99, 2745, 10501, 2048, 24564\n\
             2, GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb, 181.25, 250.00, 71, [N/A], 97, 1530, 877, 8192, 16384\n",
        )
        .unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[&0].power_watts, Some(245.5));
        assert_eq!(parsed[&0].fan_percent, Some(52.0));
        assert_eq!(parsed[&0].memory_total_mib, Some(24_564.0));
        assert_eq!(parsed[&2].power_watts, Some(181.25));
        assert_eq!(parsed[&2].fan_percent, None);
        assert_eq!(parsed[&2].memory_clock_mhz, Some(877.0));
    }

    #[test]
    fn rejects_malformed_duplicate_and_nonfinite_rows() {
        assert!(parse_nvidia_smi_csv("0, 1, 2\n").is_err());
        assert!(
            parse_nvidia_smi_csv("0, GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, 1, 2, 3, 4, 5, 6, 7, 8, 9\n0, GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb, 1, 2, 3, 4, 5, 6, 7, 8, 9\n")
                .is_err()
        );
        assert!(
            parse_nvidia_smi_csv(
                "0, GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, NaN, 2, 3, 4, 5, 6, 7, 8, 9\n"
            )
            .is_err()
        );
        assert!(parse_nvidia_smi_csv("\n\r\n").is_err());
        assert!(
            parse_nvidia_smi_csv(
                "0, MIG-GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, 1, 2, 3, 4, 5, 6, 7, 8, 9\n"
            )
            .is_err()
        );
    }
}
