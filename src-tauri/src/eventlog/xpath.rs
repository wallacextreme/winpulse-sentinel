use chrono::{DateTime, Utc};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

use crate::error::SentinelError;

const APPLICATION_PREDICATES: &str = "(Provider[@Name='Application Error'] and EventID=1000) or (Provider[@Name='Application Hang'] and EventID=1002) or (Provider[@Name='Windows Error Reporting'] and EventID=1001)";

const SYSTEM_PREDICATES: &str = "\
(Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41) or \
(Provider[@Name='EventLog'] and EventID=6008) or \
((Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] or Provider[@Name='BugCheck']) and EventID=1001) or \
((Provider[@Name='storahci'] or Provider[@Name='nvme'] or Provider[@Name='iaStorA'] or Provider[@Name='iaStorAC']) and EventID=129) or \
(Provider[@Name='disk'] and (EventID=7 or EventID=51 or EventID=153)) or \
((Provider[@Name='Ntfs'] or Provider[@Name='Microsoft-Windows-Ntfs']) and EventID=55) or \
(Provider[@Name='Microsoft-Windows-Resource-Exhaustion-Detector'] and EventID=2004) or \
(Provider[@Name='Microsoft-Windows-Kernel-Processor-Power'] and EventID=37) or \
(Provider[@Name='Microsoft-Windows-DNS-Client'] and EventID=1014) or \
((Provider[@Name='e1dexpress'] or Provider[@Name='e1rexpress'] or Provider[@Name='rt640x64'] or Provider[@Name='Netwtw08'] or Provider[@Name='Netwtw10'] or Provider[@Name='Netwtw12'] or Provider[@Name='Netwtw14']) and EventID=27) or \
(Provider[@Name='Display'] and EventID=4101)";

pub const APPLICATION_XPATH: &str = "*[System[(Provider[@Name='Application Error'] and EventID=1000) or (Provider[@Name='Application Hang'] and EventID=1002) or (Provider[@Name='Windows Error Reporting'] and EventID=1001)]]";

pub const SYSTEM_XPATH: &str = "*[System[\
(Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41) or \
(Provider[@Name='EventLog'] and EventID=6008) or \
((Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] or Provider[@Name='BugCheck']) and EventID=1001) or \
((Provider[@Name='storahci'] or Provider[@Name='nvme'] or Provider[@Name='iaStorA'] or Provider[@Name='iaStorAC']) and EventID=129) or \
(Provider[@Name='disk'] and (EventID=7 or EventID=51 or EventID=153)) or \
((Provider[@Name='Ntfs'] or Provider[@Name='Microsoft-Windows-Ntfs']) and EventID=55) or \
(Provider[@Name='Microsoft-Windows-Resource-Exhaustion-Detector'] and EventID=2004) or \
(Provider[@Name='Microsoft-Windows-Kernel-Processor-Power'] and EventID=37) or \
(Provider[@Name='Microsoft-Windows-DNS-Client'] and EventID=1014) or \
((Provider[@Name='e1dexpress'] or Provider[@Name='e1rexpress'] or Provider[@Name='rt640x64'] or Provider[@Name='Netwtw08'] or Provider[@Name='Netwtw10'] or Provider[@Name='Netwtw12'] or Provider[@Name='Netwtw14']) and EventID=27) or \
(Provider[@Name='Display'] and EventID=4101)\
]]";

pub fn build_historical_xpath(channel: &str, days: u32) -> String {
    let clamped_days = days.clamp(1, 90) as u64;
    let window_ms = clamped_days * 24 * 60 * 60 * 1000;
    let predicates = if channel.eq_ignore_ascii_case("Application") {
        APPLICATION_PREDICATES
    } else {
        SYSTEM_PREDICATES
    };
    format!("*[System[TimeCreated[timediff(@SystemTime) <= {window_ms}] and ({predicates})]]")
}

#[derive(Debug, Clone)]
pub struct ParsedWindowsEvent {
    pub channel: String,
    pub provider_name: String,
    pub event_id: u32,
    pub record_id: Option<i64>,
    pub level: u8,
    pub timestamp_utc: String,
    pub timestamp_ms: i64,
    pub raw_xml: String,
}

#[derive(Debug, Clone, Default)]
pub struct EventXmlDetails {
    pub app_name: Option<String>,
    pub module_name: Option<String>,
    pub exception_code: Option<String>,
    pub searchable_text: Option<String>,
}

fn looks_like_hex_exception(token: &str) -> bool {
    let lower = token.trim().to_ascii_lowercase();
    let hex = lower.strip_prefix("0x").unwrap_or(&lower);
    hex.len() == 8 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

fn looks_like_wer_problem_name(token: &str) -> bool {
    matches!(
        token.trim(),
        "MoBEX"
            | "APPCRASH"
            | "BEX"
            | "BEX64"
            | "AppHangB1"
            | "MoAppHang"
            | "LiveKernelEvent"
            | "BlueScreen"
    )
}

/// Extracts executable name, faulting module (.dll/.sys), exception code (e.g. 0xc0000409 / MoBEX),
/// and a concise searchable summary from `<EventData><Data>...</Data></EventData>`.
pub fn extract_event_data_summary(raw_xml: &str) -> EventXmlDetails {
    let mut reader = Reader::from_str(raw_xml);
    reader.config_mut().trim_text(true);

    let mut in_event_data = false;
    let mut in_data_tag = false;
    let mut current_data_name: Option<String> = None;
    let mut values: Vec<(Option<String>, String)> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let tag = e.local_name().as_ref().to_string();
                if tag == "EventData" || tag == "UserData" {
                    in_event_data = true;
                } else if in_event_data && tag == "Data" {
                    in_data_tag = true;
                    current_data_name = None;
                    for attr in e.attributes().flatten() {
                        if attr.key.local_name().as_ref() == "Name" {
                            if let Ok(val) = attr.normalized_value(XmlVersion::Implicit1_0) {
                                current_data_name = Some(val.into_owned());
                            }
                        }
                    }
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_event_data && in_data_tag && values.len() < 24 {
                    let text = e.as_ref().trim();
                    if !text.is_empty() && text != "0" && text != "NULL" {
                        values.push((current_data_name.clone(), text.to_string()));
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let tag = e.local_name().as_ref().to_string();
                if tag == "EventData" || tag == "UserData" {
                    in_event_data = false;
                } else if tag == "Data" {
                    in_data_tag = false;
                    current_data_name = None;
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }

    if values.is_empty() {
        return EventXmlDetails::default();
    }

    let mut app_name: Option<String> = None;
    let mut module_name: Option<String> = None;
    let mut exception_code: Option<String> = None;
    let mut kept_tokens: Vec<String> = Vec::new();

    for (name, val) in &values {
        let lower = val.to_ascii_lowercase();
        let key_lower = name
            .as_deref()
            .map(|n| n.to_ascii_lowercase())
            .unwrap_or_default();

        if app_name.is_none()
            && (key_lower == "appname"
                || key_lower == "application"
                || lower.ends_with(".exe"))
        {
            let short = val.rsplit(['\\', '/']).next().unwrap_or(val);
            app_name = Some(short.to_string());
        } else if module_name.is_none()
            && (key_lower == "modulename"
                || lower.ends_with(".dll")
                || lower.ends_with(".sys"))
        {
            let short = val.rsplit(['\\', '/']).next().unwrap_or(val);
            module_name = Some(short.to_string());
        } else if exception_code.is_none()
            && (key_lower == "exceptioncode"
                || looks_like_hex_exception(val)
                || looks_like_wer_problem_name(val))
        {
            exception_code = Some(val.clone());
        }

        if kept_tokens.len() < 12 && val.len() <= 140 && !kept_tokens.iter().any(|t| t == val) {
            kept_tokens.push(val.clone());
        }
    }

    let mut searchable = kept_tokens.join(" · ");
    if searchable.len() > 360 {
        searchable = searchable.chars().take(360).collect();
    }

    EventXmlDetails {
        app_name,
        module_name,
        exception_code,
        searchable_text: if searchable.is_empty() {
            None
        } else {
            Some(searchable)
        },
    }
}

fn normalize_channel(raw_channel: Option<String>, fallback: &str) -> String {
    match raw_channel.as_deref().map(str::trim) {
        Some(c) if c.eq_ignore_ascii_case("System") => "System".to_string(),
        Some(c) if c.eq_ignore_ascii_case("Application") => "Application".to_string(),
        _ => {
            if fallback.eq_ignore_ascii_case("Application") {
                "Application".to_string()
            } else {
                "System".to_string()
            }
        }
    }
}

pub fn parse_event_xml(
    fallback_channel: &str,
    raw_xml: &str,
) -> Result<ParsedWindowsEvent, SentinelError> {
    let mut reader = Reader::from_str(raw_xml);
    reader.config_mut().trim_text(true);

    let mut in_system = false;
    let mut current_tag = String::new();
    let mut provider_name = String::new();
    let mut event_id: Option<u32> = None;
    let mut record_id: Option<i64> = None;
    let mut level: u8 = 2;
    let mut channel: Option<String> = None;
    let mut system_time: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let tag = e.local_name().as_ref().to_string();
                if tag == "System" {
                    in_system = true;
                } else if in_system {
                    if tag == "Provider" {
                        for attr in e.attributes().flatten() {
                            if attr.key.local_name().as_ref() == "Name" {
                                if let Ok(val) = attr.normalized_value(XmlVersion::Implicit1_0) {
                                    provider_name = val.into_owned();
                                }
                            }
                        }
                    } else if tag == "TimeCreated" {
                        for attr in e.attributes().flatten() {
                            if attr.key.local_name().as_ref() == "SystemTime" {
                                if let Ok(val) = attr.normalized_value(XmlVersion::Implicit1_0) {
                                    system_time = Some(val.into_owned());
                                }
                            }
                        }
                    }
                    current_tag = tag;
                }
            }
            Ok(Event::Empty(ref e)) => {
                if in_system {
                    let tag = e.local_name().as_ref().to_string();
                    if tag == "Provider" {
                        for attr in e.attributes().flatten() {
                            if attr.key.local_name().as_ref() == "Name" {
                                if let Ok(val) = attr.normalized_value(XmlVersion::Implicit1_0) {
                                    provider_name = val.into_owned();
                                }
                            }
                        }
                    } else if tag == "TimeCreated" {
                        for attr in e.attributes().flatten() {
                            if attr.key.local_name().as_ref() == "SystemTime" {
                                if let Ok(val) = attr.normalized_value(XmlVersion::Implicit1_0) {
                                    system_time = Some(val.into_owned());
                                }
                            }
                        }
                    }
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_system && !current_tag.is_empty() {
                    let text = e.as_ref().trim();
                    match current_tag.as_str() {
                        "EventID" => {
                            if let Ok(parsed) = text.parse::<u32>() {
                                event_id = Some(parsed);
                            }
                        }
                        "EventRecordID" => {
                            if let Ok(parsed) = text.parse::<i64>() {
                                record_id = Some(parsed);
                            }
                        }
                        "Level" => {
                            if let Ok(parsed) = text.parse::<u8>() {
                                level = parsed;
                            }
                        }
                        "Channel" => {
                            if !text.is_empty() {
                                channel = Some(text.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let tag = e.local_name().as_ref().to_string();
                if tag == "System" {
                    in_system = false;
                }
                current_tag.clear();
            }
            Ok(Event::Eof) => break,
            Err(err) => {
                return Err(SentinelError::XmlParse(format!(
                    "malformed Windows Event XML: {err}"
                )));
            }
            _ => {}
        }
    }

    let event_id = event_id.ok_or_else(|| {
        SentinelError::XmlParse("missing <EventID> in Windows Event XML".to_string())
    })?;
    if provider_name.trim().is_empty() {
        return Err(SentinelError::XmlParse(
            "missing <Provider Name=...> in Windows Event XML".to_string(),
        ));
    }

    let (timestamp_utc, timestamp_ms) = match system_time {
        Some(ref ts_str) => match DateTime::parse_from_rfc3339(ts_str) {
            Ok(dt) => {
                let utc = dt.with_timezone(&Utc);
                (utc.to_rfc3339(), utc.timestamp_millis())
            }
            Err(_) => {
                let now = Utc::now();
                (now.to_rfc3339(), now.timestamp_millis())
            }
        },
        None => {
            let now = Utc::now();
            (now.to_rfc3339(), now.timestamp_millis())
        }
    };

    Ok(ParsedWindowsEvent {
        channel: normalize_channel(channel, fallback_channel),
        provider_name,
        event_id,
        record_id,
        level,
        timestamp_utc,
        timestamp_ms,
        raw_xml: raw_xml.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_application_hang_1002_xml() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Application Hang" />
    <EventID Qualifiers="0">1002</EventID>
    <Level>2</Level>
    <TimeCreated SystemTime="2026-11-25T13:05:10.123456Z" />
    <EventRecordID>45821</EventRecordID>
    <Channel>Application</Channel>
  </System>
</Event>"#;
        let parsed = parse_event_xml("Application", xml).expect("parse 1002");
        assert_eq!(parsed.channel, "Application");
        assert_eq!(parsed.provider_name, "Application Hang");
        assert_eq!(parsed.event_id, 1002);
        assert_eq!(parsed.record_id, Some(45821));
        assert_eq!(parsed.level, 2);
        assert!(parsed.timestamp_ms > 0);
    }

    #[test]
    fn extracts_app_module_and_exception_from_event_data() {
        let xml = r#"<Event><System><Provider Name="Application Error"/><EventID>1000</EventID></System>
  <EventData>
    <Data Name="AppName">mspaint.exe</Data>
    <Data Name="AppVersion">11.2609.401.0</Data>
    <Data Name="ModuleName">ucrtbase.dll</Data>
    <Data Name="ExceptionCode">0xc0000409</Data>
    <Data Name="PackageFullName">Microsoft.Paint_11.2609.401.0_x64__8wekyb3d8bbwe</Data>
  </EventData></Event>"#;
        let details = extract_event_data_summary(xml);
        assert_eq!(details.app_name.as_deref(), Some("mspaint.exe"));
        assert_eq!(details.module_name.as_deref(), Some("ucrtbase.dll"));
        assert_eq!(details.exception_code.as_deref(), Some("0xc0000409"));
        let text = details.searchable_text.expect("searchable text");
        assert!(text.contains("mspaint.exe"));
        assert!(text.contains("ucrtbase.dll"));
        assert!(text.contains("0xc0000409"));
        assert!(text.contains("Microsoft.Paint"));
    }

    #[test]
    fn historical_xpath_includes_time_window() {
        let app_q = build_historical_xpath("Application", 30);
        assert!(app_q.contains("timediff(@SystemTime) <= 2592000000"));
        assert!(app_q.contains("Application Error"));
        assert!(app_q.contains("Windows Error Reporting"));

        let sys_q = build_historical_xpath("System", 7);
        assert!(sys_q.contains("timediff(@SystemTime) <= 604800000"));
        assert!(sys_q.contains("Microsoft-Windows-Kernel-Power"));
    }

    #[test]
    fn parses_kernel_power_41_and_disk_129_xml() {
        let kp_xml = r#"<Event><System><Provider Name="Microsoft-Windows-Kernel-Power"/><EventID>41</EventID><Level>1</Level><TimeCreated SystemTime="2026-11-25T12:00:00Z"/><EventRecordID>101</EventRecordID><Channel>System</Channel></System></Event>"#;
        let kp = parse_event_xml("System", kp_xml).expect("parse 41");
        assert_eq!(kp.event_id, 41);
        assert_eq!(kp.level, 1);

        let disk_xml = r#"<Event><System><Provider Name="storahci"/><EventID>129</EventID><Level>3</Level><TimeCreated SystemTime="2026-11-25T12:01:00Z"/><EventRecordID>102</EventRecordID><Channel>System</Channel></System></Event>"#;
        let disk = parse_event_xml("System", disk_xml).expect("parse 129");
        assert_eq!(disk.provider_name, "storahci");
        assert_eq!(disk.event_id, 129);
    }

    #[test]
    fn rejects_invalid_or_incomplete_xml() {
        assert!(parse_event_xml("System", "<Event><System></System></Event>").is_err());
        assert!(parse_event_xml("System", "<Event><System><EventID>41").is_err());
    }

    #[test]
    fn xpath_queries_cover_all_required_event_ids() {
        for needle in [
            "Application Error",
            "1000",
            "Application Hang",
            "1002",
            "Windows Error Reporting",
            "1001",
        ] {
            assert!(APPLICATION_XPATH.contains(needle), "missing {needle}");
        }
        for needle in [
            "Microsoft-Windows-Kernel-Power",
            "41",
            "6008",
            "1001",
            "storahci",
            "nvme",
            "iaStorA",
            "iaStorAC",
            "129",
            "EventID=7",
            "EventID=51",
            "EventID=153",
            "Ntfs",
            "EventID=55",
            "Microsoft-Windows-Resource-Exhaustion-Detector",
            "2004",
            "Microsoft-Windows-Kernel-Processor-Power",
            "37",
            "Microsoft-Windows-DNS-Client",
            "1014",
            "EventID=27",
            "Display",
            "4101",
        ] {
            assert!(SYSTEM_XPATH.contains(needle), "missing {needle}");
        }
    }
}
