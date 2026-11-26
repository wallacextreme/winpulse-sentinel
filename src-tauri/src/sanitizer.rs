use std::sync::OnceLock;

use regex::Regex;

struct RedactionRules {
    win_user_path: Regex,
    unix_user_path: Regex,
    computer_xml: Regex,
    windows_sid: Regex,
    email: Regex,
    private_ip: Regex,
    google_api_key: Regex,
    bearer_token: Regex,
}

fn rules() -> &'static RedactionRules {
    static RULES: OnceLock<RedactionRules> = OnceLock::new();
    RULES.get_or_init(|| {
        let compile = |pat: &str| {
            Regex::new(pat).unwrap_or_else(|_| Regex::new("a^").expect("fallback empty regex"))
        };
        RedactionRules {
            win_user_path: compile(r"(?i)([A-Z]:\\Users\\)([^\\\s<>]+)"),
            unix_user_path: compile(r"(?i)([A-Z]:/Users/)([^/\s<>]+)"),
            computer_xml: compile(r"(?is)<Computer>([^<]+)</Computer>"),
            windows_sid: compile(r"\bS-1-5-(?:\d+-)+\d+\b"),
            email: compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"),
            private_ip: compile(
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
            ),
            google_api_key: compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
            bearer_token: compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
        }
    })
}

/// Deterministically strips PII, host identifiers, SIDs, private LAN IPs, and secrets
/// before sending any Windows log or telemetry context to an external LLM or MCP client.
pub fn sanitize_text(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let r = rules();
    let s = r.win_user_path.replace_all(input, "${1}[USER]");
    let s = r.unix_user_path.replace_all(&s, "${1}[USER]");
    let s = r.computer_xml.replace_all(&s, "<Computer>[HOST]</Computer>");
    let s = r.windows_sid.replace_all(&s, "[SID]");
    let s = r.email.replace_all(&s, "[EMAIL]");
    let s = r.private_ip.replace_all(&s, "[LAN_IP]");
    let s = r.google_api_key.replace_all(&s, "[REDACTED_API_KEY]");
    let s = r.bearer_token.replace_all(&s, "${1}[REDACTED_TOKEN]");
    s.into_owned()
}

pub fn sanitize_truncated(input: &str, max_chars: usize) -> String {
    let cleaned = sanitize_text(input);
    cleaned.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_windows_paths_hostnames_sids_ips_and_keys() {
        let synthetic_key = format!("{}{}", "AIza", "SyFakeUnitTestKey1234567890abcd");
        let raw = format!(
            r#"<Event><System><Provider Name="Application Error"/><Computer>TEST-HOST99</Computer><Security UserID="S-1-5-21-123456789-987654321-1001"/></System><EventData><Data>C:\Users\TestUser\AppData\Local\Temp\app.exe</Data><Data>192.168.1.44</Data><Data>1.1.1.1</Data><Data>user@example.com</Data><Data>{synthetic_key}</Data><Data>Authorization: Bearer tok_supersecret99</Data></EventData></Event>"#
        );
        let out = sanitize_text(&raw);
        assert!(!out.contains("TestUser"));
        assert!(!out.contains("TEST-HOST99"));
        assert!(!out.contains("S-1-5-21-"));
        assert!(!out.contains("192.168.1.44"));
        assert!(!out.contains("user@example.com"));
        assert!(!out.contains(&synthetic_key));
        assert!(!out.contains("tok_supersecret99"));
        assert!(out.contains(r"C:\Users\[USER]\AppData"));
        assert!(out.contains("<Computer>[HOST]</Computer>"));
        assert!(out.contains("[SID]"));
        assert!(out.contains("[LAN_IP]"));
        assert!(out.contains("1.1.1.1"));
        assert!(out.contains("[EMAIL]"));
        assert!(out.contains("[REDACTED_API_KEY]"));
        assert!(out.contains("Bearer [REDACTED_TOKEN]"));
    }
}
