use regex::RegexSet;

pub struct PromptInjectionDetector {
    dfa: RegexSet,
}

impl PromptInjectionDetector {
    pub fn new() -> Result<Self, regex::Error> {
        // Single-pass RegexSet DFA for detecting homoglyphs and leet-speak
        let patterns = vec![
            r"(?i)(i|1|l|\|)\s*(g|9|q)\s*(n|v)\s*(o|0)\s*(r|2)\s*(e|3)",
            r"(?i)s\s*y\s*s\s*t\s*e\s*m\s*p\s*r\s*o\s*m\s*p\s*t",
            r"(?i)b\s*y\s*p\s*a\s*s\s*s",
            r"(?i)f\s*o\s*r\s*g\s*e\s*t",
            r"(?i)p\s*r\s*e\s*v\s*i\s*o\s*u\s*s",
        ];
        
        let dfa = RegexSet::new(patterns)?;
        Ok(Self { dfa })
    }

    pub fn is_injection(&self, prompt: &str) -> bool {
        self.dfa.is_match(prompt)
    }
}
