use super::runbook::DiagnosticReport;

pub struct HtmlReportGenerator;

impl HtmlReportGenerator {
    pub fn generate(report: &DiagnosticReport) -> String {
        let mut html = String::new();
        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("<meta charset=\"UTF-8\">\n");
        html.push_str("<title>LumiDiag Diagnostic Report</title>\n");
        html.push_str("<style>\n");
        html.push_str("body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f9f9f9; color: #333; }\n");
        html.push_str(".container { max-width: 800px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }\n");
        html.push_str("h1 { text-align: center; color: #0056b3; }\n");
        html.push_str(
            ".meta { text-align: center; margin-bottom: 30px; font-size: 0.9em; color: #777; }\n",
        );
        html.push_str(".phase-card { border-left: 5px solid #ccc; background: #fdfdfd; margin-bottom: 15px; padding: 15px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }\n");
        html.push_str(".phase-card.success { border-left-color: #28a745; }\n");
        html.push_str(".phase-card.failure { border-left-color: #dc3545; }\n");
        html.push_str(".phase-title { font-size: 1.2em; margin: 0 0 10px 0; }\n");
        html.push_str(".status { font-weight: bold; }\n");
        html.push_str(".status.success { color: #28a745; }\n");
        html.push_str(".status.failure { color: #dc3545; }\n");
        html.push_str(".details { margin: 0; font-family: monospace; background: #eee; padding: 8px; border-radius: 4px; }\n");
        html.push_str("</style>\n</head>\n<body>\n");

        html.push_str("<div class=\"container\">\n");
        html.push_str("<h1>LumiDiag Report</h1>\n");
        html.push_str(&format!(
            "<div class=\"meta\">Target: <strong>{}</strong> | Timestamp: {}</div>\n",
            report.target, report.timestamp
        ));

        for phase in &report.phases {
            let card_class = if phase.success { "success" } else { "failure" };
            let status_text = if phase.success { "PASS" } else { "FAIL" };

            html.push_str(&format!("<div class=\"phase-card {}\">\n", card_class));
            html.push_str(&format!(
                "<h2 class=\"phase-title\">Phase: {}</h2>\n",
                phase.phase_name
            ));
            html.push_str(&format!(
                "<p>Status: <span class=\"status {}\">{}</span></p>\n",
                card_class, status_text
            ));
            html.push_str(&format!("<p class=\"details\">{}</p>\n", phase.details));
            html.push_str("</div>\n");
        }

        html.push_str("</div>\n");
        html.push_str("</body>\n</html>");
        html
    }
}
