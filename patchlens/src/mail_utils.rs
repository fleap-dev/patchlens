use mail_parser::MessageParser;

pub fn parse_mail_patch(content: &str) -> Vec<String> {
   let message = MessageParser::default()
       .parse(content)
       .expect("failed to parse email message");

   let body = message
       .body_text(0)
       .expect("failed to read email body")
       .to_string()
       .replace('\r', "");

   let segments = body
       .split("\ndiff --git ")
       .skip(1)
       .filter_map(|s| s.split_once("\n"))
       .map(|(_, s)| s)
       .filter_map(|s| s.split_once("\n"))
       .map(|(_, s)| s.to_owned())
       .collect::<Vec<_>>();

    segments
}

