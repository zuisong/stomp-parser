use bytes::{BufMut as _, BytesMut};
use nom::{
    branch::alt,
    bytes::complete::{escaped_transform, take_while_m_n},
    bytes::streaming::{is_not, tag, take, take_until},
    character::streaming::{alpha1, line_ending, not_line_ending},
    combinator::{complete, opt},
    combinator::{map_res, value},
    multi::{count, many0, many_till},
    sequence::{delimited, separated_pair, terminated, tuple},
    IResult, Parser,
};

use std::borrow::Cow;

#[derive(Debug)]
pub struct StompFrame<'a> {
    command: Cow<'a, str>,
    headers: Vec<(String, String)>,
    body: Option<Cow<'a, [u8]>>,
}

impl<'a> StompFrame<'a> {
    pub fn serialize(&self) -> BytesMut {
        let mut buffer = BytesMut::new();
        let buf = &mut buffer;
        fn write_escaped(b: u8, buffer: &mut BytesMut) {
            let escaped: &[u8] = match b {
                b'\r' => b"\\r",
                b'\n' => b"\\n",
                b':' => b"\\c",
                b'\\' => b"\\\\",
                b => return buffer.put_u8(b),
            };
            buffer.put_slice(escaped)
        }
        buf.put_slice(self.command.as_bytes());
        buf.put_u8(b'\n');
        self.headers.iter().for_each(|(key, ref val)| {
            for byte in key.as_bytes() {
                write_escaped(*byte, buf);
            }
            buf.put_u8(b':');
            for byte in val.as_bytes() {
                write_escaped(*byte, buf);
            }
            buf.put_u8(b'\n');
        });
        if let Some(ref body) = self.body {
            buf.put_slice(&get_content_length_header(body));
            buf.put_u8(b'\n');
            buf.put_slice(body);
        } else {
            buf.put_u8(b'\n');
        }
        buf.put_u8(b'\x00');
        buffer
    }
}

fn get_content_length(headers: &Vec<(String, String)>) -> Option<usize> {
    for (name, value) in headers {
        if name.as_str() == "content-length" {
            return value.parse::<usize>().ok();
        }
    }
    None
}

fn map_empty_slice(s: &[u8]) -> Option<&[u8]> {
    Some(s).filter(|c| !c.is_empty())
}

pub fn parse_frame(input: &[u8]) -> IResult<&[u8], StompFrame> {
    // dbg!(&String::from_utf8_lossy(input));
    // read stream until header end
    // drop result for save memory
    many_till(take(1_usize).map(drop), count(line_ending, 2))(input)?;

    let (input, (command, headers)) = tuple((
        delimited(
            opt(complete(line_ending)),
            alpha1.map(String::from_utf8_lossy),
            line_ending,
        ), // command
        terminated(
            many0(parse_header), // header
            line_ending,
        ),
    ))(input)?;

    let (input, body) = match get_content_length(&headers) {
        None => take_until("\x00").map(map_empty_slice).parse(input)?,
        Some(length) => take(length).map(Some).parse(input)?,
    };

    let (input, _) = tuple((tag("\x00"), opt(complete(line_ending))))(input)?;

    Ok((
        input,
        StompFrame {
            command,
            headers,
            body: body.map(Cow::Borrowed),
        },
    ))
}

fn parse_header(input: &[u8]) -> IResult<&[u8], (String, String)> {
    complete(separated_pair(
        is_not(":\r\n").and_then(unescape),
        tag(":"),
        terminated(not_line_ending, line_ending).and_then(unescape),
    ))
    .parse(input)
}

fn unescape(input: &[u8]) -> IResult<&[u8], String> {
    let mut f = map_res(
        escaped_transform(
            take_while_m_n(1, 1, |c| c != b'\\'),
            '\\',
            alt((
                value("\\".as_bytes(), tag("\\")),
                value("\r".as_bytes(), tag("r")),
                value("\n".as_bytes(), tag("n")),
                value(":".as_bytes(), tag("c")),
            )),
        ),
        String::from_utf8,
    );

    f.parse(input)
}

fn get_content_length_header(body: &[u8]) -> Vec<u8> {
    format!("content-length:{}\n", body.len()).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::AsBytes;
    use pretty_assertions::{assert_eq, assert_matches};

    #[test]
    fn parse_and_serialize_connect() {
        let data = b"CONNECT
accept-version:1.2
host:datafeeds.here.co.uk
login:user
heart-beat:6,7
passcode:password\\c123\n\n\x00"
            .to_vec();
        let (_, frame) = parse_frame(&data).unwrap();
        assert_eq!(frame.command.as_ref(), "CONNECT");
        let headers_expect: Vec<(&[u8], &[u8])> = vec![
            (&b"accept-version"[..], &b"1.2"[..]),
            (b"host", b"datafeeds.here.co.uk"),
            (b"login", b"user"),
            (b"heart-beat", b"6,7"),
            (b"passcode", b"password:123"),
        ];
        let fh: Vec<_> = frame
            .headers
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
            .collect();

        assert_eq!(fh, headers_expect);
        assert_eq!(frame.body, None);
    }

    #[test]
    fn parse_and_serialize_message() {
        let mut data = b"\nMESSAGE
destination:datafeeds.here.co.uk
message-id:12345
subscription:some-id
"
        .to_vec();
        let body = "this body contains \x00 nulls \n and \r\n newlines \x00 OK?";
        let rest = format!("content-length:{}\n\n{}\x00", body.len(), body);
        data.extend_from_slice(rest.as_bytes());
        let (_, frame) = parse_frame(&data).unwrap();
        assert_eq!(frame.command.as_bytes(), b"MESSAGE");
        let headers_expect: Vec<(&[u8], &[u8])> = vec![
            (&b"destination"[..], &b"datafeeds.here.co.uk"[..]),
            (b"message-id", b"12345"),
            (b"subscription", b"some-id"),
            (b"content-length", b"50"),
        ];
        let fh: Vec<_> = frame
            .headers
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
            .collect();
        assert_eq!(fh, headers_expect);
        assert_eq!((&frame).body.as_ref().unwrap().as_ref(), (body.as_bytes()));
    }

    #[test]
    fn parse_and_serialize_message_with_body_start_with_newline() {
        let mut data = b"MESSAGE
destination:datafeeds.here.co.uk
message-id:12345
subscription:some-id"
            .to_vec();
        let body = "\n\n\nthis body contains  nulls \n and \r\n newlines OK?";
        let rest = format!("\n\n{}\x00\r\n", body);
        data.extend_from_slice(rest.as_bytes());
        let (_, frame) = parse_frame(&data).unwrap();
        assert_eq!(frame.command.as_bytes(), b"MESSAGE");
        let headers_expect: Vec<(&[u8], &[u8])> = vec![
            (&b"destination"[..], &b"datafeeds.here.co.uk"[..]),
            (b"message-id", b"12345"),
            (b"subscription", b"some-id"),
        ];
        let fh: Vec<_> = frame
            .headers
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
            .collect();
        assert_eq!(fh, headers_expect);
        assert_eq!(frame.body.unwrap(), (body.as_bytes()));
    }

    #[test]
    fn parse_and_serialize_message_body_like_header() {
        let data = b"\nMESSAGE\r
destination:datafeeds.here.co.uk
message-id:12345
subscription:some-id\n\nsomething-like-header:1\x00\r\n"
            .to_vec();
        let (_, frame) = parse_frame(&data).unwrap();
        assert_eq!(frame.command.as_bytes(), b"MESSAGE");
        let headers_expect: Vec<(&[u8], &[u8])> = vec![
            (b"destination", b"datafeeds.here.co.uk"),
            (b"message-id", b"12345"),
            (b"subscription", b"some-id"),
        ];
        let fh: Vec<_> = frame
            .headers
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
            .collect();
        assert_eq!(fh, headers_expect);
        assert_eq!(
            frame.body.as_ref().unwrap().as_ref(),
            ("something-like-header:1".as_bytes())
        );
    }

    #[test]
    fn parse_a_incomplete_message() {
        assert_matches!(
            parse_frame(b"\nMESSAG".as_ref()),
            Err(nom::Err::Incomplete(_))
        );

        assert_matches!(
            parse_frame(b"\nMESSAGE\n\n".as_ref()),
            Err(nom::Err::Incomplete(_))
        );

        assert_matches!(
            parse_frame(b"\nMESSAG\n\n\0".as_ref()),
            Ok((
                _,
                StompFrame {
                    ref command,
                    headers: _,
                    body: None
                }
            )) if command == "MESSAG"
        );

        assert_matches!(
            parse_frame(b"\nMESSAGE\r\ndestination:datafeeds.here.co.uk".as_ref()),
            Err(nom::Err::Incomplete(_))
        );

        assert_matches!(
            parse_frame(b"\nMESSAGE\r\ndestination:datafeeds.here.co.uk\n\n".as_ref()),
            Err(nom::Err::Incomplete(_))
        );

        assert_matches!(
            parse_frame(b"\nMESSAGE\r\nheader:da\\ctafeeds.here.co.uk\n\n\0".as_ref()),
            Ok((b"",StompFrame{ headers: ref a , .. })) if a[0].1 == "da:tafeeds.here.co.uk".to_string()
        );

        assert_matches!(
            parse_frame(b"\nMESSAGE\r\ndestination:datafeeds.here.co.uk".as_ref()),
            Err(nom::Err::Incomplete(_))
        );

        assert_matches!(
            parse_frame(b"\nMESSAGE\r\ndestination:datafeeds.here.co.uk\n\n\0remain".as_ref()),
            Ok((b"remain", StompFrame { .. })),
            "stream with other after body end, should return remain text"
        );

        assert_matches!(
            parse_frame(b"\nMESSAGE\ncontent-length:10000\n\n\0remain".as_ref()),
            Err(nom::Err::Incomplete(_)),
            "content-length:10000, body size<10000, return incomplete"
        );
        assert_matches!(
            parse_frame(b"\nMESSAGE\ncontent-length:0\n\n\0remain".as_ref()),
            Ok((b"remain", StompFrame {   body:  Some(ref b), .. })) if b.len()==0,
            "empty body with content-length:0, body should be Some([])"
        );
        assert_matches!(
            parse_frame(b"\nMESSAGE\n\n\0remain".as_ref()),
            Ok((b"remain", StompFrame { body: None, .. })),
            "empty body without content-length header, body should be None"
        );
    }

    #[test]
    fn parse_and_serialize_message_header_value_with_colon() {
        let data = b"CONNECTED
server:ActiveMQ/6.0.0
heart-beat:0,0
session:ID:orbstack-45879-1702220142549-3:2
version:1.2

\0\n"
            .to_vec();
        let (_, frame) = parse_frame(&data).unwrap();
        assert_eq!(frame.command.as_bytes(), b"CONNECTED");
        let headers_expect: Vec<(&[u8], &[u8])> = vec![
            (b"server", b"ActiveMQ/6.0.0"),
            (b"heart-beat", b"0,0"),
            (b"session", b"ID:orbstack-45879-1702220142549-3:2"),
            (b"version", b"1.2"),
        ];
        let fh: Vec<_> = frame
            .headers
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
            .collect();
        assert_eq!(fh, headers_expect);
    }

    #[test]
    fn test_parser_header_unescape() {
        let h = parse_frame(
            b"MESSAGE
subscription:11
message-id:0.4.0
destination:now\\c Instant {\\n    tv_sec\\c 5740,\\n    tv_nsec\\c 164006416,\\n}
content-type:application/json
server:tokio-stomp/0.4.0

body\0"
                .as_ref(),
        );
        dbg!(&h);
        assert_matches!(h, Ok((b"", StompFrame{ body:Some(ref b) ,..})) if b.as_ref() == b"body");
    }

    #[test]
    fn test_serialize() {
        let f = StompFrame {
            command: "MESSAGE".into(),
            body: None,
            headers: vec![],
        };

        assert_eq!(
            f.serialize().as_ref(),
            b"MESSAGE

\0"
        );

        let f = StompFrame {
            command: "MESSAGE".into(),
            body: Some(b"body".as_bytes().into()),
            headers: vec![],
        };

        assert_eq!(
            f.serialize().as_ref(),
            b"MESSAGE
content-length:4

body\0"
        );

        let f = StompFrame {
            command: "MESSAGE".into(),
            body: Some(b"body".as_bytes().into()),
            headers: vec![("name\r\n:\\end".to_string(), "value\r\n:".to_string())],
        };

        assert_eq!(
            f.serialize().as_ref(),
            b"MESSAGE
name\\r\\n\\c\\\\end:value\\r\\n\\c
content-length:4

body\0"
        );
    }

    #[test]
    fn test_long_body() {
        let body = "body".repeat(1000);
        let f = StompFrame {
            command: "MESSAGE".into(),
            body: Some(body.as_bytes().into()),
            headers: vec![("name\r\n:\\end".to_string(), "value\r\n:".to_string())],
        };

        assert_eq!(
            f.serialize().as_ref(),
            format!(
                "MESSAGE
name\\r\\n\\c\\\\end:value\\r\\n\\c
content-length:{}

{}\0",
                body.len(),
                body
            )
                .as_bytes()
        );
    }
}
