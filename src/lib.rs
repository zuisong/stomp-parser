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

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct StompFrame<'a> {
    command: Cow<'a, str>,
    headers: Vec<(String, String)>,
    body: Option<Cow<'a, [u8]>>,
}

impl<'a> StompFrame<'a> {
    pub fn serialize(&self) -> Cow<[u8]> {
        let mut buffer = Vec::new();
        let buf: &mut Vec<u8> = &mut buffer;
        fn write_escaped(b: u8, buffer: &mut Vec<u8>) {
            let binding = [b];
            let escaped: &[u8] = match &binding {
                b"\r" => b"\\r",
                b"\n" => b"\\n",
                b":" => b"\\c",
                b"\\" => b"\\\\",
                bytes => bytes,
            };
            buffer.extend_from_slice(escaped)
        }
        buf.extend_from_slice(self.command.as_bytes());
        buf.push(b'\n');
        self.headers.iter().for_each(|(key, ref val)| {
            for byte in key.as_bytes() {
                write_escaped(*byte, buf);
            }
            buf.push(b':');
            for byte in val.as_bytes() {
                write_escaped(*byte, buf);
            }
            buf.push(b'\n');
        });
        if let Some(body) = &self.body {
            buf.extend_from_slice(&get_content_length_header(body));
            buf.push(b'\n');
            buf.extend_from_slice(body);
        } else {
            buf.push(b'\n');
        }
        buf.push(b'\x00');
        Cow::Owned(buffer)
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
