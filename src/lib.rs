use std::borrow::Cow;
use winnow::error::ContextError;
use winnow::{
    ascii::{alpha1, escaped_transform, line_ending, till_line_ending},
    combinator::{alt, delimited, opt, repeat, separated_pair, terminated},
    token::{tag, take, take_till, take_until, take_while},
    unpeek, IResult, PResult, Parser, Partial,
};

type Stream<'i> = Partial<&'i [u8]>;

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
        if name.eq("content-length") {
            return value.parse::<usize>().ok();
        }
    }
    None
}

fn map_empty_slice(s: &[u8]) -> Option<&[u8]> {
    Some(s).filter(|c| !c.is_empty())
}

pub fn parse_frame<'a>(input: &'a [u8]) -> IResult<&'a [u8], StompFrame, ContextError> {
    let mut partial: Partial<&'a [u8]> = Partial::new(input);
    let result = { parse_frame_stream(&mut partial)? };
    Ok((partial.into_inner(), result))
}

pub fn parse_frame_stream<'a, 'b>(input: &'a mut Partial<&'b [u8]>) -> PResult<StompFrame<'b>> {
    // dbg!(&String::from_utf8_lossy(input));

    let (command, headers) = (
        delimited(
            opt(line_ending),
            alpha1.map(String::from_utf8_lossy),
            line_ending,
        ), // command
        terminated(
            repeat(0.., parse_header), // header
            line_ending,
        ),
    )
        .parse_next(input)?;

    let body = match get_content_length(&headers) {
        None => take_until(0.., "\x00")
            .map(map_empty_slice)
            .parse_next(input)?,
        Some(length) => take(length).map(Some).parse_next(input)?,
    };

    (tag("\0"), opt(line_ending.complete_err())).parse_next(input)?;

    Ok(StompFrame {
        command,
        headers,
        body: body.map(Cow::Borrowed),
    })
}

fn parse_header(input: &mut Stream) -> PResult<(String, String)> {
    separated_pair(
        take_till(0.., [':', '\r', '\n']).and_then(unpeek(unescape)),
        tag(":"),
        terminated(till_line_ending, line_ending).and_then(unpeek(unescape)),
    )
        .parse_next(input)
}

fn unescape(input: &[u8]) -> IResult<&[u8], String, ContextError> {
    let mut f = escaped_transform(
        take_while(1, |c| c != b'\\'),
        '\\',
        alt((
            tag("\\").value("\\".as_bytes()),
            tag("r").value("\r".as_bytes()),
            tag("n").value("\n".as_bytes()),
            tag("c").value(":".as_bytes()),
        )),
    )
    .try_map(String::from_utf8);

    f.parse_peek(input)
}

fn get_content_length_header(body: &[u8]) -> Vec<u8> {
    format!("content-length:{}\n", body.len()).into_bytes()
}
