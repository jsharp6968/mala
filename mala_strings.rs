use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

#[derive(Serialize)]
struct ScoredString {
    position: usize,
    string: String,
    score: i32,
}

const MAX_STRING_CHAR_LIMIT: usize = 2600;
static EMERGENT: &[char] = &[
    'e', ' ', 't', '1', '|', 'o', 'a', 'r', 'i', 'n', 's', 'l', '2', '3', 'd', 'c', '8', '7', '0',
    '6', '4', 'm', '9', 'u', '5', 'p', 'E', 'S', 'A', 'C', 'g', 'f', 'T', 'h', 'b', 'y', '"', 'I',
    'v', 'L', 'D', 'R', 'w', '-', '_', 'P', 'O', '.', 'N', 'F', 'x', '\\', 'M', 'W', '%', 'V', 'U',
    'k', 'G', 'H', 'B', ':', '@', ',', 'q', '?', '=', ']', ';', '[', '(', '<', 'Q', '\'', 'j', 'X',
    '>', ')', 'Y', 'K', 'z', '$', '/', 'Z', '*', 'J', '+', '`', '^', '!', '&', '#', '~', '}', '{',
];

fn enhanced_human_readable(text: &str) -> i32 {
    if text.len() > MAX_STRING_CHAR_LIMIT || text.is_empty() {
        return 0;
    }

    let mut text_freq = HashMap::new();
    for char in text.chars() {
        *text_freq.entry(char).or_insert(0) += 1;
    }

    let text_vector: Vec<i32> = EMERGENT
        .iter()
        .map(|&c| *text_freq.get(&c).unwrap_or(&0) as i32)
        .collect();
    let emergent_vector: Vec<i32> = (1..=EMERGENT.len() as i32).rev().collect();

    let similarity_score = 1.0 - cosine_similarity(&text_vector, &emergent_vector);
    let diversity_score =
        text.chars().collect::<std::collections::HashSet<_>>().len() as f64 / text.len() as f64;

    let combined_score = similarity_score * 100.0 + diversity_score * 50.0;
    combined_score as i32
}

fn cosine_similarity(a: &[i32], b: &[i32]) -> f64 {
    let dot_product: i32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let a_magnitude = (a.iter().map(|&x| x.pow(2)).sum::<i32>() as f64).sqrt();
    let b_magnitude = (b.iter().map(|&x| x.pow(2)).sum::<i32>() as f64).sqrt();

    dot_product as f64 / (a_magnitude * b_magnitude)
}

fn is_printable(b: u8) -> bool {
    b >= 32 && b <= 126
}

fn extract_strings<P: AsRef<Path>>(path: P, min_length: usize) -> io::Result<Vec<(usize, String)>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut temp_string = Vec::new();
    let mut strings_with_offsets = Vec::new();
    let mut buffer = [0u8; 2048];
    let mut position = 0usize;
    let mut string_start_position = 0usize;

    while let Ok(bytes_read) = reader.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }
        for &byte in &buffer[..bytes_read] {
            if is_printable(byte) {
                if temp_string.is_empty() {
                    string_start_position = position;
                }
                temp_string.push(byte);
            } else {
                if temp_string.len() >= min_length {
                    strings_with_offsets.push((
                        string_start_position,
                        String::from_utf8_lossy(&temp_string).to_string(),
                    ));
                }
                temp_string.clear();
            }
            position += 1;
        }
    }

    if temp_string.len() >= min_length {
        strings_with_offsets.push((
            string_start_position,
            String::from_utf8_lossy(&temp_string).to_string(),
        ));
    }

    Ok(strings_with_offsets)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];

    match extract_strings(path, 6) {
        Ok(strings) => {
            let scored_strings: Vec<(usize, String, i32)> = strings
                .into_iter()
                .map(|(position, string)| {
                    let score = enhanced_human_readable(&string);
                    (position, string, score)
                })
                .filter(|&(_, _, score)| score >= 40)
                .collect();

            for (position, string, score) in scored_strings {
                let scored_string = ScoredString {
                    position,
                    string,
                    score,
                };
                if let Ok(json_string) = serde_json::to_string(&scored_string) {
                    println!("{}", json_string);
                }
            }
        }
        Err(e) => {
            eprintln!("Error processing file: {}", e);
            std::process::exit(1);
        }
    }
}
