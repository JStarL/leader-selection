use std::fs::{self, OpenOptions};
use serde::Deserialize;
use rand::{rngs::{StdRng, ThreadRng}, Rng, SeedableRng};
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Write;

#[derive(Deserialize, Debug)]
struct Node {
    name: String,
    stake: f64,
    port: u16,

    #[serde(default)]
    rep: u64,

    #[serde(default)]
    rounds_delay: u32,

    #[serde(default)]
    public_key: String,

    #[serde(default = "default_rng")]
    #[serde(skip)]
    rng: StdRng,

    #[serde(default)]
    score: f64
}

// Default reputation points at start
const DEFAULT_REP: u64 = 2;

// Act maliciously if the random number is more than the threshold
const MALICIOUS_THESHOLD: f64 = 0.998;

// The number of rounds to simulate
const NUM_ROUNDS: u32 = 100;

fn default_rng() -> StdRng {
    StdRng::from_entropy()
}

impl Node {
    pub fn new(name: String, stake: f64, port: u16, rep: u64, rounds_delay: u32, public_key: String, rng: StdRng, score: f64) -> Self {
        Node {
            name,
            stake,
            port,
            rep,
            rounds_delay,
            public_key,
            rng,
            score
        }
    }

    pub fn read_from_file(file_path: &str) -> Vec<Node> {
        let file_contents = fs::read_to_string(file_path).expect("Failed to read file");

        let mut nodes: Vec<Node>  = serde_json::from_str(&file_contents).expect("Failed to parse JSON");
        
        
        // Initialise nodes
        for node in &mut nodes {
            // default repuation points
            node.rep = DEFAULT_REP;
            
            let mut hasher: Sha256 = Sha256::new();
            hasher.update(node.public_key.clone());
            let seed = hasher.finalize();

            node.rng = StdRng::from_seed(seed.into());
            // Initially all nodes have equal rounds delay
            // 2 is the minimum value to represent time since the node was last chosen as a leader
            // and is still able to be selected as a leader
            // 0 leads to -inf
            // 1 leads to 0
            // so 2 is the minimum
            node.rounds_delay = 2;

        }

        nodes
    }

    pub fn print_node(&self) {
        println!("====================");
        println!("Name: {}", self.name);
        println!("Stake: {}", self.stake);
        println!("Port: {}", self.port);
        println!("Rep: {}", self.rep);
        println!("Rounds Delay: {}", self.rounds_delay);
        println!("Public Key: {}", self.public_key);
        println!("Score: {}", self.score);
        println!("====================");
        println!();
    }
}

fn main() {

    let file_path = "./config.json";
    
    let mut nodes: Vec<Node> = Node::read_from_file(file_path);

    let mut malicious_activity_rng = rand::thread_rng();
    
    let mut malicious_count: i32 = 0;

    // let mut csv_string = create_initial_csv_string(&nodes);

    let csv_path = "./out01.csv";

    match open_csv_file(&csv_path, &nodes) {
        Ok(_) => println!("First line of CSV file successfully written"),
        Err(e) => {
            eprintln!("Error writing first line of CSV file: {}", e);
            std::process::exit(1);
        }
    }

    // Execute Rounds
    for i in 0..NUM_ROUNDS {
        println!("=========================");
        println!("Round {}", i);
        execute_round(&i, &mut nodes, &mut malicious_activity_rng, &mut malicious_count, &csv_path);
    }


    if let Err(e) = write_stakes_to_csv(&csv_path, &nodes) {
        eprintln!("Couldn't write stakes to file: {}", e);
        std::process::exit(4);
    }

    print_final_statistics(&malicious_count);

}

fn create_initial_csv_string(nodes: &Vec<Node>) -> String {
    let mut csv_string = String::from("Round");
    
    // Add headers
    for node in nodes {
        csv_string.push_str(&format!(",{}", node.name));
    }
    csv_string
}

fn create_score_string(round: &u32, nodes: &Vec<Node>) -> String {
    let mut csv_string = String::new();

    csv_string.push_str(&round.to_string());
    
    // Add headers
    for node in nodes {
        csv_string.push_str(&format!(",{}", node.score));
    }
    csv_string
}

fn open_csv_file(file_path: &str, nodes: &Vec<Node>) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)?;
    
    let mut header = create_initial_csv_string(nodes);
    header.push_str(",Leader");

    // Write the header
    writeln!(file, "{}", header)?;
    Ok(())
}

fn write_line_to_csv(file_path: &str, nodes: &Vec<Node>, round: &u32, leader_name: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(file_path)?;
    
    let mut line = create_score_string(round, nodes);
    line.push(',');
    line.push_str(leader_name);

    writeln!(file, "{}", line)?;
    Ok(())
}

fn write_malicious_line_to_csv(file_path: &str, round: &u32, name: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(file_path)?;

    let mut round_string = String::new();
    round_string.push_str(&round.to_string());
    round_string.push(',');
    round_string.push_str(name);

    writeln!(file, "{}", round_string)?;
    Ok(())
}

fn write_stakes_to_csv(file_path: &str, nodes: &Vec<Node>) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(file_path)?;

    let mut stakes_string = String::from("Stakes");

    for node in nodes {
        stakes_string.push_str(&format!(",{}", node.stake));
    }

    writeln!(file, "{}", stakes_string)?;
    Ok(())
}

fn print_final_statistics(malicious_count: &i32) {
    println!("=========================");
    println!("Final Statistics");
    println!("Malicious Activity Count: {}", malicious_count);
}

/**
 * Calculates the score based on a formula
 */
fn calculate_score(stake: &f64, random_float: &f64, rep: &u64, rounds_delay: &u32) -> f64 {
    let rep_f64 = *rep as f64;
    let rounds_delay_f64 = *rounds_delay as f64;
    // Stake should not be 0
    // if it is 0, then taking the log of that will result in inf
    let mut tmp_stake: f64 = stake.clone() as f64;
    tmp_stake += 1.1;
    let score = tmp_stake.ln() * random_float * rep_f64.log10() * rounds_delay_f64.ln();
    score
}

/**
 * Execute the node's operations for calculating score in a given round
 */
fn execute_node(node: &mut Node) {
    let random_float: f64 = node.rng.gen();

    node.score = calculate_score(&node.stake, &random_float, &node.rep, &node.rounds_delay);

    // println!("Score of {} is: {}", node.name, node.score);
    node.print_node();

    // Update state
    node.rep += 1;
    node.rounds_delay += 1;
}

/**
 * Iterate through all nodes and attempt malicious behaviour
 * If any node has a probability greater than the threshold of being malicious
 * Assume that this node has acted maliciously and is caught by the protocol
 * Return this node
 * If no node has acted maliciously, return None
 */
fn attempt_malicious<'a>(nodes: &'a mut Vec<Node>, malicious_activity_rng: &'a mut ThreadRng) -> Option<usize> {
    for (i, node) in nodes.iter_mut().enumerate() {
        let malicious_prob: f64 = malicious_activity_rng.gen();
        if malicious_prob > MALICIOUS_THESHOLD {
            node.rep = DEFAULT_REP;
            return Some(i);
        }
    }

    None
}

fn redistribute_stake(nodes: &mut Vec<Node>, malicious_index: usize) {
    let redistributed_stake = nodes[malicious_index].stake / (nodes.len() - 1) as f64;

    for (index, node) in nodes.iter_mut().enumerate() {
        
        /*
            If malicious node:
            1) Cut stake and set to zero
            2) But to continue the simulation, assume a random number of stake generated between 1-20
         */
        if index == malicious_index {
            
            let mut stake_rng = rand::thread_rng();
            let new_stake: i32 = stake_rng.gen_range(0..=12);
            
            node.stake = new_stake as f64;
        } else {
            node.stake += redistributed_stake;
        }
    }
}

fn execute_round(
    round: &u32,
    nodes: &mut Vec<Node>,
    malicious_activity_rng: &mut ThreadRng,
    malicious_count: &mut i32,
    csv_file_path: &str
) {

    /*
     * If any node acts maliciously,
     * rollback the entire state / do not execute state changes
     * We assume that the protocol catches malicious behaviour
     */
    if let Some(i) = attempt_malicious(nodes, malicious_activity_rng) {
        println!("{} behaved maliciously!", nodes[i].name);
        *malicious_count += 1;
        // Do not execute state change

        // write line to csv
        if let Err(e) = write_malicious_line_to_csv(csv_file_path, round, &nodes[i].name) {
            eprintln!("Coudln't write malicious line to csv: {}", e);
            std::process::exit(2);
        }

        // write current funds staked to csv
        if let Err(e) = write_stakes_to_csv(csv_file_path, nodes) {
            eprintln!("Couldn't write stakes line to csv: {}", e);
            std::process::exit(3);
        }

        /*
            Redistribute the stake amongst other participants
         */
        redistribute_stake(nodes,i);

        return;
    }

    /*
     * All nodes are behaving correctly
     * So execute protocol
    */
    for node in nodes.iter_mut() {
        execute_node(node);
    }

    // Look for leader
    let mut max_score: f64 = 0.0;
    let mut max_index: usize = 0;
    for (i, node) in nodes.iter_mut().enumerate() {
        if node.score > max_score {
            max_score = node.score;
            max_index = i;
        }
    }

    let leader_name: String = nodes[max_index].name.clone();
    println!("Node {} is the leader!!!", leader_name);
    nodes[max_index].rounds_delay = 2;

    
    if let Err(e) = write_line_to_csv(csv_file_path, nodes, round, &leader_name) {
        eprintln!("Coudln't write line to csv: {}", e);
        std::process::exit(1);
    }

} 
