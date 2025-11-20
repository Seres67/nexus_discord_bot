use std::collections::{HashMap, HashSet};
use std::env::{self};
use std::fmt::Write;

use serenity::async_trait;
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::prelude::*;

async fn parse_logfile(ctx: &Context, msg: &Message) {
    let file = msg.attachments.get(0).unwrap();
    if !file.filename.ends_with(".txt") && !file.filename.ends_with(".log") {
        return;
    }
    let file_content = match file.download().await {
        Ok(c) => c,
        Err(e) => {
            println!("{e}");
            let _ = msg.reply(&ctx.http, "Failed to download file.");
            return;
        }
    };
    let file_string = match str::from_utf8(&file_content) {
        Ok(v) => v,
        Err(e) => {
            println!("{e}");
            let _ = msg.reply(&ctx.http, "Failed to read file.");
            return;
        }
    };

    let lines: Vec<&str> = file_string.lines().collect();

    let mut stacktrace_pos = 0;
    let mut found_exception_line = false;
    let mut game_exit = false;

    let mut assertions: HashMap<String, u32> = HashMap::new();
    let mut skipped: HashMap<String, u32> = HashMap::new();
    let mut crash = String::new();

    let mut iter = lines.iter().enumerate().peekable();
    while let Some((i, line)) = iter.next() {
        if line.contains("intercepted unhandled hardware exception") {
            let pos = line.find("\"").unwrap();
            let (_, to_print) = line.split_at(pos);
            writeln!(crash, "crash happened at: {}", to_print).unwrap();
            found_exception_line = true;
        } else if line.contains("intercepted gw2 assertion fail") {
            let pos = line.find("\"").unwrap();
            let (_, to_print) = line.split_at(pos);
            assertions
                .entry(to_print.to_owned())
                .and_modify(|c| *c += 1)
                .or_insert(1);
        } else if line.contains("skipped extension") {
            let pos = line.find("\"").unwrap();
            let (_, to_print) = line.split_at(pos);
            skipped
                .entry(to_print.to_owned())
                .and_modify(|c| *c += 1)
                .or_insert(1);
        } else if line.contains("ignoring hardware exception") {
            iter.next();
            continue;
        } else if line.contains("RVA") && found_exception_line {
            stacktrace_pos = i + 2;
            break;
        } else if line.contains("info: game exit") {
            game_exit = true;
        }
    }
    let mut msg_content = String::new();
    if !found_exception_line && game_exit {
        writeln!(msg_content, "\nGame crashed on exit with an unknown cause.").unwrap();
        if let Err(why) = msg.reply(&ctx.http, msg_content).await {
            println!("Error sending message: {why:?}");
        }
        return;
    }
    if !skipped.is_empty() {
        writeln!(msg_content, "Skipped extensions:").unwrap();
        for (k, v) in skipped {
            writeln!(msg_content, "- {}x {}", v, k).unwrap();
        }
    }
    if !assertions.is_empty() {
        writeln!(msg_content, "Intercepted GW2 assertion fails:").unwrap();
        for (k, v) in assertions {
            writeln!(msg_content, "- {}x {}", v, k).unwrap();
        }
    }
    writeln!(msg_content, "\n{crash}").unwrap();
    let mut culprits: HashSet<String> = HashSet::new();
    for line in &lines[stacktrace_pos..] {
        let split = line.split_whitespace().collect::<Vec<&str>>();
        if split.len() >= 4 {
            let culprit_str = split.get(3).unwrap();
            let culprit = if culprit_str.contains("@") {
                let split_culprit_str: Vec<&str> = culprit_str.split("@").collect();
                split_culprit_str.get(0).unwrap().to_owned()
            } else {
                culprit_str
            };
            let culprit_lowercase = culprit.to_lowercase();
            if culprit_lowercase.contains("ntdll")
                || culprit_lowercase.contains("kernel32")
                || culprit_lowercase.contains("kernelbase")
            {
                continue;
            }
            culprits.insert(culprit_lowercase);
        }
    }
    writeln!(msg_content, "Likely culprits:").unwrap();
    for culprit in &culprits {
        writeln!(msg_content, "{culprit}").unwrap();
    }
    if culprits.len() == 1 && culprits.contains("gw2-64") {
        writeln!(
            msg_content,
            "\nThis is most likely a game crash, and there is nothing we can do about it."
        )
        .unwrap();
    }
    if culprits.contains("nvpresent64") {
        writeln!(
            msg_content,
            "\nThis is most likely caused by NVIDIA Smooth Motion, try disabling it."
        )
        .unwrap();
    }
    if let Err(why) = msg.reply(&ctx.http, msg_content).await {
        println!("Error sending message: {why:?}");
    }
}

struct Handler;

#[async_trait]
impl EventHandler for Handler {
    // Set a handler for the `message` event. This is called whenever a new message is received.
    //
    // Event handlers are dispatched through a threadpool, and so multiple events can be
    // dispatched simultaneously.
    async fn message(&self, ctx: Context, msg: Message) {
        if msg.content == "!analyze" {
            if msg.attachments.len() == 1 {
                parse_logfile(&ctx, &msg).await;
            } else if msg.referenced_message.is_some() {
                let referenced_msg = msg.referenced_message.unwrap();
                if referenced_msg.attachments.len() == 1 {
                    parse_logfile(&ctx, &referenced_msg).await;
                }
            } else {
                if let Err(why) = msg
                    .reply_ping(
                        &ctx.http,
                        "Please send an arcdps crashlog with your command.",
                    )
                    .await
                {
                    println!("Error sending message: {why:?}");
                };
            }
        }
    }

    // Set a handler to be called on the `ready` event. This is called when a shard is booted, and
    // a READY payload is sent by Discord. This payload contains data like the current user's guild
    // Ids, current user data, private channels, and more.
    //
    // In this case, just print what the current user's username is.
    async fn ready(&self, _: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);
    }
}

#[tokio::main]
async fn main() {
    // This will load the environment variables located at `./.env`, relative to the CWD.
    // See `./.env.example` for an example on how to structure this.
    dotenv::dotenv().expect("Failed to load .env file");
    // Configure the client with your Discord bot token in the environment.
    let token = env::var("DISCORD_TOKEN").expect("Expected a token in the environment");
    // Set gateway intents, which decides what events the bot will be notified about
    let intents = GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::DIRECT_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT;

    // Create a new instance of the Client, logging in as a bot. This will automatically prepend
    // your bot token with "Bot ", which is a requirement by Discord for bot users.
    let mut client = Client::builder(&token, intents)
        .event_handler(Handler)
        .await
        .expect("Err creating client");

    // Finally, start a single shard, and start listening to events.
    //
    // Shards will automatically attempt to reconnect, and will perform exponential backoff until
    // it reconnects.
    if let Err(why) = client.start().await {
        println!("Client error: {why:?}");
    }
}
