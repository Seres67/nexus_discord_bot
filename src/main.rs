use std::collections::HashSet;
use std::env::{self};

use serenity::async_trait;
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::prelude::*;

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
                let file = msg.attachments.get(0).unwrap();
                if file.filename.ends_with(".jpg")
                    || file.filename.ends_with(".jpeg")
                    || file.filename.ends_with(".png")
                {
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

                let mut msg_content = String::new();

                let mut stacktrace_pos = 0;
                let mut found_exception_line = false;
                for (i, line) in lines.iter().enumerate() {
                    if line.contains("intercepted unhandled hardware exception") {
                        let pos = line.find("\"").unwrap();
                        let (_, to_print) = line.split_at(pos);
                        msg_content.push_str(to_print);
                        msg_content.push('\n');
                        found_exception_line = true;
                    }
                    if line.contains("RVA") && found_exception_line {
                        stacktrace_pos = i + 2;
                        break;
                    }
                }
                let mut culprits: HashSet<&str> = HashSet::new();
                for line in &lines[stacktrace_pos..] {
                    let split = line.split_whitespace().collect::<Vec<&str>>();
                    if split.len() == 4 {
                        let culprit = split.get(3).unwrap();
                        let culprit_lowercase = culprit.to_lowercase();
                        if culprit_lowercase == "ntdll" || culprit_lowercase == "kernel32" {
                            continue;
                        }
                        culprits.insert(culprit);
                    }
                }
                msg_content.push_str("\nLikely culprits:\n");
                for culprit in culprits {
                    msg_content.push_str(culprit);
                    msg_content.push('\n');
                }
                if let Err(why) = msg.reply(&ctx.http, msg_content).await {
                    println!("Error sending message: {why:?}");
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
