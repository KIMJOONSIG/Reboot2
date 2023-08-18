import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from telegram import Bot

# Telegram bot token and chat_id
token = "token"
chat_id = "6389282491"
bot = Bot(token=token)

# Log directory path
log_dir = "/path/to/your/log/directory"

class LogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('.log'):
            with open(event.src_path, 'r') as file:
                # Read the log file and analyze it
                content = file.read()
                if "suspicious_pattern" in content:
                    bot.send_message(chat_id=chat_id, text=f"Alert! Suspicious pattern detected in {event.src_path}")

observer = Observer()
observer.schedule(LogHandler(), path=log_dir, recursive=False)
observer.start()

try:
    while True:
        pass
except KeyboardInterrupt:
    observer.stop()

observer.join()
