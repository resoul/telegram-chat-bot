# 🤖 AI Telegram Bot (Go)

A simple Telegram bot written in **Go** with **Gemini AI** integration.

![Go Version](https://img.shields.io/badge/Go-1.21%2B-blue?logo=go)
![License](https://img.shields.io/badge/License-MIT-green)
![Telegram](https://img.shields.io/badge/Telegram-Bot-blue?logo=telegram)

## 📦 Installation

1. Clone the repository:
```bash
git clone https://github.com/resoul/telegram-chat-bot.git
cd telegram-chat-bot
go install
```
2. Create your environment file:
```
cp example.env .env
```
3. Then open .env and replace the placeholder values with your own API keys:
````
GEMINI_API_KEY=your_gemini_key
TELEGRAM_API_TOKEN=your_telegram_token
````
3. Run the bot:
````
go run .
````