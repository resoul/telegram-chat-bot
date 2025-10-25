package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/joho/godotenv"
	"google.golang.org/genai"
)

type Config struct {
	TelegramToken string
	ModelName     string
}

func loadConfig() *Config {
	_ = godotenv.Load()

	return &Config{
		TelegramToken: os.Getenv("TELEGRAM_API_TOKEN"),
		ModelName:     "gemini-2.5-flash",
	}
}

func main() {
	cfg := loadConfig()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Println("🧹 Shutting down gracefully...")
		cancel()
	}()

	client, err := genai.NewClient(ctx, nil)
	if err != nil {
		log.Fatalf("❌ Failed to create genai client: %v", err)
	}

	bot, err := tgbotapi.NewBotAPI(cfg.TelegramToken)
	if err != nil {
		log.Fatalf("❌ Failed to init Telegram bot: %v", err)
	}

	bot.Debug = true
	log.Printf("✅ Authorized on account %s", bot.Self.UserName)

	updateConfig := tgbotapi.NewUpdate(0)
	updateConfig.Timeout = 30
	updates := bot.GetUpdatesChan(updateConfig)

	for {
		select {
		case <-ctx.Done():
			log.Println("⏹️ Context canceled, exiting main loop.")
			return
		case update := <-updates:
			if update.Message == nil {
				continue
			}

			go handleUpdate(ctx, bot, client, cfg, update)
		}
	}
}

func handleUpdate(ctx context.Context, bot *tgbotapi.BotAPI, client *genai.Client, cfg *Config, update tgbotapi.Update) {
	msg := tgbotapi.NewMessage(update.Message.Chat.ID, "")
	message := update.Message.Text
	generate := !update.Message.IsCommand()

	if update.Message.IsCommand() {
		switch update.Message.Command() {
		case "start":
			msg.Text = "👋 Say Hello. Language code is " + update.Message.From.LanguageCode
			generate = false
		default:
			msg.Text = "Unknown command: 🤔"
			generate = false
		}
	}

	if generate {
		result, err := client.Models.GenerateContent(
			ctx,
			cfg.ModelName,
			genai.Text(message),
			nil,
		)
		if err != nil {
			log.Printf("⚠️ Generation error: %v", err)
			msg.Text = "Error 😔"
		} else {
			msg.Text = result.Text()
		}
	}

	if _, err := bot.Send(msg); err != nil {
		log.Printf("⚠️ Error msg: %v", err)
	}
}
