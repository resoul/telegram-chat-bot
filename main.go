package main

import (
	"context"
	"log"
	"os"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/joho/godotenv"
	"google.golang.org/genai"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	bot, err := tgbotapi.NewBotAPI(os.Getenv("TELEGRAM_API_TOKEN"))
	if err != nil {
		panic(err)
	}

	bot.Debug = true

	updateConfig := tgbotapi.NewUpdate(0)
	updateConfig.Timeout = 30
	updates := bot.GetUpdatesChan(updateConfig)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		msg := tgbotapi.NewMessage(update.Message.Chat.ID, "")
		message := "I understand /start."
		generate := false

		if update.Message.IsCommand() {
			switch update.Message.Command() {
			case "start":
				message = "Say Hello. Language code is " + update.Message.From.LanguageCode
				generate = true
			default:
				msg.Text = "I understand /start."
			}
		} else {
			generate = true
			message = update.Message.Text
		}

		if generate {
			result, err := client.Models.GenerateContent(
				ctx,
				"gemini-2.5-flash",
				genai.Text(message),
				nil,
			)

			if err != nil {
				log.Fatal(err)
			}

			msg.Text = result.Text()
		}

		//msg.ReplyToMessageID = update.Message.MessageID
		if _, err := bot.Send(msg); err != nil {
			panic(err)
		}
	}
}
