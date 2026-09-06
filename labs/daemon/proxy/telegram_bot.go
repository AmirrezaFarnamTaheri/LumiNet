// Package proxy implements proxy protocols and connection utilities for LumiNet.
// Ported from: ChatGPT-Telegram-Workers (Edge Telegram Bot & Webhook handlers)
// Target path: server/internal/proxy/telegram_bot.go
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TelegramBotClient handles sending message dispatches and parsing webhook updates.
type TelegramBotClient struct {
	token      string
	httpClient *http.Client
}

// NewTelegramBotClient creates a new TelegramBotClient.
func NewTelegramBotClient(token string) *TelegramBotClient {
	return &TelegramBotClient{
		token: token,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SendAlert sends a notification text message to a specific Telegram chat ID.
func (c *TelegramBotClient) SendAlert(chatID string, text string) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", c.token)

	bodyMap := map[string]interface{}{
		"chat_id": chatID,
		"text":    text,
	}

	data, err := json.Marshal(bodyMap)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(apiURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to send telegram alert request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned HTTP status: %d", resp.StatusCode)
	}

	return nil
}

// WebhookUpdate represents an incoming update payload from Telegram.
type WebhookUpdate struct {
	UpdateID int `json:"update_id"`
	Message  *struct {
		MessageID int `json:"message_id"`
		Chat      struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		Text string `json:"text"`
	} `json:"message"`
}

// HandleWebhookUpdate processes user commands received via Telegram webhooks.
func (c *TelegramBotClient) HandleWebhookUpdate(payload []byte, commandCallback func(cmd string, chatID int64) string) error {
	var update WebhookUpdate
	if err := json.Unmarshal(payload, &update); err != nil {
		return fmt.Errorf("failed to parse telegram update payload: %w", err)
	}

	if update.Message != nil && update.Message.Text != "" {
		chatID := update.Message.Chat.ID
		cmd := update.Message.Text

		// Run callback to perform operation (e.g. get status, start/stop daemon)
		response := commandCallback(cmd, chatID)
		if response != "" {
			_ = c.SendAlert(fmt.Sprintf("%d", chatID), response)
		}
	}

	return nil
}
