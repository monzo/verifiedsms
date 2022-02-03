package data_munging

import (
	"strings"
)

// This file is responsible for creating the different types of SMS message that could end up being delivered to the
// users device based on data munging by phone carriers. This will never be exhaustive, but is intended to capture as
// many devices as possible.

func GetAllIterationsOfSMSMessage(smsMessage string) []string {
	iterations := []string{
		smsMessage,
	}

	trimmedMessage := strings.TrimSpace(smsMessage)
	if trimmedMessage != smsMessage {
		iterations = append(iterations, smsMessage)
	}

	return iterations
}
