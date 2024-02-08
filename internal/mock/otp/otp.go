package otp

import (
	"context"
	"cybus/internal/dto"
	"unicode/utf8"
)

type otpMock struct {
	referenceID string
	pin         string
}

func NewOTPMock(referenceID string, pin string) (dto.OTPVerifier, error) {
	return &otpMock{pin: pin, referenceID: referenceID}, nil
}

func (m *otpMock) RequestOTP(_ context.Context, _ string, _ string) (*dto.RequestOTPResponse, error) {
	return &dto.RequestOTPResponse{PinLength: utf8.RuneCountInString(m.pin), ReferenceID: m.referenceID}, nil
}

func (m *otpMock) VerifyOTP(_ context.Context, referenceID string, pin string) error {
	if referenceID == m.referenceID && pin == m.pin {
		return nil
	}
	return dto.ErrBadCode
}

func (m *otpMock) Provider() dto.OTPVerifierProvider {
	return dto.OTPVerifierProviderMock
}
