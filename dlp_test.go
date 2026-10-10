package main

import "testing"

// Card numbers below are public network test numbers (Visa 4111..., Amex
// 3782..., Mastercard 5555...), never real cards.
func TestCreditCardDetection(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"4111 1111 1111 1111", 1},
		{"4111-1111-1111-1111", 1},
		{"4111.1111.1111.1111", 1},
		{"4111111111111111", 1},
		{"Card: 4111 1111 1111 1111 Exp 12/28 CVV 123", 1},
		{"4111 1111 1111 1111 12/28 123", 1},   // expiry on the same line
		{"4111111111111111 123", 1},            // CVV right after the number
		{"4111 1111 1111 1111 12 28 737", 1},   // expiry and CVV as plain groups
		{"Order 12 4111 1111 1111 1111", 1},    // digits before the number
		{"4111 1111 1111 1111\n12/28\n123", 1}, // separate lines
		{"Amex 3782 822463 10005", 1},
		{"4111 1111 1111 1111 5555 5555 5555 4444", 2},
		{"4111 1111 1111 1112", 0},            // fails Luhn
		{"1234567890123456789012", 0},         // one long ID, not a card
		{"Order 12345 shipped 2026-09-30", 0}, // too few digits
		{"+1 415 555 0100", 0},
		{"10.0.0.1 and 192.168.1.100", 0},
		{"0000 0000 0000 0000", 0}, // passes Luhn, no card network starts with 0
	}
	s := newDLPScanner(nil)
	for _, tt := range tests {
		got := 0
		for _, f := range s.scan(tt.in) {
			if f.rule == "credit-card" {
				got = f.count
			}
		}
		if got != tt.want {
			t.Errorf("%q: credit-card count = %d, want %d", tt.in, got, tt.want)
		}
	}
}
