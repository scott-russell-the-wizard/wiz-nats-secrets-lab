package main

import (
	"fmt"
	"log"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// Hardcoded fixture credentials (from NATS by Example) for testing Wiz Custom Secret Detection in Go source code
const (
	// Operator NKey Seed (Private Key - should trigger sr-nats-nkey-seed)
	defaultOperatorSeed = "SOALU7LPGJK2BDF7IHD7UZT6ZM23UMKYLGJLNN35QJSUI5BNR4DJRFH4R4"

	// Account NKey Seed (Private Key - should trigger sr-nats-nkey-seed)
	defaultAccountSeed = "SAALXUEDN2QR5KZDDSH5S4RIWAZDM7CVDG5HNJI2HS5LBVYFTLAQCOXZAU"

	// Signed Account JWT (Ed25519-NKey JWT - should trigger sr-nats-ed25519-jwt)
	defaultAccountJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJQQkZFUzMzR0dJRlpNNlVHQzdOWTVBUkhSQkZWRlU0VUQ3RlMyV05MWkgzS1BHV0ZWRUZRIiwiaWF0IjoxNjc4OTczOTQ1LCJpc3MiOiJPQ0NLUjc2UUNLVjRSMjI0V1A2WklTWFdMWExKWldERjIyVFJaRlFNMkk2S1VQRURRM09WQ0o2TiIsIm5hbWUiOiJteS1hY2NvdW50Iiwic3ViIjoiQUI1RDZONjRaR1VUQ0dFVEJXM0hTT1JMVEpINVVDQ0I1Q0tQWkZXQ0Y2VVYzS0k1QkNUUlBGREMiLCJuYXRzIjp7ImxpbWl0cyI6eyJzdWJzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsIndpbGRjYXJkcyI6dHJ1ZSwiY29ubiI6LTEsImxlYWYiOi0xLCJtZW1fc3RvcmFnZSI6LTEsImRpc2tfc3RvcmFnZSI6LTF9LCJkZWZhdWx0X3Blcm1pc3Npb25zIjp7InB1YiI6e30sInN1YiI6e319LCJ0eXBlIjoiYWNjb3VudCIsInZlcnNpb24iOjJ9fQ.4-kUapoPK_9A9L_CfJRBEe1XukgVBGaSU3J5tBFbajF3G5660BORa2CRUnN6x0dv-jUgui5EIQeANDB5kh_wDw"
)

func main() {
	log.SetFlags(0)

	// Reference: https://natsbyexample.com/examples/auth/nkeys-jwts/go/
	operatorKP, _ := nkeys.FromSeed([]byte(defaultOperatorSeed))
	operatorPub, _ := operatorKP.PublicKey()
	fmt.Printf("operator pubkey: %s\n", operatorPub)

	operatorSeed, _ := operatorKP.Seed()
	fmt.Printf("operator seed: %s\n\n", string(operatorSeed))

	accountKP, _ := nkeys.FromSeed([]byte(defaultAccountSeed))
	accountPub, _ := accountKP.PublicKey()
	fmt.Printf("account pubkey: %s\n", accountPub)

	accountSeed, _ := accountKP.Seed()
	fmt.Printf("account seed: %s\n", string(accountSeed))

	accountClaims := jwt.NewAccountClaims(accountPub)
	accountClaims.Name = "my-account"
	accountClaims.Limits.JetStreamLimits.DiskStorage = -1
	accountClaims.Limits.JetStreamLimits.MemoryStorage = -1

	accountJWT, _ := accountClaims.Encode(operatorKP)
	fmt.Printf("account jwt: %s\n\n", accountJWT)

	userKP, _ := nkeys.CreateUser()
	userPub, _ := userKP.PublicKey()
	userSeed, _ := userKP.Seed()

	userClaims := jwt.NewUserClaims(userPub)
	userClaims.Name = "my-user"
	userClaims.Limits.Data = 1024 * 1024 * 1024
	userClaims.Permissions.Pub.Allow.Add("foo.>", "bar.>")
	userClaims.Permissions.Sub.Allow.Add("_INBOX.>")

	userJWT, _ := userClaims.Encode(accountKP)
	creds, _ := jwt.FormatUserConfig(userJWT, userSeed)
	fmt.Printf("creds file:\n%s\n", creds)
}
