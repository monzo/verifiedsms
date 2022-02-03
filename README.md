# verifiedsms

This is a go library for interacting with the Google [Verified SMS](https://developers.google.com/business-communications/verified-sms)
service. You'll need to already be signed up as a Verified SMS Partner to use this library.

Example:

```go
package main

import "github.com/monzo/verifiedsms"

partner := verified_sms.VerifiedSMSPartner{
    ServiceAccountJSONFile: "foobar",
}

agent := verified_sms.VerifiedSMSAgent{
	ID: "barbaz",
	PrivateKey: ...,
}

wasMessageVerified, err := partner.MarkSMSAsVerified(context.Background(), "+447700900461", agent, "hello!")
```
