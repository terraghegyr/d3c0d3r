package main

import (
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"html"
	"net/url"
	"syscall/js"
	"unicode"
)

func rot13(this js.Value, p []js.Value) any {
	text := p[0].String()
	result := ""
	for _, char := range text {
		if char >= 'A' && char <= 'Z' {
			result += string(((char-'A'+rune(13))%26 + 'A'))
		} else if char >= 'a' && char <= 'z' {
			result += string(((char-'a'+rune(13))%26 + 'a'))
		} else {
			result += string(char)
		}
	}
	return result
}

func rot18(this js.Value, p []js.Value) any {
	result := ""
	text := p[0].String()
	for _, r := range text {
		if unicode.IsLetter(r) {
			// Apply ROT13 to letters (both upper and lower case)
			if unicode.IsLower(r) {
				result += string((r-'a'+13)%26 + 'a')
			} else {
				result += string((r-'A'+13)%26 + 'A')
			}
		} else if unicode.IsDigit(r) {
			// Apply ROT5 to digits
			result += string((r-'0'+5)%10 + '0')
		} else {
			// Non-alphanumeric characters remain unchanged
			result += string(r)
		}
	}
	return result
}

func rot47(this js.Value, p []js.Value) any {
	text := p[0].String()
	result := ""
	for _, r := range text {
		if r >= 33 && r <= 126 {
			// Shift within printable ASCII range
			result += string(((r-33+47)%94 + 33))
		} else {
			// Non-printable characters remain unchanged
			result += string(r)
		}
	}
	return result
}

// hexEncode encodes input string to hex
func hexEncode(this js.Value, p []js.Value) any {
	text := p[0].String()
	return hex.EncodeToString([]byte(text))
}

// hexDecode decodes hex input string
func hexDecode(this js.Value, p []js.Value) any {
	text := p[0].String()
	bytes, err := hex.DecodeString(text)
	if err != nil {
		return "(invalid hex input)"
	}
	return string(bytes)
}

// base64Encode encodes input string to Base64
func base32Encode(this js.Value, p []js.Value) any {
	text := p[0].String()
	return base32.StdEncoding.EncodeToString([]byte(text))
}

// base64Decode decodes Base64 input string
func base32Decode(this js.Value, p []js.Value) any {
	text := p[0].String()
	bytes, err := base32.StdEncoding.DecodeString(text)
	if err != nil {
		return "(invalid base64 input)"
	}
	return string(bytes)
}

// base64Encode encodes input string to Base64
func base64Encode(this js.Value, p []js.Value) any {
	text := p[0].String()
	return base64.StdEncoding.EncodeToString([]byte(text))
}

// base64Decode decodes Base64 input string
func base64Decode(this js.Value, p []js.Value) any {
	text := p[0].String()
	bytes, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "(invalid base64 input)"
	}
	return string(bytes)
}

// urlEncode encodes input string to URL encoded string
func urlEncode(this js.Value, p []js.Value) any {
	text := p[0].String()
	return url.QueryEscape(text)
}

// urlDecode decodes URL encoded input string
func urlDecode(this js.Value, p []js.Value) any {
	text := p[0].String()
	decoded, err := url.QueryUnescape(text)
	if err != nil {
		return "(invalid URL encoding)"
	}
	return decoded
}

// htmlEscape escapes HTML characters in input string
func htmlEscape(this js.Value, p []js.Value) any {
	text := p[0].String()
	return html.EscapeString(text)
}

// htmlUnescape unescapes HTML characters in input string
func htmlUnescape(this js.Value, p []js.Value) any {
	text := p[0].String()
	return html.UnescapeString(text)
}

// ascii85Encode encodes input string to ASCII85
func ascii85Encode(this js.Value, p []js.Value) any {
	text := p[0].String()
	buf := make([]byte, ascii85.MaxEncodedLen(len(text)))
	n := ascii85.Encode(buf, []byte(text))
	return string(buf[:n])
}

// ascii85Decode decodes ASCII85 input string
func ascii85Decode(this js.Value, p []js.Value) any {
	text := p[0].String()
	buf := make([]byte, len(text))
	n, _, err := ascii85.Decode(buf, []byte(text), true)
	if err != nil {
		return "(invalid Ascii85 input)"
	}
	return string(buf[:n])
}

func md5Hash(this js.Value, p []js.Value) any {
	text := p[0].String()
	hash := md5.New()
	hash.Write([]byte(text))
	hashBytes := hash.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

func sha1Hash(this js.Value, p []js.Value) any {
	text := p[0].String()
	hash := sha1.New()
	hash.Write([]byte(text))
	hashBytes := hash.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

func sha256Hash(this js.Value, p []js.Value) any {
	text := p[0].String()
	hash := sha256.New()
	hash.Write([]byte(text))
	hashBytes := hash.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

func sha384Hash(this js.Value, p []js.Value) any {
	text := p[0].String()
	hash := sha512.New384()
	hash.Write([]byte(text))
	hashBytes := hash.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

func sha512Hash(this js.Value, p []js.Value) any {
	text := p[0].String()
	hash := sha512.New()
	hash.Write([]byte(text))
	hashBytes := hash.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

// registerCallbacks registers Go functions to JavaScript
func registerCallbacks() {
	js.Global().Set("rot13", js.FuncOf(rot13))
	js.Global().Set("rot18", js.FuncOf(rot18))
	js.Global().Set("rot47", js.FuncOf(rot47))
	js.Global().Set("hexEncode", js.FuncOf(hexEncode))
	js.Global().Set("hexDecode", js.FuncOf(hexDecode))
	js.Global().Set("base32Encode", js.FuncOf(base32Encode))
	js.Global().Set("base32Decode", js.FuncOf(base32Decode))
	js.Global().Set("base64Encode", js.FuncOf(base64Encode))
	js.Global().Set("base64Decode", js.FuncOf(base64Decode))
	js.Global().Set("urlEncode", js.FuncOf(urlEncode))
	js.Global().Set("urlDecode", js.FuncOf(urlDecode))
	js.Global().Set("htmlEscape", js.FuncOf(htmlEscape))
	js.Global().Set("htmlUnescape", js.FuncOf(htmlUnescape))
	js.Global().Set("ascii85Encode", js.FuncOf(ascii85Encode))
	js.Global().Set("ascii85Decode", js.FuncOf(ascii85Decode))
	js.Global().Set("md5Hash", js.FuncOf(md5Hash))
	js.Global().Set("sha1Hash", js.FuncOf(sha1Hash))
	js.Global().Set("sha256Hash", js.FuncOf(sha256Hash))
	js.Global().Set("sha384Hash", js.FuncOf(sha384Hash))
	js.Global().Set("sha512Hash", js.FuncOf(sha512Hash))
}

func main() {
	c := make(chan struct{}, 0)
	registerCallbacks()
	<-c
}

