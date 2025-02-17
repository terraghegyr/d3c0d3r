package main

import (
	"bufio"
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"html"
	"net/url"
	"os"
)

// rotN shifts characters by n places
func rotN(text string, shift int) string {
	result := ""
	for _, char := range text {
		if char >= 'A' && char <= 'Z' {
			result += string(((char-'A'+rune(shift))%26 + 'A'))
		} else if char >= 'a' && char <= 'z' {
			result += string(((char-'a'+rune(shift))%26 + 'a'))
		} else {
			result += string(char)
		}
	}
	return result
}

func hexEncode(text string) string {
	return hex.EncodeToString([]byte(text))
}

func hexDecode(text string) string {
	bytes, err := hex.DecodeString(text)
	if err != nil {
		return "(invalid hex input)"
	}
	return string(bytes)
}

func base64Encode(text string) string {
	return base64.StdEncoding.EncodeToString([]byte(text))
}

func base64Decode(text string) string {
	bytes, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "(invalid base64 input)"
	}
	return string(bytes)
}

func base32Encode(text string) string {
	return base32.StdEncoding.EncodeToString([]byte(text))
}

func base32Decode(text string) string {
	bytes, err := base32.StdEncoding.DecodeString(text)
	if err != nil {
		return "(invalid base32 input)"
	}
	return string(bytes)
}

func urlEncode(text string) string {
	return url.QueryEscape(text)
}

func urlDecode(text string) string {
	decoded, err := url.QueryUnescape(text)
	if err != nil {
		return "(invalid URL encoding)"
	}
	return decoded
}

func htmlEscape(text string) string {
	return html.EscapeString(text)
}

func htmlUnescape(text string) string {
	return html.UnescapeString(text)
}

func ascii85Encode(text string) string {
	buf := make([]byte, ascii85.MaxEncodedLen(len(text)))
	n := ascii85.Encode(buf, []byte(text))
	return string(buf[:n])
}

func ascii85Decode(text string) string {
	buf := make([]byte, len(text))
	n, _, err := ascii85.Decode(buf, []byte(text), true)
	if err != nil {
		return "(invalid Ascii85 input)"
	}
	return string(buf[:n])
}

func hashString(text string, hasher hash.Hash) string {
	hasher.Write([]byte(text))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func main() {
	var input string
	if len(os.Args) > 1 && os.Args[1] == "-i" {
		// Read from stdin (piped input)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			input = scanner.Text()
		}
	} else {
		// Interactive mode
		fmt.Print("Enter text: ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		input = scanner.Text()
	}

	// Output results in required order
	fmt.Println("\nDecoding Results:")
	fmt.Println("HEX Decode:", hexDecode(input))
	fmt.Println("Base32 Decode:", base32Decode(input))
	fmt.Println("Base64 Decode:", base64Decode(input))
	fmt.Println("URL Decode:", urlDecode(input))
	fmt.Println("HTML Unescape:", htmlUnescape(input))
	fmt.Println("Ascii85 Decode:", ascii85Decode(input))
	fmt.Println("ROT13 Decode:", rotN(input, 13))
	fmt.Println("ROT18 Decode:", rotN(input, 18))

	fmt.Println("\nEncoding Results:")
	fmt.Println("HEX Encode:", hexEncode(input))
	fmt.Println("Base32 Encode:", base32Encode(input))
	fmt.Println("Base64 Encode:", base64Encode(input))
	fmt.Println("URL Encode:", urlEncode(input))
	fmt.Println("HTML Escape:", htmlEscape(input))
	fmt.Println("Ascii85 Encode:", ascii85Encode(input))
	fmt.Println("ROT13 Encode:", rotN(input, 26))
	fmt.Println("ROT18 Encode:", rotN(input, 36))

	fmt.Println("\nHashing Results:")
	fmt.Println("MD5:", hashString(input, md5.New()))
	fmt.Println("SHA-1:", hashString(input, sha1.New()))
	fmt.Println("SHA-256:", hashString(input, sha256.New()))
	fmt.Println("SHA-384:", hashString(input, sha512.New384()))
	fmt.Println("SHA-512:", hashString(input, sha512.New()))
}
