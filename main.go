package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"sync"
	"unicode"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var cfgFile string
var logger = logrus.New()

type Config struct {
	InputFile       string `yaml:"input_file"`
	OutputFile      string `yaml:"output_file"`
	NoReverse       bool   `yaml:"no_reverse"`
	Rot13           bool   `yaml:"rot13"`
	CaesarShift     int    `yaml:"caesar_shift"`
	Base64Encode    bool   `yaml:"base64_encode"`
	Base64Decode    bool   `yaml:"base64_decode"`
	URLEncode       bool   `yaml:"url_encode"`
	URLDecode       bool   `yaml:"url_decode"`
	Atbash          bool   `yaml:"atbash"`
	VigenereKey     string `yaml:"vigenere_key"`
	HexEncode       bool   `yaml:"hex_encode"`
	HexDecode       bool   `yaml:"hex_decode"`
	XORKey          string `yaml:"xor_key"`
	Concurrency     int    `yaml:"concurrency"`
	LogLevel        string `yaml:"log_level"`
}

var config Config

func initConfig() {
	if cfgFile != "" {
		data, err := ioutil.ReadFile(cfgFile)
		if err != nil {
			logger.Fatalf("Error reading config file: %v", err)
		}
		err = yaml.Unmarshal(data, &config)
		if err != nil {
			logger.Fatalf("Error parsing config file: %v", err)
		}
	}

	// Set log level
	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)
}

func reverse(s string) string {
	runes := []rune(s)
	var wg sync.WaitGroup
	mu := sync.Mutex{}

	chunkSize := len(runes) / config.Concurrency
	if chunkSize == 0 {
		chunkSize = len(runes)
	}
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			end := start + chunkSize
			if end > len(runes) {
				end = len(runes)
			}
			mu.Lock()
			for j, k := start, end-1; j < k; j, k = j+1, k-1 {
				runes[j], runes[k] = runes[k], runes[j]
			}
			mu.Unlock()
		}(i * chunkSize)
	}
	wg.Wait()
	return string(runes)
}

func rot13(s string) string {
	return caesarCipher(s, 13)
}

func caesarCipher(s string, shift int) string {
	var result strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			result.WriteRune('a' + ((c-'a'+rune(shift))%26))
		case c >= 'A' && c <= 'Z':
			result.WriteRune('A' + ((c-'A'+rune(shift))%26))
		default:
			result.WriteRune(c)
		}
	}
	return result.String()
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func base64Decode(s string) string {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		logger.Errorf("Error decoding Base64: %v", err)
		return ""
	}
	return string(data)
}

func urlEncode(s string) string {
	return url.QueryEscape(s)
}

func urlDecode(s string) string {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		logger.Errorf("Error decoding URL: %v", err)
		return ""
	}
	return decoded
}

// Atbash Cipher: a>z, b>y, c>x, and so on
func atbashCipher(s string) string {
	var result strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			result.WriteRune('z' - (c - 'a'))
		case c >= 'A' && c <= 'Z':
			result.WriteRune('Z' - (c - 'A'))
		default:
			result.WriteRune(c)
		}
	}
	return result.String()
}

// Vigenere Cipher (only alphabets). Non-alpha chars unchanged.
// If config.VigenereKey is empty, skip.
func vigenereCipher(s, key string, encode bool) string {
	if key == "" {
		return s
	}

	var result strings.Builder
	keyIndex := 0
	keyRunes := []rune(strings.ToLower(key))
	keyLen := len(keyRunes)

	for _, c := range s {
		if unicode.IsLetter(c) {
			base := 'a'
			if unicode.IsUpper(c) {
				base = 'A'
			}
			shift := keyRunes[keyIndex%keyLen] - 'a'
			if !encode {
				shift = -shift
			}

			rotated := base + ((c-base)+shift+26)%26
			result.WriteRune(rotated)

			keyIndex++
		} else {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// Hex Encode/Decode
func hexEncode(s string) string {
	return hex.EncodeToString([]byte(s))
}

func hexDecode(s string) string {
	data, err := hex.DecodeString(s)
	if err != nil {
		logger.Errorf("Error decoding hex: %v", err)
		return ""
	}
	return string(data)
}

// XOR cipher with a key. For simplicity key is a string and it XOR each byte in a repeating fashion.
func xorCipher(s, key string) string {
	if key == "" {
		return s
	}
	data := []byte(s)
	keyBytes := []byte(key)
	keyLen := len(keyBytes)
	for i := range data {
		data[i] = data[i] ^ keyBytes[i%keyLen]
	}
	return string(data)
}

func processText(inputText string) string {
	processedText := inputText

	// Reverse (if not disabled)
	if !config.NoReverse {
		processedText = reverse(processedText)
		logger.Debug("Applied reverse transformation")
	}

	// ROT13
	if config.Rot13 {
		processedText = rot13(processedText)
		logger.Debug("Applied ROT13 transformation")
	}

	// Caesar Cipher
	if config.CaesarShift != 0 {
		processedText = caesarCipher(processedText, config.CaesarShift)
		logger.Debugf("Applied Caesar cipher with shift %d", config.CaesarShift)
	}

	// Atbash
	if config.Atbash {
		processedText = atbashCipher(processedText)
		logger.Debug("Applied Atbash cipher")
	}

	// Vigenere Cipher
	// Assume Vigenere is always encoding since we have no separate decode flag.
	// If you want both encode/decode, you'd add another flag. For now, let's treat it as encoding.
	if config.VigenereKey != "" {
		processedText = vigenereCipher(processedText, config.VigenereKey, true)
		logger.Debug("Applied Vigenere cipher")
	}

	// Base64 Encode
	if config.Base64Encode {
		processedText = base64Encode(processedText)
		logger.Debug("Applied Base64 encoding")
	}

	// Base64 Decode
	if config.Base64Decode {
		processedText = base64Decode(processedText)
		logger.Debug("Applied Base64 decoding")
	}

	// Hex Encode
	if config.HexEncode {
		processedText = hexEncode(processedText)
		logger.Debug("Applied Hex encoding")
	}

	// Hex Decode
	if config.HexDecode {
		processedText = hexDecode(processedText)
		logger.Debug("Applied Hex decoding")
	}

	// URL Encode
	if config.URLEncode {
		processedText = urlEncode(processedText)
		logger.Debug("Applied URL encoding")
	}

	// URL Decode
	if config.URLDecode {
		processedText = urlDecode(processedText)
		logger.Debug("Applied URL decoding")
	}

	// XOR cipher
	if config.XORKey != "" {
		processedText = xorCipher(processedText, config.XORKey)
		logger.Debug("Applied XOR cipher")
	}

	return processedText
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "./TT.go [flags] <text>",
		Long: `TT is a versatile text processing tool with advanced features and modern practices. 
Can apply multiple transformations such as reverse, ROT13, Caesar, Atbash, Vigenere, XOR, 
Base64, Hex, and URL encode/decode. 
Use different combinations for educational or obfuscation purposes (not for secure encryption!).`,
		Run: func(cmd *cobra.Command, args []string) {
			initConfig()
			var inputText string
			if config.InputFile != "" {
				data, err := ioutil.ReadFile(config.InputFile)
				if err != nil {
					logger.Fatalf("Error reading input file: %v", err)
				}
				inputText = string(data)
				logger.Infof("Read input from file: %s", config.InputFile)
			} else if len(args) > 0 {
				inputText = strings.Join(args, " ")
				logger.Info("Read input from command-line arguments")
			} else {
				logger.Error("No input text provided")
				cmd.Help()
				os.Exit(1)
			}

			result := processText(inputText)

			if config.OutputFile != "" {
				err := ioutil.WriteFile(config.OutputFile, []byte(result), 0644)
				if err != nil {
					logger.Fatalf("Error writing to output file: %v", err)
				}
				logger.Infof("Wrote output to file: %s", config.OutputFile)
			} else {
				fmt.Println(result)
			}
		},
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Config file (YAML format)")
	rootCmd.PersistentFlags().StringVarP(&config.InputFile, "in", "i", "", "Read input text from a file")
	rootCmd.PersistentFlags().StringVarP(&config.OutputFile, "out", "o", "", "Write output text to a file")
	rootCmd.PersistentFlags().BoolVar(&config.NoReverse, "no-reverse", false, "Do not reverse the input text")
	rootCmd.PersistentFlags().BoolVar(&config.Rot13, "rot13", false, "Apply ROT13 transformation")
	rootCmd.PersistentFlags().IntVar(&config.CaesarShift, "caesar", 0, "Apply Caesar cipher with specified shift")
	rootCmd.PersistentFlags().BoolVar(&config.Base64Encode, "base64-encode", false, "Apply Base64 encoding")
	rootCmd.PersistentFlags().BoolVar(&config.Base64Decode, "base64-decode", false, "Apply Base64 decoding")
	rootCmd.PersistentFlags().BoolVar(&config.URLEncode, "url-encode", false, "Apply URL encoding")
	rootCmd.PersistentFlags().BoolVar(&config.URLDecode, "url-decode", false, "Apply URL decoding")
	rootCmd.PersistentFlags().BoolVar(&config.Atbash, "atbash", false, "Apply Atbash cipher")
	rootCmd.PersistentFlags().StringVar(&config.VigenereKey, "vigenere-key", "", "Apply Vigenere cipher with the given key")
	rootCmd.PersistentFlags().BoolVar(&config.HexEncode, "hex-encode", false, "Apply Hex encoding")
	rootCmd.PersistentFlags().BoolVar(&config.HexDecode, "hex-decode", false, "Apply Hex decoding")
	rootCmd.PersistentFlags().StringVar(&config.XORKey, "xor-key", "", "Apply XOR cipher with the given key")
	rootCmd.PersistentFlags().IntVar(&config.Concurrency, "concurrency", 4, "Number of concurrent workers")
	rootCmd.PersistentFlags().StringVar(&config.LogLevel, "log-level", "info", "Set log level (debug, info, warn, error)")

	if err := rootCmd.Execute(); err != nil {
		logger.Fatal(err)
	}
}