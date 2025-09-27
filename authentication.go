package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
	"github.com/golang-jwt/jwt/v4"
)

type MyJWTClaims struct {
	*jwt.RegisteredClaims
	UserInfo interface{}
}

type UserJWTData struct {
	Username string
	ID       uint
	Admin    bool
}

var (
	privateKey []byte
	publicKey  []byte
)

func create(sub string, userInfo interface{}) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	exp := time.Now().Add(time.Hour * 24)

	claims := &MyJWTClaims{
		&jwt.RegisteredClaims{
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		userInfo,
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}

func getClaimsFromToken(tokenString string) (jwt.MapClaims, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("get claims: parse key: %w", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token claims")
}

func readKeyFiles() ([]byte, []byte, error) {
	// Try to read existing keys
	prvKey, err := os.ReadFile(eventConf.JWTPrivateKey)
	if err != nil {
		// If private key doesn't exist, generate new keys
		if os.IsNotExist(err) {
			fmt.Println("JWT keys not found, generating new keys...")
			return generateJWTKeys()
		}
		return nil, nil, err
	}

	pubKey, err := os.ReadFile(eventConf.JWTPublicKey)
	if err != nil {
		// If public key doesn't exist, generate new keys
		if os.IsNotExist(err) {
			fmt.Println("JWT keys not found, generating new keys...")
			return generateJWTKeys()
		}
		return nil, nil, err
	}

	return prvKey, pubKey, nil
}

func generateJWTKeys() ([]byte, []byte, error) {
	// Ensure the keys directory exists
	keysDir := filepath.Dir(eventConf.JWTPrivateKey)
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Generate 2048-bit RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Encode private key to PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	// Encode public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	publicKeyBytes = pem.EncodeToMemory(publicKeyPEM)

	// Write keys to files
	if err := os.WriteFile(eventConf.JWTPrivateKey, privateKeyBytes, 0600); err != nil {
		return nil, nil, fmt.Errorf("failed to write private key: %w", err)
	}

	if err := os.WriteFile(eventConf.JWTPublicKey, publicKeyBytes, 0644); err != nil {
		return nil, nil, fmt.Errorf("failed to write public key: %w", err)
	}

	fmt.Printf("Generated JWT keys:\n  Private: %s\n  Public: %s\n", eventConf.JWTPrivateKey, eventConf.JWTPublicKey)

	return privateKeyBytes, publicKeyBytes, nil
}

func initCookies(router *gin.Engine) {
	router.Use(sessions.Sessions("quotient", cookie.NewStore([]byte("quotient"))))
}

func login(c *gin.Context) {
	var err error
	session := sessions.Default(c)
	var jsonData map[string]interface{}
	if err := c.ShouldBindJSON(&jsonData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing fields"})
		return
	}

	username := jsonData["username"].(string)
	password := jsonData["password"].(string)

	// Validate form input
	if strings.Trim(username, " ") == "" || strings.Trim(password, " ") == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username or password can't be empty."})
		return
	}

	// Authenticate user
	var isAdmin bool
	var teamid uint

	if eventConf.LdapConnectUrl != "" {
		teamid, isAdmin, err = ldapLogin(username, password)
		if err != nil {
			debugPrint("LDAP ERROR:", err)
		}
	}

	// user still not found yet
	if !isAdmin && teamid == 0 {
		for _, admin := range eventConf.Admin {
			if username == admin.Name && password == admin.Pw {
				isAdmin = true
				break
			}
		}

		if !isAdmin {
			teamid, err = dbLogin(username, password)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password."})
				return
			}
		}
	}

	session.Set("id", username)

	jwtContent := UserJWTData{
		Username: username,
		Admin:    isAdmin,
		ID:       teamid,
	}

	tok, err := create(username, jwtContent)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
		return
	}

	c.SetCookie("auth_token", tok, 86400, "/", "*", false, false)

	if err := session.Save(); err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "redirect": "/"})
}

func ldapLogin(username string, password string) (uint, bool, error) {
	ldapServer, err := ldap.DialURL(eventConf.LdapConnectUrl)
	if err != nil {
		// c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return 0, false, err
	}
	defer ldapServer.Close()

	err = ldapServer.Bind(eventConf.LdapBindDn, eventConf.LdapBindPassword)
	if err != nil {
		// c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password."})
		return 0, false, err
	}

	// search for dn based on SAM
	searchRequest := ldap.NewSearchRequest(
		eventConf.LdapBaseDn, // baseDN
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(samaccountname=%s)", username), // filter
		[]string{"cn", "memberOf"},                   // attributes to retrieve
		nil,
	)
	searchResult, err := ldapServer.Search(searchRequest)
	if err != nil {
		// c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return 0, false, err
	}

	// Check if user was found (which should always be true if it binded)
	if len(searchResult.Entries) == 0 {
		// c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password."})
		return 0, false, errors.New("incorrect username or password")
	}

	// test bind
	err = ldapServer.Bind(searchResult.Entries[0].DN, password) // test correct password
	if err != nil {
		// c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password."})
		return 0, false, err
	}

	var isAdmin bool
	var teamid uint

	// Print group membership
	for _, entry := range searchResult.Entries {
		for _, memberOf := range entry.GetAttributeValues("memberOf") {
			if strings.EqualFold(memberOf, eventConf.LdapAdminGroupDn) {
				isAdmin = true
				break
			}
			if strings.EqualFold(memberOf, eventConf.LdapTeamGroupDn) {
				team, err := dbGetTeam(entry.GetAttributeValue("cn"))
				if err != nil {
					// c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return 0, false, err
				}
				teamid = team.ID
				break
			}
		}
	}
	return teamid, isAdmin, nil
}

func logout(c *gin.Context) {
	session := sessions.Default(c)
	id := session.Get("id")

	cookie, err := c.Request.Cookie("auth_token")

	if cookie != nil && err == nil {
		c.SetCookie("auth_token", "", -1, "/", "*", false, true)
	}

	err = session.Save()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	if id == nil {
		c.JSON(http.StatusOK, gin.H{"message": "No session."})
		return
	}
	session.Delete("id")
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	c.Redirect(http.StatusSeeOther, "/")
}

func isLoggedIn(c *gin.Context) (bool, error) {
	tok, err := c.Cookie("auth_token")
	if err != nil {
		return false, nil
	}
	_, err = getClaimsFromToken(tok)
	if err != nil {
		return false, err
	}
	return true, nil
}

func clearAuthCookiesAndRedirect(c *gin.Context) {
	// Clear the auth_token cookie
	c.SetCookie("auth_token", "", -1, "/", "*", false, true)
	// Clear session
	session := sessions.Default(c)
	session.Delete("id")
	session.Save()
	// Redirect to home page
	c.Redirect(http.StatusSeeOther, "/")
}

func authRequired(c *gin.Context) {
	status, err := isLoggedIn(c)
	if status == false || err != nil {
		clearAuthCookiesAndRedirect(c)
		return
	}
	c.Next()
}

func contextGetClaims(c *gin.Context) (UserJWTData, error) {
	isLoggedIn, err := isLoggedIn(c)
	if err != nil {
		return UserJWTData{}, err
	}

	if isLoggedIn == false {
		return UserJWTData{}, errors.New("not logged in")
	}

	tokenString, err := c.Cookie("auth_token")
	if err != nil {
		return UserJWTData{}, err
	}

	claims, err := getClaimsFromToken(tokenString)
	if err != nil {
		return UserJWTData{}, err
	}

	if val, ok := claims["UserInfo"]; ok {
		userInfo := val.(map[string]interface{})
		return UserJWTData{ID: uint(userInfo["ID"].(float64)), Username: userInfo["Username"].(string), Admin: userInfo["Admin"].(bool)}, nil
	}
	return UserJWTData{}, errors.New("no user info")
}

func adminAuthRequired(c *gin.Context) {
	claims, err := contextGetClaims(c)
	if err != nil {
		clearAuthCookiesAndRedirect(c)
		return
	}

	if claims.Admin == false {
		clearAuthCookiesAndRedirect(c)
		return
	}

	c.Next()
}

func authRequiredAPI(c *gin.Context) {
	status, err := isLoggedIn(c)
	if status == false || err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	c.Next()
}

func adminAuthRequiredAPI(c *gin.Context) {
	claims, err := contextGetClaims(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if claims.Admin == false {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	c.Next()
}
