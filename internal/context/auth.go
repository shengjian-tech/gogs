// Copyright 2014 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package context

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-macaron/csrf"
	"github.com/go-macaron/session"
	gouuid "github.com/satori/go.uuid"
	"github.com/wenzhenxi/gorsa"
	"gopkg.in/macaron.v1"
	log "unknwon.dev/clog/v2"

	"gogs.io/gogs/internal/auth"
	"gogs.io/gogs/internal/conf"
	"gogs.io/gogs/internal/db"
	"gogs.io/gogs/internal/tool"
)

type ToggleOptions struct {
	SignInRequired  bool
	SignOutRequired bool
	AdminRequired   bool
	DisableCSRF     bool
}

func Toggle(options *ToggleOptions) macaron.Handler {
	return func(c *Context) {
		// Cannot view any page before installation.
		if !conf.Security.InstallLock {
			c.RedirectSubpath("/install")
			return
		}

		// Check prohibit login users.
		if c.IsLogged && c.User.ProhibitLogin {
			c.Data["Title"] = c.Tr("auth.prohibit_login")
			c.Success("user/auth/prohibit_login")
			return
		}

		// Check non-logged users landing page.
		if !c.IsLogged && c.Req.RequestURI == "/" && conf.Server.LandingURL != "/" {
			c.RedirectSubpath(conf.Server.LandingURL)
			return
		}

		// Redirect to dashboard if user tries to visit any non-login page.
		if options.SignOutRequired && c.IsLogged && c.Req.RequestURI != "/" {
			c.RedirectSubpath("/")
			return
		}

		if !options.SignOutRequired && !options.DisableCSRF && c.Req.Method == "POST" && !isAPIPath(c.Req.URL.Path) {
			csrf.Validate(c.Context, c.csrf)
			if c.Written() {
				return
			}
		}

		if options.SignInRequired {
			if !c.IsLogged {
				// Restrict API calls with error message.
				if isAPIPath(c.Req.URL.Path) {
					c.JSON(http.StatusForbidden, map[string]string{
						"message": "Only authenticated user is allowed to call APIs.",
					})
					return
				}

				c.SetCookie("redirect_to", url.QueryEscape(conf.Server.Subpath+c.Req.RequestURI), 0, conf.Server.Subpath)
				c.RedirectSubpath("/user/login")
				return
			} else if !c.User.IsActive && conf.Auth.RequireEmailConfirmation {
				c.Title("auth.active_your_account")
				c.Success("user/auth/activate")
				return
			}
		}

		// Redirect to log in page if auto-signin info is provided and has not signed in.
		if !options.SignOutRequired && !c.IsLogged && !isAPIPath(c.Req.URL.Path) &&
			len(c.GetCookie(conf.Security.CookieUsername)) > 0 {
			c.SetCookie("redirect_to", url.QueryEscape(conf.Server.Subpath+c.Req.RequestURI), 0, conf.Server.Subpath)
			c.RedirectSubpath("/user/login")
			return
		}

		if options.AdminRequired {
			if !c.User.IsAdmin {
				c.Status(http.StatusForbidden)
				return
			}
			c.PageIs("Admin")
		}
	}
}

func isAPIPath(url string) bool {
	return strings.HasPrefix(url, "/api/")
}

// authenticatedUserID returns the ID of the authenticated user, along with a bool value
// which indicates whether the user uses token authentication.
func authenticatedUserID(c *macaron.Context, sess session.Store) (_ int64, isTokenAuth bool) {
	if !db.HasEngine {
		return 0, false
	}
	// TODO 加入对 JWT token 的解析 用作产业大脑跳转到 gogs 默认登录
	var token string
	rawQuery := c.Req.URL.RawQuery
	if strings.Contains(rawQuery, "jwttoken") {
		token = strings.Split(rawQuery, "=")[1]
	}
	if token != "" {
		// 解密 token
		plainTest, err := parseRSAToken(token)
		if err != nil {
			log.Error("[error_parse_rsa_token][err: %v]", err)
			return 0, false
		}
		// TODO 解析token 获得用户ID
		result, err := jwt.DecodeSegment(strings.Split(plainTest, ".")[1])
		if err != nil {
			log.Error("error_parse_token")
			return 0, false
		}
		var tmp = make(map[string]interface{}, 0)
		err = json.Unmarshal(result, &tmp)
		if err != nil {
			log.Error("error_parse_token")
			return 0, false
		}
		userID := tmp["userId"].(string)
		userName := tmp["account"].(string)
		// 生成secert 校验
		secert := getJwtSecret(userID)
		// 校验token 是否有效
		_, err = jwt.Parse(plainTest, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method,SigningMethodHMAC")
			}
			return []byte(secert), nil
		})
		if err != nil {
			log.Error("[error_parse_token]")
			return 0, false
		}
		var user *db.User
		if user, err = db.GetUserByName(userName); err != nil {
			if db.IsErrUserNotExist(err) {
				log.Info("Failed to get user by ID: %v", err)
				// 拦截到 token  用户不存在则直接创建
				user, err = db.Users.CreateUser(db.User{
					ChanyeId:    userID,
					Name:        userName,
					Passwd:      "default",
					IsActive:    !conf.Auth.RequireEmailConfirmation,
					LowerName:   strings.ToLower(userName),
					Email:       userName + "@default.com",
					AvatarEmail: userName + "@default.com",
					Avatar:      tool.HashEmail(userName + "@default.com"),
				})
				if err != nil {
					log.Error("new user failed")
					return 0, false
				}
				if db.CountUsers() == 1 {
					user.IsAdmin = true
					user.IsActive = true
					if err := db.UpdateUser(user); err != nil {
						log.Error("update user")
						return 0, false
					}
				}
			}

		}
		sess.Set("uid", user.ID)
	}

	// Check access token.
	if isAPIPath(c.Req.URL.Path) {
		tokenSHA := c.Query("token")
		if len(tokenSHA) <= 0 {
			tokenSHA = c.Query("access_token")
		}
		if len(tokenSHA) == 0 {
			// Well, check with header again.
			auHead := c.Req.Header.Get("Authorization")
			if len(auHead) > 0 {
				auths := strings.Fields(auHead)
				if len(auths) == 2 && auths[0] == "token" {
					tokenSHA = auths[1]
				}
			}
		}

		// Let's see if token is valid.
		if len(tokenSHA) > 0 {
			t, err := db.AccessTokens.GetBySHA(tokenSHA)
			if err != nil {
				if !db.IsErrAccessTokenNotExist(err) {
					log.Error("GetAccessTokenBySHA: %v", err)
				}
				return 0, false
			}
			if err = db.AccessTokens.Save(t); err != nil {
				log.Error("UpdateAccessToken: %v", err)
			}
			return t.UserID, true
		}
	}

	uid := sess.Get("uid")
	if uid == nil {
		return 0, false
	}
	if id, ok := uid.(int64); ok {
		if _, err := db.GetUserByID(id); err != nil {
			if !db.IsErrUserNotExist(err) {
				log.Error("Failed to get user by ID: %v", err)
			}
			return 0, false
		}
		return id, false
	}
	return 0, false
}

// authenticatedUser returns the user object of the authenticated user, along with two bool values
// which indicate whether the user uses HTTP Basic Authentication or token authentication respectively.
func authenticatedUser(ctx *macaron.Context, sess session.Store) (_ *db.User, isBasicAuth bool, isTokenAuth bool) {
	if !db.HasEngine {
		return nil, false, false
	}

	uid, isTokenAuth := authenticatedUserID(ctx, sess)

	if uid <= 0 {
		if conf.Auth.EnableReverseProxyAuthentication {
			webAuthUser := ctx.Req.Header.Get(conf.Auth.ReverseProxyAuthenticationHeader)
			if len(webAuthUser) > 0 {
				u, err := db.GetUserByName(webAuthUser)
				if err != nil {
					if !db.IsErrUserNotExist(err) {
						log.Error("Failed to get user by name: %v", err)
						return nil, false, false
					}

					// Check if enabled auto-registration.
					if conf.Auth.EnableReverseProxyAutoRegistration {
						u := &db.User{
							Name:     webAuthUser,
							Email:    gouuid.NewV4().String() + "@localhost",
							Passwd:   webAuthUser,
							IsActive: true,
						}
						if err = db.CreateUser(u); err != nil {
							// FIXME: should I create a system notice?
							log.Error("Failed to create user: %v", err)
							return nil, false, false
						} else {
							return u, false, false
						}
					}
				}
				return u, false, false
			}
		}

		// Check with basic auth.
		baHead := ctx.Req.Header.Get("Authorization")
		if len(baHead) > 0 {
			auths := strings.Fields(baHead)
			if len(auths) == 2 && auths[0] == "Basic" {
				uname, passwd, _ := tool.BasicAuthDecode(auths[1])

				u, err := db.Users.Authenticate(uname, passwd, -1)
				if err != nil {
					if !auth.IsErrBadCredentials(err) {
						log.Error("Failed to authenticate user: %v", err)
					}
					return nil, false, false
				}

				return u, true, false
			}
		}
		return nil, false, false
	}

	u, err := db.GetUserByID(uid)
	if err != nil {
		log.Error("GetUserByID: %v", err)
		return nil, false, false
	}
	return u, false, isTokenAuth
}

// getJwtSecret 与产业大脑生成签名秘钥的方法一致 32位的MD5加密 需要 userid
func getJwtSecret(userID string) string {
	// fmt.Println("userID", userID)
	var jwtSecret = "shengjian.net+sdaflewkffreg"
	h := md5.New()
	h.Write([]byte(userID + jwtSecret))
	return hex.EncodeToString(h.Sum(nil))
}

// 与产业大脑 RSA 解密 token 的公钥一致
var PubKey = `-----BEGIN 公钥-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDF0KvU+madkXy6Ij9RblPbFcARktp+VdIb9StULenzpfSK2PzMh+4iS3LVqTbAeMT9B+gvTEeXlcp/7vO8CaumJAQ9ID3gDpddpOTYTXMF8sMP52kAiaJzHik7idfesHNRv2N8IfM4ZlhLyydlrImJ61oEcP6WgE4xWcRqpXdBUQIDAQAB
-----END 公钥-----
`

// parseRSAToken 用公钥解密 RSA 私钥加密的方法
func parseRSAToken(token string) (string, error) {
	resultToken, err := gorsa.PublicDecrypt(token, PubKey)
	if err != nil {
		return "", err
	}
	// fmt.Println("--------------", resultToken)
	return resultToken, nil
}
