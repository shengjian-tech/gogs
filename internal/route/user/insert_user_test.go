package user

import (
	"fmt"
	"strings"
	"testing"

	"gogs.io/gogs/internal/conf"
	"gogs.io/gogs/internal/db"
	"gogs.io/gogs/internal/tool"
	"xorm.io/xorm"
)

func Test_Insert_User(t *testing.T) {
	connStr := fmt.Sprintf("%s:%s@tcp(%s)/%s%scharset=utf8mb4&parseTime=true",
		"root", "1234", "192.168.32.130", "gogs", "?")
	var engineParams = map[string]string{"rowFormat": "DYNAMIC"}
	e, err := xorm.NewEngineWithParams("mysql", connStr, engineParams)
	if err != nil {
		fmt.Println("NewEngineWithParams failed ", err.Error())
		return
	}
	// 建立 mysql 连接

	u := &db.User{
		Name:     "admin",
		Email:    "120@qq.com",
		Passwd:   "123456",
		IsActive: !conf.Auth.RequireEmailConfirmation,
		ChanyeId: "u_10001",
	}
	u.Email = strings.ToLower(u.Email)
	u.LowerName = strings.ToLower(u.Name)
	u.AvatarEmail = u.Email
	u.Avatar = tool.HashEmail(u.AvatarEmail)
	if u.Rands, err = db.GetUserSalt(); err != nil {
		fmt.Println("GetUserSalt failed", err.Error())
		return
	}
	if u.Salt, err = db.GetUserSalt(); err != nil {
		fmt.Println("GetUserSalt failed", err.Error())
		return
	}
	u.EncodePassword()
	u.MaxRepoCreation = -1

	sess := e.NewSession()
	defer sess.Close()
	if err = sess.Begin(); err != nil {
		fmt.Println("sess.Begin failed", err.Error())
		return
	}

	if _, err = sess.Insert(u); err != nil {
		fmt.Println("sess.insert failed", err.Error())
		return
	}

	sess.Commit()
	// Auto-set admin for the only user.
	count, _ := e.Where("type=0").Count(new(db.User))
	if count == 1 {
		u.IsAdmin = true
		u.IsActive = true
		// Organization does not need email
		if !u.IsOrganization() {
			u.Email = strings.ToLower(u.Email)
			has, err := e.Where("id!=?", u.ID).And("type=?", u.Type).And("email=?", u.Email).Get(new(db.User))
			if err != nil {
				fmt.Println("Organization does not need email,", err.Error())
				return
			} else if has {
				fmt.Println("Organization has not need email,", err.Error())
				return
			}
			if len(u.AvatarEmail) == 0 {
				u.AvatarEmail = u.Email
			}
			u.Avatar = tool.HashEmail(u.AvatarEmail)
		}

		u.LowerName = strings.ToLower(u.Name)
		u.Location = tool.TruncateString(u.Location, 255)
		u.Website = tool.TruncateString(u.Website, 255)
		u.Description = tool.TruncateString(u.Description, 255)

		_, err := e.ID(u.ID).AllCols().Update(u)
		if err != nil {
			fmt.Println("Update failed", err.Error())
			return
		}
	}

}
