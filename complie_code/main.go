package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/tjfoc/gmsm/sm3"
	"github.com/xuperchain/contract-sdk-go/code"
	"github.com/xuperchain/contract-sdk-go/driver"
)

type counter struct{}

func (c *counter) Initialize(ctx code.Context) code.Response {
	return code.OK(nil)
}

func main() {
	driver.Serve(new(counter))
}

func (s *counter) PullCodeComplie(ctx code.Context) code.Response {
	var err error
	userName := string(ctx.Args()["userName"])
	repoName := string(ctx.Args()["repoName"])
	address := string(ctx.Args()["gitAddr"])
	branch := string(ctx.Args()["branch"])
	commitID := string(ctx.Args()["commitID"])

	contractName := string(ctx.Args()["contractName"])
	if strings.TrimSpace(address) == "" {
		ctx.Logf("address can not empty")
		return code.Errors("address can not empty")
	}
	// 不传入分支名  默认 分支名为 master 或者 main
	if strings.TrimSpace(branch) == "" {
		branch = "master"
	}
	// clone 的代码就存入一个临时文件夹 无论成功失败  删除临时文件夹
	repoPath := "/tmpcode/" + userName + "/" + repoName
	/*defer func(repoPath string) {
		os.RemoveAll(repoPath)
	}(repoPath)*/
	//被克隆的目录不存在
	_, err = os.Stat(repoPath)
	if os.IsNotExist(err) {
		pullCodeCmdStr := fmt.Sprintf("git clone -b %s %s %s", branch, address, repoPath)
		// git clone 指定地址，分支的合约代码
		pullCodeCmd := exec.Command("sh", "-c", pullCodeCmdStr)
		err = pullCodeCmd.Run()
		if err != nil {
			ctx.Logf("git clone contract code failed %s %s", err.Error(), address)
			return code.Error(err)
		}

		// 判断 commitID 是否为空 不为空 reset 到指定的 commitID
		if strings.TrimSpace(commitID) != "" {
			checkoutCommitCmd := exec.Command("sh", "-c", "cd "+repoPath+"&&"+" git checkout "+commitID)
			err = checkoutCommitCmd.Run()
			if err != nil {
				ctx.Logf("check out the commit failed %s", err.Error())
				return code.Error(err)
			}
		}
	}

	//编译后的文件是否存在
	var path = "/xuperchain/data/contract/" + userName + "/" + repoName
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		// TODO编译代码为二进制文件，目前先支持 golang的 native。其他后续支持
		buildCmd := exec.Command("sh", "-c", "cd "+repoPath+"&&"+"go build -o "+repoName)
		err = buildCmd.Run()
		if err != nil {
			ctx.Logf("build contract failed %s", err.Error())
			return code.Error(err)
		}

		// 判断移动到的目录是否存在，不存在直接创建
		/*if err == nil {
			// 清空该目录下的所有文件
			removeCmd := exec.Command("sh", "-c", " rm -rf "+path+"/*")
			err = removeCmd.Run()
			if err != nil {
				ctx.Logf("rm -rf contract exec failed %s", err.Error())
				return code.Error(err)
			}
		}*/
		err = os.MkdirAll(path, os.ModePerm)
		if err != nil {
			ctx.Logf("mkdir failed %s", err.Error())
			return code.Error(err)
		}
		// 移动编译好的文件到指定目录
		mvCmd := exec.Command("sh", "-c", " mv "+repoPath+"/"+repoName+"  "+path+"/")
		err = mvCmd.Run()
		if err != nil {
			ctx.Logf("mv contract failed %s", err.Error())
			return code.Error(err)
		}
	}
	// 取md5值
	pFile, err := os.Open(path + "/" + repoName)
	if err != nil {
		ctx.Logf("open file failed %s", err.Error())
		return code.Error(err)
	}
	defer pFile.Close()
	sm3B, err := ioutil.ReadAll(pFile)
	if err != nil {
		ctx.Logf("file sm3 failed %s", err.Error())
		return code.Error(err)
	}
	md5Str := hex.EncodeToString(sm3.Sm3Sum(sm3B))

	//返回值
	var rsp = make(map[string]string)
	rsp["md5"] = md5Str
	rsp["path"] = path + "/" + repoName
	b, err := json.Marshal(rsp)
	if err != nil {
		ctx.Logf("json marshal rsp failed %s", err.Error())
		return code.Error(err)
	}
	// TODO put md5 到 合约信息中
	ctx.Logf("md5Str======= %s", md5Str)
	ctx.Logf("rsp['path']======= %s", rsp["path"])
	err = ctx.PutObject([]byte(contractName+"_hash"), []byte(md5Str))
	if err != nil {
		ctx.Logf("json marshal rsp failed %s", err.Error())
		return code.Error(err)
	}
	err = ctx.PutObject([]byte(contractName+"_path"), []byte(rsp["path"]))
	if err != nil {
		ctx.Logf("json marshal rsp failed %s", err.Error())
		return code.Error(err)
	}
	return code.OK(b)
}
func (s *counter) Get(ctx code.Context) code.Response {
	contractName := string(ctx.Args()["contractName"])
	if contractName == "" {
		ctx.Logf("failed! contractName is nil!")
		return code.Errors("failed! contractName is nil!")
	}
	_hash, err := ctx.GetObject([]byte(contractName + "_hash"))
	if err != nil {
		ctx.Logf("get failed")
		return code.Error(err)
	}
	_path, err := ctx.GetObject([]byte(contractName + "_path"))
	if err != nil {
		ctx.Logf("get failed")
		return code.Error(err)
	}
	//返回数据
	returnMap := make(map[string]string)
	returnMap[contractName+"_hash"] = string(_hash)
	returnMap[contractName+"_path"] = string(_path)
	b, err := json.Marshal(returnMap)
	if err != nil {
		ctx.Logf("json.Marshal failed")
		return code.Error(err)
	}
	return code.OK(b)
}
