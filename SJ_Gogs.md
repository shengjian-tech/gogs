# SJ_Gogs  Update

1. ##### Modify（1）

   >取消仓库转移，删除仓库，删除仓库wiki的高危操作
   >
   >`internal/route/repo/setting.go`中仓库转移，仓库删除，删除仓库wiki等操作直接重定向到仓库页面。不做转移，删除操作。

2. ##### Modify（2）

   >去除页面登录，登出，注册按钮，改为与我们公司产业大脑业务连通自动注册，增加解析token功能，从token获取用户信息自动注册。
   >
   >主要修改为 `internal/context/auth.go`的 `authenticatedUserID()`方法，其中添加对于我们自己业务端jwttoken的解析，自动生成gogs用户等，在`internal/cmd/web.go`中注释掉注册，登出，登录等路由接口。

3. ##### Modify（3）

   >增加部分接口来适配我们自己的业务需求，新增了部分接口如下：
   >
   >- 获取用户仓库数量
   >
   >  请求路径：`"/repos/count/:name"` 
   >
   >  请求方式：`Get`
   >
   >  请求参数:`用户名（唯一）`
   >
   >  响应数据:`用户的仓库列表`
   >
   >- 用户创建仓库接口
   >
   >  请求路径：`"/repos/create/v1"` 
   >
   >  请求方式：`Get`
   >
   >  请求参数:`仓库信息`
   >
   >  响应数据:`创建仓库返回结果信息`
   >
   >- 用户fork指定仓库
   >
   >  请求路径：`"/fork/backend/:repoid"` 
   >
   >  请求方式：`Get`
   >
   >  请求参数:`仓库ID`
   >
   >  响应数据:`返回fork仓库结果`
   >- 获取设置到浏览器的Cookie数据,主要用于POST请求时，校验CSRF。
    >
   >  请求路径：`"/get/cookie?jwttoken=dada"` 
   >
   >  请求方式：`Get`
   >
   >  请求参数:`jwttoken`
   >
   >  响应数据:`返回需要设置到浏览器的Cookie数据`

4. ##### Modify（4）
> 如何进制用户强制push代码 git push -f 等操作。
> 由于Gogs就是对git服务的封装，依赖本地git服务，所以可以在Gogs服务运行的机器执行下述命令 禁止强制提交代码
> `git config --global receive.denyNonFastForwards true`