# deepsider2api-deno
deepsider2api deno脚本，支持将扩展deepsider api转换成openai标准格式，支持流式响应和获取模型列表请求
# 如何部署
首先点个star，fork该项目
访问deno.com，使用github注册并登陆
在dash.deno.com中
点击project从github中导入该项目
部署时，只需填写下面几项
```
Install Step
deno install -gArf jsr:@deno/deployctl
Build Step
deployctl deploy
Entrypoint
main.ts
```
其他不用填写，点击Deploy Project进行部署
返回fork的项目仓库，点击action，点击正在运行的deploy action，进入后点开授权地址，授权deno后即可部署完成。
# 如何使用
部署地址/v1/models即可获取模型列表
部署地址/v1/chat/completions可进行聊天请求，传入令牌token，支持多个token传入，用逗号分隔，比如:
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.1,eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.2,…`
脚本会根据传入的key进行随机轮询
# token获取方式
F12进入devtool中，找到网络，进行一次对话，在网络日志conversation中即可看到token信息
