# fileapp

> 一个简易的文件中转系统



## 支持功能

1. 用户认证：默认账号 admin/cnsec2024
2. 支持向内部区域上传TXT文件
3. 支持从内部区域发送文件到公开区域
4. 支持对接DLP应用检测系统，在对接DLP菜单中填写UCWI相关IP信息和认证信息
   - 仅支持webserviceapp文件同步送审接口
   - 当未命中策略时，内部区域文件正常发送到公开区域
   - 当命中策略，并且actioncode等于1时，弹出告警信息，文件正常发送
   - 当命中策略，并且cationcode等于2时，弹出告警信息，禁止文件发送



## 如何运行

```
streamlit run app-logic.py
```

