import streamlit as st
from datetime import datetime
import requests
import time
import hmac
import hashlib
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import uuid
import json
import io



# 初始化会话状态
if 'file_content_public' not in st.session_state:
    st.session_state['file_content_public'] = {"content": "", "filename": "", "uploaded_at": ""}
if 'ucwi_credentials' not in st.session_state:
    st.session_state['ucwi_credentials'] = {
        "ip_address": "",
        "port": "",
        "app_id": "",
        "access_key": "",
        "secret_key": ""
    }

if 'http_response' not in st.session_state:
    st.session_state['http_response'] = ""

if 'incident_info' not in st.session_state:
    st.session_state['incident_info'] = ""

if 'action_code' not in st.session_state:
    st.session_state['action_code'] = ""


def ucwi_credentials_form():
    st.header("UCWI认证信息")

    ip_address = st.text_input("IP地址", value=st.session_state['ucwi_credentials']['ip_address'])
    port = st.number_input("端口", value=int(st.session_state['ucwi_credentials']['port']) if
    st.session_state['ucwi_credentials']['port'] else 0)
    app_id = st.text_input("Webservices Id", value=st.session_state['ucwi_credentials']['app_id'])
    access_key = st.text_input("Access Key", value=st.session_state['ucwi_credentials']['access_key'])
    secret_key = st.text_input("Secret Key", value=st.session_state['ucwi_credentials']['secret_key'])

    if st.button("保存认证信息"):
        st.session_state['ucwi_credentials'] = {
            "ip_address": ip_address,
            "port": str(port),
            "app_id": app_id,
            "access_key": access_key,
            "secret_key": secret_key
        }
        st.success("认证信息已保存")


def get_auth(access_key, secret_key, timestamp):
    token_source = secret_key + timestamp
    token = hmac.new(
        secret_key.encode('utf-8'),
        token_source.encode('utf-8'),
        hashlib.sha256).hexdigest()
    return "SKG {0}:{1}".format(access_key, token)


def get_headers():
    timestamp = "{0:.0f}".format(time.time())
    auth = get_auth(
        st.session_state['ucwi_credentials']['access_key'],
        st.session_state['ucwi_credentials']['secret_key'],
        timestamp)

    headers = {
        "X-Skg-Timestamp": timestamp,
        "authorization": auth,
    }
    return headers

def send_to_ucwi(file_content, filename):
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    url = f"https://{st.session_state['ucwi_credentials']['ip_address']}:{st.session_state['ucwi_credentials']['port']}/skg/v1/dlp/channel/cloudapp/{st.session_state['ucwi_credentials']['app_id']}/sync"
    #print(url)
    headers = get_headers()
    metadata = {
        "user": "cnsec_jizhiming",
        # "filename": "mimi.txt",
        "queryID": str(uuid.uuid4()),
        # "md5": "e569660a0bc41a34d7d7aa12cb29feac",
        "operation": 1,
        # "antivirus": True,
        # "encoding": "UTF-8",
    }
    data = {"metadata": json.dumps(metadata)}

    # 将文件内容转换为BytesIO对象，模拟文件上传
    #file_like_object = io.BytesIO(file_content.encode('utf-8'))
    files = {'request': (filename, file_content, 'text/plain')}  # 文件名，文件内容，MIME类型

    try:
        response = requests.post(url, data=data, headers=headers, files=files,verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        st.error(f"请求UCWI时发生错误,未正常响应: {e}")
        return ""

def process_http_response(response_text):
    try:
        response_json = json.loads(response_text)
        incident_info = response_json.get("incident_info")
        st.session_state['incident_info'] = incident_info
        #print(incident_info)

        #if incident_info is None:
        if len(incident_info) == 0:
            st.success("UCWI：外发文件无敏感内容")
            # 直接COPY文件到公开区域的逻辑应在此处实现，但基于现有代码结构，该部分逻辑已在update_public_content中处理。

        else:
            # 增加风险分析展示区域
            st.warning("UCWI：外发文件存在敏感内容，触发策略")

            action_code = response_json.get("actionCode")
            st.session_state['action_code'] = action_code
            policy_name = incident_info.get("matchedPolicies")[0]["name"]
            severity = incident_info.get("matchedPolicies")[0]["severity"]
            if severity ==1:
                severity = "高"
            elif severity == 2:
                severity = "中"
            elif severity == 3:
                severity = "低"
            elif severity == 4:
                severity = "信息"

            actionSettingName = incident_info.get("matchedPolicies")[0]["actionSettingName"]
            numberOfMatches = incident_info.get("matchedPolicies")[0]["numberOfMatches"]
            st.write(f"- 策略名称: {policy_name}")
            st.write(f"- 策略安全等级: {severity}")
            st.write(f"- 策略动作: {actionSettingName}")
            st.write(f"- 命中规则数: {numberOfMatches}")

            #if strategy_name:
                #st.write(f"- 策略名称: {strategy_name}")
                #st.write(f"- 策略危险等级: {severity}")

            if action_code == 2:
                st.error("文件中转系统：外发文件存在敏感内容，禁止发送")
            elif action_code == 1:
                st.warning("文件中转系统：外发文件可能存在风险，外发动作已被平台审计")

            # 实现存储策略到下拉框的逻辑需要前端界面的调整，此处简化处理仅展示信息。

    except json.JSONDecodeError:
        st.error("无法解析UCWI的响应为JSON格式")



def update_public_content(file_content, filename):
    """更新公开区域的文件内容，如果UCWI认证信息完整则同时发送到UCWI"""
    # 更新公开区域的文件内容
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state['file_content_public'] = {
        "content": file_content,
        "filename": filename,
        "uploaded_at": now
    }

    # 检查ucwi_credentials是否全部填写
    if all(st.session_state['ucwi_credentials'].values()):
        response_text = send_to_ucwi(file_content, filename)
        st.session_state['http_response'] = response_text

        process_http_response(response_text)


        if not st.session_state['incident_info'] or st.session_state['action_code'] == 1:
            #st.success("内容已上传到公开区域并发送至UCWI:外发文件无敏感内容")
            st.success("文件流转系统：内容已上传到公开区域")
        else:
            st.session_state['file_content_public'] = {
                "content": '',
                "filename": '',
                "uploaded_at": ''
            }

    else:
        st.success("内容已上传到公开区域")


def private_area():
    st.header("内部区域")

    uploaded_file = st.file_uploader("上传TXT文件", type=['txt'])

    if uploaded_file is not None:
        file_content = uploaded_file.read().decode('utf-8')
        st.text_area("文件预览", value=file_content, height=300)
        filename = uploaded_file.name

        if st.button("上传到公开区域"):
            update_public_content(file_content, filename)

            #如果UCWI认证信息未填写完整，这部分不进行显示
            if all(st.session_state['ucwi_credentials'].values()):

                # 构造HTTP请求的展示文本
                request_details = (
                    f"URL: https://{st.session_state['ucwi_credentials']['ip_address']}:{st.session_state['ucwi_credentials']['port']}\n"
                    f"Method: POST\n"
                    f"Headers:\n"
                    f"  - access_key: {st.session_state['ucwi_credentials']['access_key']}\n"
                    f"  - secret_key: {st.session_state['ucwi_credentials']['secret_key']}\n"
                    f"Payload:\n"
                    f"  - filename: {filename}\n"
                    f"  - content: {file_content[:50]}... (truncated for preview)"
                )

                # 使用expander组件创建一个可折叠的HTTP请求展示区域
                with st.expander("HTTP Requests", expanded=False):
                    st.code(request_details, language='plaintext')

                with st.expander("HTTP Response", expanded=False):
                    st.code(st.session_state['http_response'], language='plaintext')


def public_area():
    st.header("公开区域")

    content_info = st.session_state['file_content_public']

    if content_info["content"]:
        st.write(f"**文件名:** {content_info['filename']}")
        st.write(f"**上传时间:** {content_info['uploaded_at']}")
        st.text_area("文件内容预览", value=content_info["content"], height=300)


def login():
    """用户认证函数"""
    st.title("文件流转平台")

    # 写死的用户名和密码
    correct_username = "admin"
    correct_password = "cnsec2024"

    username = st.text_input("用户名")
    password = st.text_input("密码", type="password")

    if st.button("登录"):
        if username == correct_username and password == correct_password:
            st.success("登录成功!")
            # 设置一个会话状态表示已登录，这样就可以控制页面访问权限了
            st.session_state['logged_in'] = True
            # 登录成功后，可以重定向到内部区域，这里使用 Streamlit 的 experimental_rerun 函数
            #import streamlit as st
            st.experimental_rerun()
        else:
            st.error("用户名或密码错误，请重试。")




# 修改main函数以包含登录逻辑
def main():
    # 初始化会话状态，添加登录状态
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False

    # 如果用户未登录，则显示登录表单
    if not st.session_state['logged_in']:
        login()
    else:
        #st.set_page_config(layout="wide")

        tabs = ["对接DLP", "公开区域", "内部区域"]
        choice = st.sidebar.radio("菜单", tabs)

        if choice == "对接DLP":
            ucwi_credentials_form()
        elif choice == "内部区域":
            private_area()
        else:
            public_area()

if __name__ == "__main__":
    main()