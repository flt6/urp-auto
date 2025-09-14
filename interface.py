import streamlit as st
from pathlib import Path
import subprocess
import streamlit_autorefresh
import hashlib
import json
import uuid
import shutil

tokenFile = Path("tokens.json")
PASSWORD_HASH = "*****"  # md5 of the password
URL_PREFIX = "https://******/urp"


def verify():
    pwd = st.text_input("请输入密码", type="password")
    if st.button("确认"):
        if hashlib.md5(pwd.encode("utf-8")).hexdigest() != PASSWORD_HASH:
            st.error("密码错误")
            st.stop()
        else:
            st.session_state["verified"] = True
            st.rerun()
        

def main():
    st.title("抢课管理")
    prefix = st.text_input("Prefix","1")
    prefix = Path(prefix)
    if not prefix.exists():
        st.error("路径不存在")
        if st.button("创建路径"):
            (prefix/Path("logs")).mkdir(exist_ok=True, parents=True)
            (prefix/Path("class.csv")).touch()
            shutil.copyfile("main.py", prefix/Path("main.py"))
            shutil.copyfile(".env", prefix/Path(".env"))
            cmd = [
                "pm2", "start", "python3", "--name", "urp_"+prefix.name,
                "--", "-m", "streamlit", "run", "main.py",
                "--no-autorestart"
            ]
            subprocess.run(cmd, cwd=prefix)
            cmd = [
                "pm2", "stop", "urp_"+prefix.name
            ]
            subprocess.run(cmd, cwd=prefix)
            st.success("创建成功")
            st.rerun()
        st.stop()
    if st.button("开始抢课"):
        subprocess.run(
            f"pm2 start urp_{prefix.name}".split()
        )
        st.success("抢课线程已启动，请勿重复点击")
    if st.button("停止抢课"):
        subprocess.run(
            f"pm2 stop urp_{prefix.name}".split()
        )
        st.success("抢课线程已停止，请勿重复点击")
    logs = (prefix/Path("logs")).glob("*.log")
    sorted_logs = sorted(logs, key=lambda x: x.stat().st_ctime, reverse=True)
    if not sorted_logs:
        st.warning("暂无日志")
    else:
        st.code(sorted_logs[0].read_text(encoding="utf-8"),"log")
    ansFile = prefix/Path("answers.txt")
    if ansFile.exists():
        answer = st.text_area("答案", ansFile.read_text())
    else:
        answer = st.text_area("答案, 每行一个答案, 按顺序填写")

    st.slider("rerun间隔", min_value=1.0, value=5.0,max_value=10.0, step=0.1, key="rerun_interval")
    if st.button("保存答案"):
        ansFile.write_text(answer)
        st.success("答案保存成功, 请刷新页面")
    
    with st.expander("修改配置"):
        envfile = prefix/Path(".env")
        env = st.text_area(".env", envfile.read_text(), height=200)
        classfile = prefix/Path("class.csv")
        classes = st.text_area("class.csv", classfile.read_text(), height=200)
        if st.button("保存配置"):
            envfile.write_text(env)
            classfile.write_text(classes)
            st.success("保存成功, 请刷新页面")
            st.rerun()
    st.markdown("---\n### 其他日志")
    for file in sorted_logs:
        with st.expander(file.name):
            st.code(file.read_text(encoding="utf-8"),"log")
    
    if st.button("创建token"):
        tokens = {}
        if tokenFile.exists():
            tokens = json.loads(tokenFile.read_text(encoding="utf-8"))
        new_token = uuid.uuid4().hex
        tokens[new_token] = str(prefix.resolve())
        tokenFile.write_text(json.dumps(tokens), encoding="utf-8")
        st.success(f"创建成功, {URL_PREFIX}?token={new_token}")
        
    

def user(_prefix: str):
    prefix = Path(_prefix)
    st.title("抢课信息展示")
    st.markdown(f"## 实时日志")
    logs = (prefix/Path("logs")).glob("*.log")
    sorted_logs = sorted(logs, key=lambda x: x.stat().st_ctime, reverse=True)
    st.code(sorted_logs[0].read_text(encoding="utf-8"),"log")
    st.markdown("---\n### 历史运行日志")
    for file in sorted_logs:
        with st.expander(file.name):
            st.code(file.read_text(encoding="utf-8"),"log")
    st.slider("刷新间隔（s）", min_value=1.0, value=5.0,max_value=10.0, step=0.1, key="rerun_interval")

if __name__ == "__main__":
    param = st.query_params.get("token", None)
    if tokenFile.exists() and param is not None:
        tokens:dict[str,str] = json.loads(tokenFile.read_text(encoding="utf-8"))
        if param not in tokens.keys():
            st.error("token无效")
        else:
            assert param is not None
            streamlit_autorefresh.st_autorefresh(st.session_state.get("rerun_interval", 5)*1000)
            prefix = tokens[param]
            user(prefix)
            st.stop()
        
    if not st.session_state.get("verified", False):
        verify()
        st.stop()
    streamlit_autorefresh.st_autorefresh(st.session_state.get("rerun_interval", 5)*1000)
    main()
    