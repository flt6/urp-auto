import hashlib
import dotenv
import base64
import json
import re
import logging
from typing import List, Dict, Optional
from time import sleep,time

import requests

from bs4 import BeautifulSoup, Tag
from os import environ
import pandas as pd
from collections import deque
from datetime import datetime
from serverchan_sdk import sc_send as _sc_send

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
now = datetime.now().strftime("%Y%m%d_%H%M%S")
file = logging.FileHandler(f'logs/lessons_{now}.log', mode='w', encoding='utf-8')
file.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
file.setLevel(logging.INFO)
logger.addHandler(file)  # 日志输出到文件

class LessonsException(Exception):
    """自定义异常类"""
    pass


def sc_send(title: str, desp: str):
    if not environ.get("SC_KEY"):
        logger.error("SC_KEY 未设置，无法发送通知")
        return
    sc_key = environ.get("SC_KEY")
    try:
        _sc_send(sc_key, title, desp, options={"tags": "自动选课"})
    except Exception as e:
        logger.error(f"发送失败: {e}")

class Lessons:

    def __init__(self):
        self.session = requests.session()
        self.lessons_list: List[Dict[str, str]] = []
        self.username: Optional[str] = None
        self.term: Optional[str] = None
        self.fajhh: Optional[str] = None
        self.token: Optional[str] = None

        # 加载环境变量
        dotenv.load_dotenv()
        
        # 检查必需的环境变量
        required_keys = ["uname", "password", "recap_username", "recap_password"]
        for key in required_keys:
            if not environ.get(key):
                raise LessonsException(f"请在环境变量中设置{key}")
        
        self.base = environ.get("base", "http://jwstudent.lnu.edu.cn")

    def _retry(self, max_retries: int = 5):
        retry = 0
        def _wrapper(func, *args, **kwargs):
            nonlocal retry
            """装饰器：重试请求"""
            try:
                return func(self, *args, **kwargs)
            except Exception as e:
                logger.warning(f"重试因为 {e}")
                retry += 1
                if retry > max_retries:
                    raise LessonsException("重试次数超过限制")
                else:
                    return _wrapper(func, *args, **kwargs)
        return _wrapper
            
                

    def _retry_request(self, func, max_retries: int = 10, error_msg: str = "请求失败") -> requests.Response:
        """通用的请求重试方法"""
        for attempt in range(1, max_retries + 1):
            try:
                response = func()
                self.judge_logout(response)
                return response
            except (requests.ConnectionError, requests.HTTPError, requests.Timeout) as e:
                logger.warning(f"{error_msg}！{type(e).__name__}: {e}")
                if attempt < max_retries:
                    logger.info(f'第{attempt}次重试')
                else:
                    raise LessonsException(f"{error_msg}！请检查网络连接！")
        
        # 这行不会被执行，但为了类型检查
        raise LessonsException(f"{error_msg}！重试次数耗尽")

    @staticmethod
    def recapture(b64: str) -> str:
        """验证码识别"""
        recap_username = environ.get("recap_username")
        recap_password = environ.get("recap_password")
        
        if not recap_username or not recap_password:
            raise LessonsException("验证码识别服务配置不完整")
            
        data = {
            "username": recap_username,
            "password": recap_password,
            "ID": "04897896",
            "b64": b64,
            "version": "3.1.1"
        }
        
        try:
            response = requests.post("http://www.fdyscloud.com.cn/tuling/predict", 
                                   json=data, timeout=10)
            response.raise_for_status()
            result = response.json()
            return result["data"]["result"]
        except (requests.RequestException, KeyError, json.JSONDecodeError) as e:
            raise LessonsException(f"验证码识别失败: {e}")


    @staticmethod
    def pwd_md5(string: str) -> str:
        md5_part1 = hashlib.md5((string + "{Urp602019}").encode()).hexdigest().lower()
        md5_part2 = hashlib.md5(string.encode()).hexdigest().lower()
        final_result = md5_part1 + '*' + md5_part2
        return final_result

    # @self._r
    def _login(self):
        """登录模块"""
        username = environ.get("uname")
        password = environ.get("password")
        
        if not username or not password:
            raise LessonsException("用户名或密码未设置")
            
        self.username = username
        
        try:
            # 获取登录页面的token
            req = self.session.get("http://jwstudent.lnu.edu.cn/login")
            req.raise_for_status()
            html = req.text
            match = re.search(r'name="tokenValue" value="(.+?)">', html)
            if not match:
                raise LessonsException("未找到 tokenValue")
            token_value = match.group(1)

            # 获取验证码
            req = self.session.get(f"{self.base}/img/captcha.jpg")
            req.raise_for_status()
            im = req.content
            b64 = base64.b64encode(im).decode('utf-8')
            captcha_code = self.recapture(b64=b64)
            
            # 保存验证码图片用于调试
            # with open("captcha.jpg", "wb") as f:
            #     f.write(im)
            logger.info(f"验证码识别结果: {captcha_code}")

            hashed_password = self.pwd_md5(password)

            # 模拟请求的 payload
            payload = {
                "j_username": username,
                "j_password": hashed_password,
                "j_captcha": captcha_code,
                "tokenValue": token_value
            }

            # 发送 POST 请求
            url = f"{self.base}/j_spring_security_check"
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            response = self.session.post(url, data=payload, headers=headers)

            if "发生错误" in response.text:
                err = re.search(r'<strong>发生错误！</strong>(.+)', response.text)
                if err:
                    error_message = err.group(1).strip()
                    raise LessonsException(f"登录失败: {error_message}")
                raise LessonsException("登录失败")
                
            logger.info("登录成功")
            return True
            
        except requests.RequestException as e:
            raise LessonsException(f"登录过程中网络错误: {e}")
        
    
    def judge_logout(self, response: requests.Response):
        """检查账号是否在其他地方被登录"""
        if response.url == f"{self.base}/login?errorCode=concurrentSessionExpired":
            raise LessonsException("有人登录了您的账号！")

    def judge_choose(self, bs: BeautifulSoup):
        """判断是否可以选课"""
        alert = bs.find("div", {"class": "alert alert-block alert-danger"})
        if alert is not None:
            raise LessonsException("对不起，当前为非选课阶段！")

    def get_tokenvalue(self, bs: BeautifulSoup) -> str:
        """获取token值"""
        token_element = bs.find("input", {"type": "hidden", "id": "tokenValue"})
        if not token_element or not isinstance(token_element, Tag):
            raise LessonsException("未找到tokenValue元素")
        
        value = token_element.get("value")
        if not value:
            raise LessonsException("未找到tokenValue")
        return str(value)
    
    def get_base_info(self):
        res = self.session.get(f"{self.base}/student/courseSelect/gotoSelect/index")
        res.raise_for_status()
        html = res.text
        match = re.search(r"fajhh=(\d+)", html)
        if not match:
            print(html)
            raise LessonsException("未找到培养方案编号")
        self.fajhh = match.group(1)
        
        res = self.session.get(f"{self.base}/student/courseSelect/planCourse/index?fajhh={self.fajhh}")
        res.raise_for_status()
        html = res.text
        bs = BeautifulSoup(html, "html.parser")
        match = bs.select_one("select#jhxn option[selected]")
        if not match:
            raise LessonsException("未找到学期信息")
        self.term = str(match.get("value"))
        
        print(self.fajhh, self.term)
    
    def read_lessons(self) -> List[tuple[str, str, str]]:
        classes = []
        df = pd.read_csv("class.csv")
        df.columns = df.columns.str.strip()  # 去除列名两端的空格
        for col in ["课程号", "课序号", "课程名"]:
            if col not in df.columns:
                raise LessonsException(f"缺少必要的列: {col}")
        df = df[["课程号", "课序号", "课程名"]]
        df.columns = ["id", "kxh", "name"]  # 重命名列
        df = df.drop_duplicates(subset=["id", "kxh"])  # 去重
        for line in df.itertuples(index=False):
            classes.append((line.id, "%02d"%line.kxh, line.name))
        return classes

    def get_left(self, cl: tuple[str, list[str], str]) -> list[int]|None:
        """获取课程余量"""
        url = f"{self.base}/student/courseSelect/planCourse/courseList"
        params = {
            "fajhh": self.fajhh,
            "jhxn": self.term,
            "kcsxdm": "",
            "kch": cl[0],
            "kcm": "",
            "kxh": "",
            "kclbdm": "",
            "kzh": "",
            "xqh": "",
            "xq": 0,
            "jc": 0
        }
        response = self._retry_request(lambda: self.session.post(url, data=params))
        data = response.json()["kylMap"]
        if len(data) == 0:
            logger.error(f"课程 {cl[2]} 的余量信息为空: {data}")
            return
       
        ret = []
        for kxh in cl[1]:
            key = f"{self.term}_{cl[0]}_{kxh}"
            left = data.get(key, None)
            if left is None:
                logger.error(f"课程 {cl[2]} 的余量信息不存在: {key} not in {data.keys()}")
                ret.append(-1)
            ret.append(int(left))
        return ret
        
    def select(self,cl: tuple[str,str,str]) -> bool:
        """选课"""
        
        url = f"{self.base}/student/courseSelect/gotoSelect/index"
        response = self._retry_request(lambda: self.session.get(url))
        response.raise_for_status()
        html = response.text
        match = re.search(r'<input type="hidden" id="tokenValue" value="(.+?)"/>', html)
        if not match:
            logger.error("未找到 tokenValue")
            return False
        token = match.group(1)
        
        url = f"{self.base}/student/courseSelect/selectCourse/checkInputCodeAndSubmit"
        cms = f"{cl[2]}_{cl[1]}"
        cms = ",".join(map(lambda x:str(ord(x)),cms))
        params = {
            "dealType": 2,
            "fajhh": self.fajhh,
            "kcIds": f"{cl[0]}_{cl[1]}_{self.term}",
            "kcms": cms,
            "sj": "0_0",
            "kclbdm": "",
            "kzh": "",
            "xqh": "",
        }
        sel_data = params.copy()
        sel_data.update({"inputCode":"undefined", "tokenValue": token})
        response = self._retry_request(lambda: self.session.post(url, data=sel_data))
        response.raise_for_status()
        if response.json().get("result") != "ok":
            logger.error(f"选课时发生错误: {response}")
            return False
        
        logger.info("选课请求已发送，等待结果...")
        
        url = f"{self.base}/student/courseSelect/selectCourses/waitingfor"
        response = self._retry_request(lambda: self.session.post(url, data=params))
        response.raise_for_status()
        html = response.text
        redisKey = re.search(r'var redisKey = "(.+)";', html)
        if not redisKey:
            print(html)
            logger.error(f"选课 {cl[2]} 时未找到 redisKey")
            return False        
        redisKey = redisKey.group(1)
        
        parms = {
            "kcNum": 1,
            "redisKey": redisKey,
        }
        cnt = 1
        while cnt<=10:
            url = f"{self.base}/student/courseSelect/selectResult/query"
            response = self._retry_request(lambda: self.session.post(url, data=parms))
            response.raise_for_status()
            result = response.json()
            if result["isFinish"]:
                text = "\n".join(result["result"])
                if "已经选择了课程！" in text:
                    logger.info(f"课程 {cl[2]} 已经选上，无需重复选课")
                    return True
                if "成功" not in text:
                    logger.error(f"选课失败: {text}")
                    return False
                else:
                    logger.info(f"选课成功: {text}")
            else:
                print(f"第{cnt}次查询中...")
                cnt+=1
                sleep(1)
        
        logger.warning(f"选课 {cl[2]} 结果查询超时，可能未成功选课")
        return False
    
    def login(self):
        logger.info("尝试登录")
        flag = False
        for i in range(10):
            try:
                if self._login():
                    flag = True
                    break
            except Exception as e:
                logger.error(f"登录失败: {e}")
        if not flag:
            raise LessonsException("登录失败，无法获取token")
    
    def auto_spider(self):
        """自动选课主程序"""
        try:
            self.login()
            logger.info("获取基础信息")
            self.get_base_info()
            classes_src = self.read_lessons()
            classes:dict[str,tuple[str,list[str],str]] = {}
            mp:dict[str,str] = {} # {"课程号": "课程名称"}
            for id, kxh, name in classes_src:
                mp[id] = name
                if classes.get(id) is None:
                    classes[id] = (id, [kxh], name)
                else:
                    classes[id][1].append(kxh)
            
            logger.info(f"读取课程信息，共有 {len(classes)} 门课程")
            for cl in classes.values():
                logger.info(f"课程 {cl[2]} ({cl[0]}) 的可选课序号: {', '.join(cl[1])}")
            
            logger.info("开始自动选课")
            
            errs = deque(maxlen=5)
            master_err = 0
            while classes:
                suc = []
                if len(errs) == 5 and errs[0] - time() < 20:
                    logger.error("最近5次获取课程余量异常，尝试重新登录")
                    sc_send("选课异常", desp="最近5次获取课程余量异常，尝试重新登录")
                    self.login()
                    master_err += 1
                if master_err >= 3:
                    logger.error("反复发生重要异常，退出程序")
                    sc_send("选课异常", desp="反复发生重要异常，退出程序")
                    return
                for lcl in classes.copy().values():
                    logger.info(f"检查课程 {lcl[2]} 余量")
                    try:
                        lefts = self.get_left(lcl)
                        if lefts is None:
                            errs.appendleft(time())
                            logger.error(f"获取课程 {lcl[2]} 余量时返回异常")
                            continue
                    except Exception as e:
                        errs.appendleft(time())
                        logger.error(f"获取课程 {lcl[2]} 余量时发生错误: {e}")
                        continue
                    for i,left in enumerate(lefts):
                        cl = (lcl[0], lcl[1][i], lcl[2])
                        if left > 0:
                            logger.info(f"课程 {cl[2]}_{cl[1]} 有余量: {left}，开始选课")
                            try:
                                ret = self.select(cl)
                                if ret:
                                    suc.append(cl)
                                    classes.pop(cl[0])
                                    break
                            except Exception as e:
                                errs.appendleft(time())
                                logger.error(f"选课 {cl[2]}_{cl[1]} 时发生错误: {e}")
                            finally:
                                sleep(2)  # 避免请求过快导致服务器拒绝
                        elif left == -1:
                            logger.error(f"课程 {cl[2]}_{cl[1]} 余量信息异常")
                        else:
                            logger.info(f"课程 {cl[2]}_{cl[1]} 无余量")
                    sleep(2)
                logger.info(f"当前还有{len(classes)}门课程未选上，分别为{','.join(mp[i] for i in classes.keys())}。等待10秒后继续检查")
                if suc:
                    sc_send("选课成功", desp=f"已成功选上课程: {', '.join(f'{i[2]}_{i[1]}' for i in suc)}")
                sleep(10)  # 等待10秒后继续检查
            
                    
            logger.info("自动选课完成")
            
        except LessonsException as e:
            logger.error(f"选课过程中发生错误: {e}")
            sc_send("选课异常", desp=f"选课过程中发生错误: {e}")
            raise e
        except Exception as e:
            logger.error(f"意外错误: {e}")
            sc_send("选课异常", desp=f"选课过程中发生意外错误: {e}")
            raise e

if __name__ == "__main__":
    les = Lessons()
    les.auto_spider()