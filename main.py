import base64
import hashlib
import json
import logging
import re
from collections import deque
from datetime import datetime
from os import environ
from pathlib import Path
from time import sleep, time
from typing import Callable, List, Optional

import dotenv
import pandas as pd
import requests
from serverchan_sdk import sc_send as _sc_send

# 配置日志
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

Path("logs").mkdir(exist_ok=True)  # 确保日志目录存在
now = datetime.now().strftime("%Y%m%d_%H%M%S")
file = logging.FileHandler(f"logs/lessons_{now}.log", mode="w", encoding="utf-8")
file.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
file.setLevel(logging.INFO)
logger.addHandler(file)  # 日志输出到文件


class LessonsException(Exception):
    """自定义异常类"""
    pass
class ReloginException(LessonsException):
    """用于处理需要重新登录的异常"""
    pass

class QuestionException(LessonsException):
    """用于处理答题相关的异常"""
    pass
class WaitException(Exception):
    "需要进一步等待"
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

    def __init__(self,dotenv_path: Optional[Path] = None, dangerously_disable_init: bool = False):
        self.session = requests.session()
        self.term: Optional[str] = None
        self.fajhh: Optional[str] = None
        self.waitcount = 0

        # 加载环境变量
        if not dangerously_disable_init:
            dotenv.load_dotenv(dotenv_path)

            # 检查必需的环境变量
            required_keys = [
                "uname",
                "password",
                "recap_username",
                "recap_password",
                "FILE",
            ]
            for key in required_keys:
                if not environ.get(key):
                    raise LessonsException(f"请在环境变量中设置{key}")

        self.base = environ.get("base", "http://jwstudent.lnu.edu.cn")
        self.interval_1 = int(environ.get("INTERVAL_1", 2))  # 请求间隔，默认为2秒
        self.interval_2 = int(environ.get("INTERVAL_2", 10))  # 请求间隔，默认为10秒

    def _retry_request(
        self, func, max_retries: int = 10, error_msg: str = "请求失败"
    ) -> requests.Response:
        """通用的请求重试方法"""
        for attempt in range(1, max_retries + 1):
            try:
                response = func()
                self.judge_logout(response)
                return response
            except (
                requests.ConnectionError,
                requests.HTTPError,
                requests.Timeout,
            ) as e:
                logger.warning(f"{error_msg}！{type(e).__name__}: {e}")
                if attempt < max_retries:
                    logger.info(f"第{attempt}次重试")
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
            "version": "3.1.1",
        }

        try:
            response = requests.post(
                "http://www.fdyscloud.com.cn/tuling/predict", json=data, timeout=10
            )
            response.raise_for_status()
            result = response.json()
            return result["data"]["result"]
        except (requests.RequestException, KeyError, json.JSONDecodeError) as e:
            raise LessonsException(f"验证码识别失败: {e}")

    @staticmethod
    def pwd_md5(string: str) -> str:
        first_md5 = hashlib.md5((string + "{Urp602019}").encode()).hexdigest().lower()
        md5_part1 = hashlib.md5((first_md5).encode()).hexdigest().lower()
        
        password_with_salt = hashlib.md5((string).encode()).hexdigest().lower()
        md5_part2 = hashlib.md5((password_with_salt).encode()).hexdigest().lower()
        final_result = md5_part1 + "*" + md5_part2
        return final_result

    def _login(self):
        """登录模块"""
        username = environ.get("uname")
        password = environ.get("password")

        if not username or not password:
            raise LessonsException("用户名或密码未设置")

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
            b64 = base64.b64encode(im).decode("utf-8")
            captcha_code = self.recapture(b64=b64)

            logger.info(f"验证码识别结果: {captcha_code}")

            hashed_password = self.pwd_md5(password)

            # 模拟请求的 payload
            payload = {
                "j_username": username,
                "j_password": hashed_password,
                "j_captcha": captcha_code,
                "tokenValue": token_value,
            }

            # 发送 POST 请求
            url = f"{self.base}/j_spring_security_check"
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = self.session.post(url, data=payload, headers=headers)

            if "发生错误" in response.text:
                err = re.search(r"<strong>发生错误！</strong>(.+)", response.text)
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
            raise ReloginException("有人登录了您的账号！")

    @staticmethod
    def extract_questions_and_answers(html_content):
        """提取题目ID和答案选项"""
        results = []
        
        question_pattern = r'<input type="hidden"\s+id="([^"]+)">([^<]+)'
        questions = re.findall(question_pattern, html_content)
        
        for question_id, question_text in questions:
            question_text = question_text.strip()
            
            answer_pattern = rf'name="{re.escape(question_id)}"[^>]+value="([^"]+)"[^>]*>\s*<span[^>]*class="lbl">([^<]+)</span>'
            answers = re.findall(answer_pattern, html_content)
            
            results.append({
                'id': question_id,
                'question': question_text,
                'answers': {value: text.strip() for value, text in answers}
            })
        
        return results

    def get_base_info(self):
        res = self.session.get(f"{self.base}/student/courseSelect/courseSelect/index")
        res.raise_for_status()
        html = res.text
        # html = Path("test.html").read_text("utf-8")
        if "对不起，当前为非选课阶段！" in html:
            raise WaitException("当前为非选课阶段！")
        if "/student/courseSelect/viewSelectCoursePaper/checkDa" in html:
            # 答题
            # debugging
            questions = self.extract_questions_and_answers(html)
            ansFile = Path("answers.txt")
            if not ansFile.exists():
                logger.error("需要答题")
                quetxt = []
                for que in questions:
                    t = ""
                    t += f"题目: {que['question']}\n"
                    for value, text in que['answers'].items():
                        t+=f"  {value}: {text}\n"
                    quetxt.append(t)
                logger.info("\n-----------\n".join(quetxt))
                sc_send("需要答题","\n-----------\n".join(quetxt))
                raise QuestionException("需要答题"+"\n-----------\n".join(quetxt))
            ans = ansFile.read_text().splitlines()
            if len(ans) != len(questions):
                raise QuestionException("答案与题目不匹配")
            l = []
            for i in range(len(ans)):
                l.append(questions[i]["id"]+"@"+ans[i].strip())
            logger.debug("答题  -  "+"info="+",".join(l))
            res = self.session.post(f"{self.base}/student/courseSelect/viewSelectCoursePaper/checkDa",
                              data={"info": ",".join(l)},  # 使用字典格式
                              headers={
                                  'Content-Type': 'application/x-www-form-urlencoded'
                              })
            res.raise_for_status()
            ret = res.json()
            if ret["result"] != "ok":
                logger.error("答题失败",ret["result"])
                raise ReloginException("重启")

        res = self.session.get(f"{self.base}/student/courseSelect/gotoSelect/index")
        res.raise_for_status()
        html = res.text
        match = re.search(r"fajhh=(\d+)", html)
        if not match:
            # print(html)
            raise LessonsException("未找到培养方案编号")
        self.fajhh = match.group(1)

        res = self.session.get(
            f"{self.base}/student/courseSelect/planCourse/index?fajhh={self.fajhh}"
        )
        res.raise_for_status()
        html = res.text
        # 使用正则表达式替代 BeautifulSoup 来查找选中的学期选项
        # 由于 HTML 结构特殊，selected 在单独行上，需要向前查找对应的 option
        lines = html.split('\n')
        for i, line in enumerate(lines):
            if 'selected' in line.strip():
                # 向前查找包含 option value 的行
                for j in range(i-1, max(0, i-10), -1):
                    if 'option value=' in lines[j]:
                        value_match = re.search(r'value="([^"]*)"', lines[j])
                        if value_match:
                            self.term = str(value_match.group(1))
                            break
                if self.term:
                    break
        
        if not self.term:
            raise LessonsException("未找到学期信息")

        # print(self.fajhh, self.term)

    def read_lessons(self,df:Optional[pd.DataFrame]=None) -> List[tuple[str, str, str]]:
        classes = []
        if df is None:
            file = Path(environ.get("FILE", "class.xlsx"))
            if not file.is_file():
                raise LessonsException(f"课程文件 {file} 不存在，请检查路径")
            d: dict[str, Callable[[Path], pd.DataFrame]] = {
                ".csv": pd.read_csv,
                ".xlsx": pd.read_excel,
                ".xls": pd.read_excel,
                ".json": pd.read_json,
            }
            func = d.get(file.suffix.lower())
            if func is None:
                raise LessonsException(
                    f"不支持的文件格式: {file.suffix}. 仅支持 .csv, .xlsx, .xls, .json 格式"
                )
            df = func(file)
        df.columns = df.columns.str.strip()  # 去除列名两端的空格
        for col in ["课程号", "课序号", "课程名"]:
            if col not in df.columns:
                raise LessonsException(f"缺少必要的列: {col}")
        df = df[["课程号", "课序号", "课程名"]]
        df.columns = ["id", "kxh", "name"]  # 重命名列
        df = df.drop_duplicates(subset=["id", "kxh"])  # 去重
        for line in df.itertuples(index=False):
            classes.append((line.id, "%02d" % line.kxh, line.name))
        return classes

    def get_left(self, cl: tuple[str, list[str], str]) -> list[int] | None:
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
            "jc": 0,
        }
        response = self._retry_request(lambda: self.session.post(url, data=params))
        with open("response.json", "w", encoding="utf-8") as f:
            f.write(response.text)
        data:dict = response.json()
        
        cls:list[dict] = data.get("rwfalist", [])
        if not cls:
            logger.error(f"课程 {cl[2]} 的课程信息为空: {data}")
            return None

        for item in cls:
            if item["classNum"] in cl[1]:
                # print(item["classNum"],type(item["classNum"]))
                if item["kcm"] != cl[2]:
                    logger.critical(
                        f"课程 {cl[2]} 的课程名与查询信息不匹配: {item['kcm']} != {cl[2]}"
                    )
                    sc_send(
                        "选课异常",
                        desp=f"课程 {cl[2]} 的课程名与查询信息不匹配: {item['kcm']} != {cl[2]}",
                    )
                    return None
    
        kyl:dict[str,str] = data["kylMap"]
        if len(kyl) == 0:
            logger.error(f"课程 {cl[2]} 的余量信息为空: {kyl}")
            return
        ret = []
        for kxh in cl[1]:
            key = f"{self.term}_{cl[0]}_{kxh}"
            left = kyl.get(key, None)
            if left is None:
                logger.error(
                    f"课程 {cl[2]} 的余量信息不存在: {key} not in {kyl.keys()}"
                )
                ret.append(-1)
                continue
            ret.append(int(left))
        return ret

    def select(self, cl: tuple[str, str, str]) -> bool:
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
        cms = ",".join(map(lambda x: str(ord(x)), cms))
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
        sel_data.update({"inputCode": "undefined", "tokenValue": token})
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
            # print(html)
            logger.error(f"选课 {cl[2]} 时未找到 redisKey")
            return False
        redisKey = redisKey.group(1)

        parms = {
            "kcNum": 1,
            "redisKey": redisKey,
        }
        cnt = 1
        while cnt <= 10:
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
                logger.info(f"第{cnt}次查询中...")
                cnt += 1
                sleep(1)

        logger.warning(f"选课 {cl[2]} 结果查询超时，可能未成功选课")
        return False

    def login(self):
        logger.info("尝试登录")
        flag = False
        for i in range(2):
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
            flag = True
            while flag:
                if self.waitcount > 120:
                    sc_send("选课异常","未到选课时间，等待超时。")
                    logger.critical("Waiting too much time, not selecting.")
                    exit(-1)
                try:
                    self.get_base_info()
                    flag = False
                except WaitException:
                    logger.warning("当前非选课时间")
                    self.waitcount += 1
                    sleep(self.interval_2)
                except QuestionException:
                    logger.error("需要答题")
                    ans = Path("answers.txt")
                    while not ans.exists():
                        sleep(self.interval_2)
            if self.waitcount:
                sc_send("选课通知","开始自动选课。")
                        
            classes_src = self.read_lessons()
            classes: dict[str, tuple[str, list[str], str]] = {}
            mp: dict[str, str] = {}  # {"课程号": "课程名称"}
            for id, kxh, name in classes_src:
                mp[id] = name
                if classes.get(id) is None:
                    classes[id] = (id, [kxh], name)
                else:
                    if classes[id][2] != name:
                        raise LessonsException(
                            f"课程 {name}_{kxh} 的名称不一致: {classes[id][2]} != {name}"
                        )
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
                    errs.clear()
                if master_err >= 3:
                    logger.error("反复发生重要异常，退出程序")
                    sc_send("选课异常", desp="反复发生重要异常，退出程序")
                    return
                try:
                    for lcl in classes.copy().values():
                        logger.info(f"检查课程 {lcl[2]} 余量")
                        try:
                            lefts = self.get_left(lcl)
                            if lefts is None:
                                errs.appendleft(time())
                                logger.error(f"获取课程 {lcl[2]} 余量时返回异常")
                                continue
                        except ReloginException as e:
                            raise e
                        except Exception as e:
                            errs.appendleft(time())
                            logger.error(f"获取课程 {lcl[2]} 余量时发生错误: {e}")
                            continue
                        for i, left in enumerate(lefts):
                            cl = (lcl[0], lcl[1][i], lcl[2])
                            if left > 0:
                                logger.info(
                                    f"课程 {cl[2]}_{cl[1]} 有余量: {left}，开始选课"
                                )
                                try:
                                    ret = self.select(cl)
                                    if ret:
                                        suc.append(cl)
                                        classes.pop(cl[0])
                                        break
                                except ReloginException as e:
                                    raise e
                                except Exception as e:
                                    errs.appendleft(time())
                                    logger.error(f"选课 {cl[2]}_{cl[1]} 时发生错误: {e}")
                                finally:
                                    sleep(self.interval_1)  # 避免请求过快导致服务器拒绝
                            elif left == -1:
                                logger.error(f"课程 {cl[2]}_{cl[1]} 余量信息异常")
                            else:
                                logger.info(f"课程 {cl[2]}_{cl[1]} 无余量")
                        sleep(self.interval_1)
                    logger.info(
                        f"当前还有{len(classes)}门课程未选上，分别为{','.join(mp[i] for i in classes.keys())}。等待{self.interval_2}秒后继续检查"
                    )
                    if suc:
                        sc_send(
                            "选课成功",
                            desp=f"已成功选上课程: {', '.join(f'{i[2]}_{i[1]}' for i in suc)}",
                        )
                except ReloginException as e:
                    logger.error(f"需要重新登录: {e}")
                    sc_send("选课异常", desp=f"需要重新登录: {e}")
                    self.login()
                    continue
                except LessonsException as e:
                    logger.error(f"选课过程中发生错误: {e}")
                    sc_send("选课异常", desp=f"选课过程中发生错误: {e}")
                    errs.appendleft(time())
                    continue
                except Exception as e:
                    logger.error(f"意外错误: {e}")
                    sc_send("选课异常", desp=f"选课过程中发生意外错误: {e}")
                    errs.appendleft(time())
                    continue
                sleep(self.interval_2)  # 等待10秒后继续检查

            logger.info("自动选课完成")

        except WaitException as e:
            logger.error("当前非选课时间")
            logger.error("不应该被这个except捕捉")
            sleep(self.interval_2)
            self.auto_spider()
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
