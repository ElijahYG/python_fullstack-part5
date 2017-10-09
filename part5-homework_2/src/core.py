#!/usr/bin/env python
# _*_ coding:utf-8 _*_
__author__ = "Elijah"
__date__ = "2017/10/8 13:56"


import sys

sys.path.append('../conf')
import settings
import paramiko
from multiprocessing import Process


class operation_client(object):
    # 远程操作主机
    def __init__(self, host, port, username, password, cmd):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.cmd = cmd

    def run(self):
        '''
        起线程连接远程主机后调用
        :return:
        '''
        cmd_str = self.cmd.split()[0]
        if hasattr(self, cmd_str):  
            getattr(self, cmd_str)()
        else:
            setattr(self, cmd_str, self.command)
            getattr(self, cmd_str)()  

    def command(self):
        '''
        批量命令处理
        :return:
        '''
        ssh = paramiko.SSHClient() 
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=self.host, port=self.port, username=self.username, password=self.password)
        stdin, stdout, stderr = ssh.exec_command(self.cmd)
        result = stdout.read()
        print("%s".center(30, "-") % self.host)
        print(result.decode())
        ssh.close()

    def upload(self):
        '''
        上传文件
        :return:
        '''
        filename = self.cmd.split()[1] 
        transport = paramiko.Transport((self.host, self.port))
        transport.connect(username=self.username, password=self.password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put(filename, filename.split('\\')[-1])
        print('上传文件：' + str(filename) + ' 成功!')
        transport.close()


def show_host_list():
    '''
    通过选择分组显示主机名与IP
    :return:
    '''
    num_list = []
    for index, key in enumerate(settings.msg_dic):
        num_list.append(key)
        print('主机组编号：' + str(index + 1), '\n\t\t主机组名：' + str(key), '\n\t\t主机数量：' + str(len(settings.msg_dic[key])))
    while True:
        choose_host_list = input("请输入批量操作的主机组编号(或者输入q退出)：>>>").strip()
        if choose_host_list.lower() == 'q':
            break
        host_dic = settings.msg_dic.get(num_list[int(choose_host_list) - 1])
        if host_dic:
            for key in host_dic:
                print(key, host_dic[key]["IP"])
            return host_dic
        else:
            print("对不起！您输入的主机组编号有误！\n")
            continue


def interactive(host_dic):
    '''
    根据选择的分组主机多线程批量操作
    :param host_dic:
    :return:
    '''
    str_info = '''
批量主机管理工具功能说明：
1、批量文件上传：upload file_path
例如：upload C:\\Users\\YG\\Desktop\\file.txt 

2、批量操作主机：df -h 、ls 、pwd ......
'''
    print(str_info)
    thread_list = []
    while True:
        command = input("请输入操作命令(或者输入q退出)：>>>").strip()
        if command.lower() == 'q':
            print('感谢使用批量主机管理工具！再见！')
            break
        elif command:
            for key in host_dic:
                host, port, username, password = host_dic[key]["IP"], host_dic[key]["port"], host_dic[key]["username"], \
                                                 host_dic[key]["password"]
                func = operation_client(host, port, username, password, command)
                t = Process(target=func.run)
                t.start()
                thread_list.append(t)
            for t in thread_list:
                t.join() 
        else:
            continue


def run():
    host_dic = show_host_list()
    interactive(host_dic)
